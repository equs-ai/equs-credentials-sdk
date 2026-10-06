//! Credential metadata and metadata processors.

use snafu::{Location, Snafu, ensure};
use ssi::json_ld::JsonLdNodeObject;
use std::fmt::Debug;
use tracing::{Level, instrument};

use crate::utils;
use crate::vc::claims::Claim;
use crate::vc::core::KeyMetadata;
use crate::vc::formats::HasClaims;
use crate::vc::{Credential, CredentialMetadata, HasVCFormat};
use common_macros::DebugError;

type Level_ = Level;

/// `Metadata` Error.
///
/// Should be used by all `CredentialMetadataProcessor` implementations.
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("Resolving error: {details}"))]
    Resolving {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

/// `Result` alias for `MetadataProcessor` [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// A common service to generate a [CredentialMetadata] for the [Credential].
///
/// # Implementation
///
/// Default implementation: [DefaultMetadataProcessor].
pub trait CredentialMetadataProcessor {
    /// Resolve a `CredentialMetadata` for `Credential`.
    ///
    /// # Arguments
    ///
    /// * `credential` - a `Credential`.
    /// * `key_metadata` - a key meta of the `Holder` used for `Credential` generation.
    ///
    /// # Returns
    ///
    /// A `CredentialMetadata` of the provided `Credential` on success.
    ///
    /// # Errors
    ///
    /// * [Error::FormatNotSupported] - format is not supported by the processor.
    /// * [Error::Resolving] - fails to resolve `Credential`.
    fn resolve_metadata(
        credential: &Credential,
        key_metadata: KeyMetadata,
    ) -> Result<CredentialMetadata>;
}

/// A default implementation of [CredentialMetadataProcessor].
///
/// Fills in mandatory `type` and `format` for [CredentialMetadata].
pub struct DefaultMetadataProcessor;

impl DefaultMetadataProcessor {
    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    fn type_(credential: &Credential) -> Result<String> {
        match credential {
            Credential::LdpVc(ldp_vc) => {
                let type_ = Vec::<String>::from(ldp_vc.json_ld_type())
                    .last()
                    .unwrap_or(&"VerifiableCredential".to_string())
                    .to_owned();

                Ok(type_)
            }
            Credential::SdJwt(jwt) => {
                let claims = jwt.parse_claims().map_err(|err| {
                    ResolvingSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;

                let type_ = match claims.get("vct") {
                    Some(Claim::String(vct)) => vct,
                    _ => ResolvingSnafu {
                        details: "vct not found",
                    }
                    .fail()?,
                };
                Ok(type_.to_owned())
            }
            _ => FormatNotSupportedSnafu {
                format: credential.format().to_string(),
            }
            .fail(),
        }
    }

    #[instrument(level = Level::TRACE, skip(credential), err())]
    fn resolve_fields(credential: &Credential) -> Result<Vec<String>> {
        let claims = credential.parse_claims().map_err(|err| {
            ResolvingSnafu {
                details: format!("{err:?}"),
            }
            .build()
        })?;

        let fields: Vec<String> = utils::json::claims_to_json_path(claims)
            .map_err(|err| {
                ResolvingSnafu {
                    details: format!("Unable to create fields for claims: {err}"),
                }
                .build()
            })?
            .iter()
            .map(|(k, _)| k.to_owned())
            .collect();

        Ok(fields)
    }
}

impl CredentialMetadataProcessor for DefaultMetadataProcessor {
    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    fn resolve_metadata(
        credential: &Credential,
        key_metadata: KeyMetadata,
    ) -> Result<CredentialMetadata> {
        let format = credential.format();
        let type_ = Self::type_(credential)?;

        let claims = credential.parse_claims().map_err(|err| {
            ResolvingSnafu {
                details: format!("{err:?}"),
            }
            .build()
        })?;

        match credential {
            Credential::SdJwt(_) => {
                validate_did_match(
                    claims.get("sub"),
                    &key_metadata,
                    "Cannot retrieve a 'sub' field of sd-jwt credential",
                )?;
            }
            Credential::LdpVc(_) => {
                validate_did_match(
                    claims
                        .get("credentialSubject")
                        .and_then(|cred_sub| cred_sub.get("id")),
                    &key_metadata,
                    "Cannot retrieve a 'credentialSubject' field of json-ld-vc credential",
                )?;
            }
            Credential::JwtVcJson(_) | Credential::JwtVcJsonLd(_) => {
                return Err(FormatNotSupportedSnafu {
                    format: "Credential with jwt-vc-json or jwt-vc-json-ld is not supported"
                        .to_string(),
                }
                .fail()?);
            }
        }

        Ok(CredentialMetadata {
            type_,
            format,
            kid: key_metadata.kid,
            alg: None,
            fields: Self::resolve_fields(credential)?,
        })
    }
}

#[instrument(level = Level::TRACE, err())]
fn validate_did_match(
    subject_claim_value: Option<&Claim>,
    key_metadata: &KeyMetadata,
    missing_field_message: &str,
) -> Result<()> {
    let cred_did = match subject_claim_value {
        Some(Claim::String(did)) => did,
        _ => ResolvingSnafu {
            details: missing_field_message.to_string(),
        }
        .fail()?,
    };

    ensure!(
        key_metadata.did_url.starts_with(cred_did.as_str()),
        ResolvingSnafu {
            details: format!(
                "Credential and key-metadata DIDs does not match: credential DID = {}, key metadata DID url = {}",
                cred_did, key_metadata.did_url
            ),
        }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::json_ld_vc::VC;
    use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor, Error};
    use crate::vc::{Credential, VCFormat};
    use rstest::rstest;

    struct TestCaseCred {
        pub credential: Credential,
        pub type_: String,
        pub format: VCFormat,
        pub key_metadata: KeyMetadata,
    }

    pub const LDP_VC_CRED: &str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential", "UniversityDegree"],
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;

    #[rstest]
    #[case::sd_jwt_cred(sd_jwt_cred())]
    #[case::ldp_vc_cred(ldp_vc_cred())]
    #[test]
    fn metadata_resolved_correctly(#[case] case: TestCaseCred) {
        let key_metadata = case.key_metadata;
        let metadata =
            DefaultMetadataProcessor::resolve_metadata(&case.credential, key_metadata.clone())
                .unwrap();

        assert_eq!(metadata.kid, key_metadata.kid);
        assert_eq!(metadata.format, case.format);
        assert_eq!(metadata.type_, case.type_);
    }

    #[test]
    fn metadata_resolving_fails_on_unsupported_format() {
        let key_metadata = KeyMetadata {
            did_url: "did:example".to_owned(),
            kid: "12345".to_string(),
        };

        let unsupported = Credential::JwtVcJson("invalid".into());
        let res = DefaultMetadataProcessor::resolve_metadata(&unsupported, key_metadata.clone());

        assert!(matches!(res.err(), Some(Error::FormatNotSupported { .. })));
    }

    #[test]
    fn sd_jwt_metadata_resolving_fails_on_invalid_cred() {
        let key_metadata = KeyMetadata {
            did_url: "did:example".to_owned(),
            kid: "12345".to_string(),
        };

        let invalid_cred = Credential::SdJwt("invalid".into());
        let res = DefaultMetadataProcessor::resolve_metadata(&invalid_cred, key_metadata.clone());

        assert!(matches!(res.err(), Some(Error::Resolving { .. })));
    }

    #[test]
    fn sd_jwt_metadata_resolving_fails_when_vct_is_missing() {
        let key_metadata = KeyMetadata {
            did_url: "did:example".to_owned(),
            kid: "12345".to_string(),
        };

        let invalid_cred = Credential::SdJwt(sd_jwt_cred_no_vct_token());
        let res = DefaultMetadataProcessor::resolve_metadata(&invalid_cred, key_metadata.clone());

        assert!(matches!(res.err(), Some(Error::Resolving { .. })));
    }

    #[test]
    fn resolve_sd_jwt_cred_fields() {
        let credential = Credential::SdJwt(sd_jwt_cred_token());
        let mut fields = DefaultMetadataProcessor::resolve_fields(&credential).unwrap();

        fields.sort();

        assert_eq!(
            fields,
            vec![
                "$.dob".to_string(),
                "$.exp".to_string(),
                "$.iat".to_string(),
                "$.iss".to_string(),
                "$.name".to_string(),
                "$.nbf".to_string(),
                "$.sub".to_string(),
                "$.surname".to_string(),
                "$.vct".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_js_ld_cred_fields() {
        let credential = Credential::LdpVc(VC::new(
            serde_json::from_str(LDP_VC_CRED).unwrap(),
            Default::default(),
        ));

        let mut fields = DefaultMetadataProcessor::resolve_fields(&credential).unwrap();

        fields.sort();

        assert_eq!(
            fields,
            vec![
                "$.@context[*]".to_string(),
                "$.credentialSubject.id".to_string(),
                "$.id".to_string(),
                "$.issuanceDate".to_string(),
                "$.issuer".to_string(),
                "$.type[*]".to_string(),
                "$.type[*]".to_string(),
            ]
        )
    }

    fn sd_jwt_cred() -> TestCaseCred {
        TestCaseCred {
            credential: Credential::SdJwt(sd_jwt_cred_token()),
            type_: "https://issuer.net/cred_schema".to_owned(),
            format: VCFormat::SdJwtVc,
            key_metadata: KeyMetadata {
                did_url: test_fixtures::did_key_url(&ED25519_KEYS.1),
                kid: "12345".to_string(),
            },
        }
    }

    fn ldp_vc_cred() -> TestCaseCred {
        TestCaseCred {
            credential: Credential::LdpVc(serde_json::from_str(LDP_VC_CRED).unwrap()),
            type_: "UniversityDegree".into(),
            format: VCFormat::LdpVc,
            key_metadata: KeyMetadata {
                did_url: "did:example:d23dd687a7dc6787646f2eb98d0".to_owned(),
                kid: "12345".to_string(),
            },
        }
    }

    /// Ed25519 issuer and holder keys of the SD-JWT fixtures.
    static ED25519_KEYS: std::sync::LazyLock<(test_fixtures::JWK, test_fixtures::JWK)> =
        std::sync::LazyLock::new(|| {
            (
                test_fixtures::JWK::generate_ed25519().unwrap(),
                test_fixtures::JWK::generate_ed25519().unwrap(),
            )
        });

    fn sd_jwt_cred_token() -> String {
        let (issuer, holder) = &*ED25519_KEYS;
        test_fixtures::sd_jwt(
            &serde_json::json!({
                "typ": "vc+sd-jwt",
                "alg": "EdDSA",
                "kid": test_fixtures::did_key_url(issuer)
            }),
            &serde_json::json!({
                "dob": "09/09/1989",
                "vct": "https://issuer.net/cred_schema",
                "sub": test_fixtures::did_key(holder),
                "nbf": 1727134181,
                "_sd_alg": "sha-256",
                "iss": test_fixtures::did_key(issuer),
                "iat": 1727134181,
                "exp": 1758670181,
                "cnf": {
                    "jwk": holder.to_public()
                }
            }),
            &[
                r#"["szwq9x4_yjVE_io1R7q6LQ", "name", "John"]"#,
                r#"["OXJ1XxxaLiNjexydYK3cHg", "surname", "Doe"]"#,
            ],
            issuer,
        )
    }
    fn sd_jwt_cred_no_vct_token() -> String {
        let (issuer, holder) = &*ED25519_KEYS;
        test_fixtures::sd_jwt(
            &serde_json::json!({
                "typ": "vc+sd-jwt",
                "alg": "EdDSA",
                "kid": test_fixtures::did_key_url(issuer)
            }),
            &serde_json::json!({
                "dob": "09/09/1989",
                "sub": test_fixtures::did_key(holder),
                "nbf": 1727134420,
                "_sd_alg": "sha-256",
                "iss": test_fixtures::did_key(issuer),
                "iat": 1727134420,
                "exp": 1758670420,
                "cnf": {
                    "jwk": holder.to_public()
                }
            }),
            &[
                r#"["pt2LyPmGjRLZhi8TcD2lrQ", "name", "John"]"#,
                r#"["AA-9Rk76zn3VD_aXGcaehQ", "surname", "Doe"]"#,
            ],
            issuer,
        )
    }
}
