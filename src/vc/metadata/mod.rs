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
    use crate::inmem::kms::LocalKms;
    use crate::kms::KeyType;
    use crate::utils::test_utils::{
        create_did_url_and_key_handle, create_did_url_and_key_handle_kid,
    };
    use crate::vc::claims::Claims;
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::json_ld_vc::VC;
    use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
    use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor, Error};
    use crate::vc::{Credential, VCFormat, VCMetadata};
    use futures::executor::block_on;
    use rstest::rstest;
    use serde_json::json;
    use time::Duration;

    struct TestCaseCred {
        pub credential: Credential,
        pub type_: String,
        pub format: VCFormat,
        pub key_metadata: KeyMetadata,
    }

    /// The credential type used by the minted SD-JWT VC fixtures below.
    const SD_JWT_VCT: &str = "https://issuer.net/cred_schema";

    /// Mints an EdDSA-signed SD-JWT VC with claims `name`, `surname`, `dob`
    /// (`name`/`surname` selectively disclosed), mirroring the shape of the
    /// old committed `SD_JWT_CRED`/`SD_JWT_CRED_NO_VCT` tokens (same header
    /// `alg`, same claim set).
    ///
    /// `include_vct` toggles the negative case: the SDK's own
    /// `SdJwtAPI::create_vc` always injects `vct`, so producing a credential
    /// that genuinely lacks it means driving the prepare/sign split directly
    /// and stripping the claim from the unsigned credential before signing —
    /// the only way to get a validly-signed SD-JWT VC without a `vct`.
    async fn sd_jwt_credential(include_vct: bool) -> (String, KeyMetadata) {
        let kms = LocalKms::new();
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::Ed25519).await;
        let (hld_did_url, hld_kid, hld_kh) =
            create_did_url_and_key_handle_kid(&kms, KeyType::Ed25519).await;

        let claims: Claims = json!({
            "name": "John",
            "surname": "Doe",
            "dob": "09/09/1989",
        })
        .try_into()
        .unwrap();

        let vc_meta = VCMetadata {
            vct: SD_JWT_VCT.to_string(),
            lifetime: Some(Duration::days(365)),
            disclosures: vec!["$.name".to_string(), "$.surname".to_string()],
            credential_status: None,
        };

        let mut unsigned = SdJwtAPI::prepare_credential(
            claims,
            &iss_did_url,
            &hld_did_url,
            &hld_kh,
            &vc_meta,
            String::new(),
        )
        .unwrap();

        if !include_vct {
            unsigned.claims.remove("vct");
        }

        let credential = SdJwtAPI::sign_credential(unsigned, iss_kh).await.unwrap();

        (
            credential,
            KeyMetadata {
                kid: hld_kid,
                did_url: hld_did_url.to_string(),
            },
        )
    }

    fn sd_jwt_cred_with_vct() -> (String, KeyMetadata) {
        block_on(sd_jwt_credential(true))
    }

    fn sd_jwt_cred_without_vct() -> String {
        block_on(sd_jwt_credential(false)).0
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

        let invalid_cred = Credential::SdJwt(sd_jwt_cred_without_vct());
        let res = DefaultMetadataProcessor::resolve_metadata(&invalid_cred, key_metadata.clone());

        assert!(matches!(res.err(), Some(Error::Resolving { .. })));
    }

    #[test]
    fn resolve_sd_jwt_cred_fields() {
        let (credential, _) = sd_jwt_cred_with_vct();
        let credential = Credential::SdJwt(credential);
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
        let (credential, key_metadata) = sd_jwt_cred_with_vct();
        TestCaseCred {
            credential: Credential::SdJwt(credential),
            type_: SD_JWT_VCT.to_owned(),
            format: VCFormat::SdJwtVc,
            key_metadata,
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
}
