use serde_json::Value;
use snafu::{Location, Snafu};
use std::fmt::Debug;
use tracing::{instrument, Level};

use crate::vc::core::KeyMetadata;
use crate::vc::formats::HasClaims;
use crate::vc::{Credential, CredentialMetadata, HasVCFormat};
use common_macros::DebugError;

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
            Credential::LdpVc(w3c_vc) => {
                let type_ = w3c_vc
                    .type_
                    .clone()
                    .into_iter()
                    .last()
                    .unwrap_or("VerifiableCredential".to_string());
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
                    Some(Value::String(vct)) => vct,
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

        Ok(CredentialMetadata {
            type_,
            format,
            kid: key_metadata.kid,
            alg: None,
            tags: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::vc::core::KeyMetadata;
    use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor, Error};
    use crate::vc::{Credential, VCFormat};
    use rstest::rstest;

    struct TestCaseCred {
        pub credential: Credential,
        pub type_: String,
        pub format: VCFormat,
        pub key_metadata: KeyMetadata,
    }

    // inputs:
    //
    // "name": "John",
    // "surname": "Doe",
    // "dob": "09/09/1989",
    // "vct": "https://issuer.net/cred_schema",
    // "sub": "did:key:z6MkqLdRvJwvhEoakcdyQvL5koo2iHfDnicd5xor567ujpmr",
    // "iss": "did:key:z6MkhEcbQWUFDpjbrmPZNwSrP88Xta7stHTo4QiA5AmrpHaY",
    pub const SD_JWT_CRED: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2hFY2JRV1VGRHBqYnJtUFpOd1NyUDg4WHRhN3N0SFRvNFFpQTVBbXJwSGFZIn0.eyJfc2QiOlsiYzZLRXVOWWhIbWY1em0wSC04NVlIc0t0X3h2NTY4VGJlMDJ3dTlQVkhQQSIsImVGd3NtMHBiTzhlM0VBaXJ0NEYyYWZBY2VoSHJtb2xsbEptVnNMdWR3aHciXSwiZG9iIjoiMDkvMDkvMTk4OSIsInZjdCI6Imh0dHBzOi8vaXNzdWVyLm5ldC9jcmVkX3NjaGVtYSIsInN1YiI6ImRpZDprZXk6ejZNa3FMZFJ2Snd2aEVvYWtjZHlRdkw1a29vMmlIZkRuaWNkNXhvcjU2N3VqcG1yIiwibmJmIjoxNzI3MTM0MTgxLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ejZNa2hFY2JRV1VGRHBqYnJtUFpOd1NyUDg4WHRhN3N0SFRvNFFpQTVBbXJwSGFZIiwiaWF0IjoxNzI3MTM0MTgxLCJleHAiOjE3NTg2NzAxODEsImNuZiI6eyJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJvYjJyckVQMldvdkhhSi1yUFBVcmxKTnZuNUV4X0hudEh1bmhRWXE2eVpVIn19fQ.NNeO4SZYVEo5P1pgdCKb3F41Mtb6mNhKtPvASuzW0O1AlfMsUaHRXUohAmkMNWDDh-KriRWhnA5_Fwypg-NpCg~WyJzendxOXg0X3lqVkVfaW8xUjdxNkxRIiwgIm5hbWUiLCAiSm9obiJd~WyJPWEoxWHh4YUxpTmpleHlkWUszY0hnIiwgInN1cm5hbWUiLCAiRG9lIl0~";
    // inputs:
    //
    // "name": "John",
    // "surname": "Doe",
    // "dob": "09/09/1989",
    // "sub": "did:key:z6MkftE2DVebXqAV1Qoa6Dv8whynhAcWBP4vTnAurG4pMVqK",
    // "iss": "did:key:z6MkpB6C5bwpYTtKDnSKtb1QAmcxXxwTfmgQcz3Um2BpjZQ6",
    pub const SD_JWT_CRED_NO_VCT: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3BCNkM1YndwWVR0S0RuU0t0YjFRQW1jeFh4d1RmbWdRY3ozVW0yQnBqWlE2In0.eyJfc2QiOlsiaHJTV3dmSkFoc2M4U0xZUXItSU5iQWt3Y1ZBRF9lWURhOHU0LWI1UWN5OCIsIncxcjJtdnNQYk1ndXVjM281TnZNSTVpTzZzdDE2TUlFYndZSzhyYUhBTEEiXSwiZG9iIjoiMDkvMDkvMTk4OSIsInN1YiI6ImRpZDprZXk6ejZNa2Z0RTJEVmViWHFBVjFRb2E2RHY4d2h5bmhBY1dCUDR2VG5BdXJHNHBNVnFLIiwibmJmIjoxNzI3MTM0NDIwLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ejZNa3BCNkM1YndwWVR0S0RuU0t0YjFRQW1jeFh4d1RmbWdRY3ozVW0yQnBqWlE2IiwiaWF0IjoxNzI3MTM0NDIwLCJleHAiOjE3NTg2NzA0MjAsImNuZiI6eyJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJGVURyUDZZN05xZHhxMWlCalR1MzJCQUY1YS1QNEFPcFJGakt5Qk5LM3hJIn19fQ.l08oQxDKhJqkWvZ7g_4AuogB4uheINK_pIPC6yxhrKeFwbq9Xjd2_5MwzEz52VV5vyY3KxjaUHm81MisKIpoCw~WyJwdDJMeVBtR2pSTFpoaThUY0QybHJRIiwgIm5hbWUiLCAiSm9obiJd~WyJBQS05Ums3NnpuM1ZEX2FYR2NhZWhRIiwgInN1cm5hbWUiLCAiRG9lIl0~";

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

        let invalid_cred = Credential::SdJwt(SD_JWT_CRED_NO_VCT.into());
        let res = DefaultMetadataProcessor::resolve_metadata(&invalid_cred, key_metadata.clone());

        assert!(matches!(res.err(), Some(Error::Resolving { .. })));
    }

    fn sd_jwt_cred() -> TestCaseCred {
        TestCaseCred {
            credential: Credential::SdJwt(SD_JWT_CRED.to_owned()),
            type_: "https://issuer.net/cred_schema".to_owned(),
            format: VCFormat::SdJwtVc,
            key_metadata: KeyMetadata{
                did_url: "did:key:z6MkqLdRvJwvhEoakcdyQvL5koo2iHfDnicd5xor567ujpmr#z6MkqLdRvJwvhEoakcdyQvL5koo2iHfDnicd5xor567ujpmr".to_owned(),
                kid: "12345".to_string(),
            },
        }
    }

    fn ldp_vc_cred() -> TestCaseCred {
        TestCaseCred {
            credential: Credential::LdpVc(
                ssi::vc::Credential::from_json_unsigned(LDP_VC_CRED).unwrap(),
            ),
            type_: "UniversityDegree".into(),
            format: VCFormat::LdpVc,
            key_metadata: KeyMetadata {
                did_url: "did:example:d23dd687a7dc6787646f2eb98d0".to_owned(),
                kid: "12345".to_string(),
            },
        }
    }
}
