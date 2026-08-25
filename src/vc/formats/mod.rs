//! VC formats

use crate::crypto;
use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::vc::core::{HolderBinder, PresentationRestrictionValue};
use async_trait::async_trait;
use common_macros::DebugError;
use snafu::{Location, Snafu};
use ssi::claims::SignatureError;
use ssi::dids::DIDURL;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

pub mod json_ld_vc;

#[cfg(not(target_arch = "wasm32"))]
pub mod mso_mdoc;
pub mod sd_jwt_vc;
pub mod vc;
pub mod vp;

#[cfg(feature = "delegate-sd-jwt")]
pub mod dsd_jwt;
#[cfg(feature = "delegate-sd-jwt")]
pub use dsd_jwt::{ChainBindingMode, DelegationParams};

/// `VC` format internal error.
///
/// Defines errors for all supported low-level VC operations.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },

    #[snafu(display("Unsupported key type: {type_}"))]
    KeyTypeNotSupported { type_: String },

    #[snafu(display("Credential creation error: {details}"))]
    CredentialCreation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Multiple credential subjects are not supported"))]
    MultipleSubjectNotSupported {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Verifiable presentation does not include credential"))]
    NoCredential {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Multiple credentials are not supported"))]
    MultipleCredentialsNotSupported {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Signing error: {details}"))]
    Signing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Signature error: {source}"))]
    SpruceSigning {
        source: SignatureError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Verification error: {details}"))]
    Verifying {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Parsing error: {details}"))]
    Parsing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Error during checking status: {details}"))]
    StatusCheck {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Presentation error: {details}"))]
    Presentation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("DID parsing error: {details}"))]
    DID {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("JWK error"))]
    JWK {
        source: ssi::jwk::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("JWS error"))]
    JWS {
        source: ssi::claims::jws::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("JSON error"))]
    Json {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Base64 decoding error"))]
    Base64 {
        source: base64::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Proof validation error"))]
    ProofValidation {
        source: ssi::claims::ProofValidationError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Claims error"))]
    Claims {
        source: crate::vc::claims::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Uri parsing error: {source}"))]
    UriParsing {
        source: did_resolver::did_doc::schema::types::uri::UriWrapperError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("IriReference parsing error: {source}"))]
    IriRefParsing {
        source: iref::iri::InvalidIriRef<String>,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("IriBuf parsing error: {source}"))]
    IriBufParsing {
        source: iref::iri::InvalidIri<String>,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Crypto suite creation error: {details}"))]
    CryptoSuiteCreation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Could not parse disclosures"))]
    JsonPointerParsing {
        source: ssi::json_pointer::InvalidJsonPointer,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Unimplemented: {details}"))]
    Unimplemented {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_not_supported_display_includes_format() {
        let e = FormatNotSupportedSnafu {
            format: "custom_fmt".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Unsupported format: custom_fmt"));
    }

    #[test]
    fn key_type_not_supported_display_includes_type() {
        let e = KeyTypeNotSupportedSnafu {
            type_: "MyKeyType".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Unsupported key type: MyKeyType"));
    }

    #[test]
    fn credential_creation_display_includes_details() {
        let e = CredentialCreationSnafu {
            details: "issuer key missing".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Credential creation error: issuer key missing"));
    }

    #[test]
    fn verifying_display_includes_details() {
        let e = VerifyingSnafu {
            details: "signature invalid".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Verification error: signature invalid"));
    }

    #[test]
    fn parsing_display_includes_details() {
        let e = ParsingSnafu {
            details: "unexpected token".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Parsing error: unexpected token"));
    }

    #[test]
    fn unimplemented_display_includes_details() {
        let e = UnimplementedSnafu {
            details: "mso_mdoc on wasm".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Unimplemented: mso_mdoc on wasm"));
    }
}

#[derive(Debug, Default)]
pub struct VerifyOptions {
    // TODO seems to be jwt_vc_json-specific and should be removed from generic code.
    pub selective_claims: Option<Vec<String>>,
    // Subject Key Identifiers (SKI) of the trusted x509 certificates used to verify the signature of the credential.
    pub trusted_certs_skids: Option<HashSet<String>>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait API<CL, C, P, CM, PM, VR>
where
    C: HasClaims<CL>,
    P: HasCredential<C>,
{
    async fn create_vc<S, K>(
        claims: CL,
        issuer_data: (&DIDURL, S),
        holder_data: (&DIDURL, K),
        metadata: CM,
        did_resolver: UniversalResolver,
    ) -> Result<C>
    where
        S: crypto::Signer + crypto::Key,
        K: crypto::Key;

    async fn create_vp<S>(
        credential: &C,
        holder_signer: S,
        metadata: PM,
        did_resolver: UniversalResolver,
    ) -> Result<P>
    where
        S: crypto::Signer + crypto::Key;

    async fn verify_vc(
        credential: &C,
        opts: VerifyOptions,
        did_resolver: UniversalResolver,
    ) -> Result<()>;

    async fn verify_vp(
        presentation: &P,
        holder_binder: Option<HolderBinder>,
        opts: VerifyOptions,
        did_resolver: UniversalResolver,
    ) -> Result<VR>;
}

pub trait HasClaims<CL> {
    fn parse_claims(&self) -> Result<CL>;
    fn has_type(&self, type_: PresentationRestrictionValue) -> Result<bool>;
}

pub trait HasCredential<C> {
    fn get_credential(&self) -> Result<C>;
}

pub trait IsExpired<C> {
    fn is_expired(credential: &C) -> Result<bool>;
}
pub trait IsValid<C> {
    async fn is_valid(
        claims: &C,
        http_client: &dyn HttpClient,
        did_resolver: UniversalResolver,
        cache: Option<&mut HashMap<String, String>>,
    ) -> Result<bool>;
}

pub trait GetDateTimeClaim<CL, EC> {
    fn get_date_time_claim(exp_key: &str, claims: &CL) -> Option<EC>;
}
