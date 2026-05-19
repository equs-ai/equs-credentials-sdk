use crate::kms::Error as KmsError;
use crate::vc::claims::Error as ClaimsError;
use crate::vc::{dcql, presentation_exchange};
use crate::{http, nonce, vc};
use common_macros::DebugError;
use snafu::{Location, Snafu};
use ssi::dids::InvalidDIDURL;
use std::fmt::Debug;

/// An `oid4vp` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
pub enum InternalError {
    #[snafu(display("Authorization Response error: {details}"))]
    AuthorizationResponse {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Authorization Response mode unsupported: {details}"))]
    AuthorizationResponseUnsupportedMode {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Authorization Response jwe decryption error: {details}"))]
    AuthorizationResponseDecryption {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Credential not found"))]
    CredentialNotFound,
    #[snafu(display("Please provide the metadata required to generate the ID token"))]
    IdTokenMetadataNotFound,
    #[snafu(display("ID token parse error"))]
    IdTokenParse {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("ID token validation error: {details}"))]
    IdTokenValidation {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
    #[snafu(display("ID token generation error"))]
    IdTokenGeneration {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("KMS error"))]
    KMS {
        #[snafu(implicit)]
        location: Location,
        source: KmsError,
    },
    #[snafu(display("oid4vp-rs library internal error"))]
    Oid4VpLib {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("JWS error"))]
    JWS {
        source: ssi::claims::jws::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Parse error"))]
    Json {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },
    #[snafu(display("Parse error: {details}"))]
    Parse {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("VC error"))]
    VC {
        source: vc::core::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("VC status error"))]
    VCStatus {
        source: vc::core::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("VC is not valid: {details}"))]
    VCNotValid { details: String },

    #[snafu(display("Url parse error"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Presentation exchange error"))]
    PresentationExchange {
        #[snafu(implicit)]
        location: Location,
        source: presentation_exchange::Error,
    },
    #[snafu(display("DCQL error"))]
    DCQL {
        #[snafu(implicit)]
        location: Location,
        source: dcql::Error,
    },
    #[snafu(display("Http error"))]
    HttpClient {
        #[snafu(implicit)]
        location: Location,
        source: http::HttpError,
    },
    #[snafu(display("Nonce generation error"))]
    NonceGeneration {
        #[snafu(implicit)]
        location: Location,
        source: nonce::Error,
    },

    #[snafu(display("Claims error"))]
    Claims {
        source: ClaimsError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("DID url buf resolution error"))]
    DidUrlResolution {
        source: InvalidDIDURL<String>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("JWE error: {details}"))]
    JWE {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Client Error"))]
    Client {
        source: anyhow::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Transaction data error: {details}"))]
    TransactionData {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_response_display_includes_details() {
        let e = AuthorizationResponseSnafu {
            details: "malformed vp_token".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Authorization Response error: malformed vp_token"));
    }

    #[test]
    fn credential_not_found_display() {
        let e = CredentialNotFoundSnafu.build();
        assert!(format!("{e}").contains("Credential not found"));
    }

    #[test]
    fn format_not_supported_display_includes_format() {
        let e = FormatNotSupportedSnafu {
            format: "vc+mdoc".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Unsupported format: vc+mdoc"));
    }

    #[test]
    fn vc_not_valid_display_includes_details() {
        let e = VCNotValidSnafu {
            details: "expired credential".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("VC is not valid: expired credential"));
    }

    #[test]
    fn jwe_display_includes_details() {
        let e = JWESnafu {
            details: "decryption failed".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("JWE error: decryption failed"));
    }

    #[test]
    fn id_token_metadata_not_found_display() {
        let e = IdTokenMetadataNotFoundSnafu.build();
        assert!(
            format!("{e}")
                .contains("Please provide the metadata required to generate the ID token")
        );
    }

    #[test]
    fn id_token_validation_display_includes_details() {
        let e = IdTokenValidationSnafu {
            details: "nonce mismatch".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("ID token validation error: nonce mismatch"));
    }

    #[test]
    fn transaction_data_display_includes_details() {
        let e = TransactionDataSnafu {
            details: "hash mismatch".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Transaction data error: hash mismatch"));
    }
}
