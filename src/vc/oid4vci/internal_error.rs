use crate::http::HttpError;
use crate::vc::oid4vci::metadata;
use crate::{nonce, storage, vault, vc};
use common_macros::DebugError;
use oauth2::basic::BasicRequestTokenError;
use oid4vci::credential::RequestError;
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// An `oid4vci` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
pub enum InternalError {
    #[snafu(display("Credential definition not found for ID: {id}"))]
    CredDefNotFound {
        id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "No scope set for Credential definition ID: {id}. Only scope authorization supported"
    ))]
    NoScopeSet {
        id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Claims validation error: {details}"))]
    ClaimsValidation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Issuer service error: {details}"))]
    IssuerService {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Holder service error: {details}"))]
    HolderService {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Url parse error"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Parse error"))]
    Parse {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },
    #[snafu(display("Storage error"))]
    Storage {
        #[snafu(implicit)]
        location: Location,
        source: storage::Error,
    },
    #[snafu(display("VC error: {source}"))]
    VC {
        #[snafu(implicit)]
        location: Location,
        source: vc::core::Error,
    },
    #[snafu(display("Vault error"))]
    Vault {
        #[snafu(implicit)]
        location: Location,
        source: vault::Error,
    },
    #[snafu(display("Request error"))]
    Request {
        #[snafu(implicit)]
        location: Location,
        source: RequestError<HttpError>,
    },
    #[snafu(display("Discovery error"))]
    Discovery {
        #[snafu(implicit)]
        location: Location,
        //TODO: Check that nothing other than 'reqwest::Error' can be used here.
        source: anyhow::Error,
    },
    #[snafu(display("Http error"))]
    HttpClient {
        #[snafu(implicit)]
        location: Location,
        source: HttpError,
    },
    #[snafu(display("Metadata resolving error"))]
    Metadata {
        #[snafu(implicit)]
        location: Location,
        source: metadata::Error,
    },
    #[snafu(display("Nonce Handler error"))]
    NonceHandler {
        #[snafu(implicit)]
        location: Location,
        source: nonce::Error,
    },

    #[snafu(display("Type conversion error: {details}"))]
    TypeConversion {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
    #[snafu(display("authorization callback error: {details}"))]
    AuthorizationCallback {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
    #[snafu(display("Token request error"))]
    TokenRequest {
        #[snafu(implicit)]
        location: Location,
        source: BasicRequestTokenError<HttpError>,
    },

    #[snafu(display("Authorization request error: {details}"))]
    AuthorizationRequest {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cred_def_not_found_display_includes_id() {
        let e = CredDefNotFoundSnafu {
            id: "cred-123".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Credential definition not found for ID: cred-123"));
    }

    #[test]
    fn no_scope_set_display_includes_id() {
        let e = NoScopeSetSnafu {
            id: "def-456".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("No scope set for Credential definition ID: def-456"));
    }

    #[test]
    fn claims_validation_display_includes_details() {
        let e = ClaimsValidationSnafu {
            details: "missing claim".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Claims validation error: missing claim"));
    }

    #[test]
    fn issuer_service_display_includes_details() {
        let e = IssuerServiceSnafu {
            details: "issuer unreachable".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Issuer service error: issuer unreachable"));
    }

    #[test]
    fn type_conversion_display_includes_details() {
        let e = TypeConversionSnafu {
            details: "expected string got number".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Type conversion error: expected string got number"));
    }

    #[test]
    fn authorization_callback_display_includes_details() {
        let e = AuthorizationCallbackSnafu {
            details: "callback failed".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("authorization callback error: callback failed"));
    }

    #[test]
    fn authorization_request_display_includes_details() {
        let e = AuthorizationRequestSnafu {
            details: "invalid redirect_uri".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Authorization request error: invalid redirect_uri"));
    }
}
