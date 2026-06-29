//! Delegate SD-JWT (draft-gco-oauth-delegate-sd-jwt) §7.1 presentation-layer support.
//! EXPERIMENTAL: tracks an unstable IETF draft; the wire constants here are the
//! single source of truth for the `delegate` transaction type.

pub const TRANSACTION_TYPE_DELEGATE: &str = "delegate";
/// `transaction_data` `format` value: dSD-JWT (no further holder binding by the delegate).
pub const FORMAT_DSD_JWT: &str = "dSD-JWT";
/// `transaction_data` `format` value: dSD-JWT+KB (delegate adds its own KB-JWT).
pub const FORMAT_DSD_JWT_KB: &str = "dSD-JWT+KB";
/// KB-JWT claim holding the delegate payload digest (§7.1).
pub const CLAIM_DELEGATE_PAYLOAD: &str = "delegate_payload";

pub use openid4vp::core::authorization_request::parameters::DelegateSdJwtTransactionDataFormat;
