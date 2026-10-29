use crate::vc::oid4vp::Error::{Internal, Protocol};
use crate::vc::oid4vp::internal_error::NonceGenerationSnafu;
use crate::vc::oid4vp::{Error, ErrorType, ProtocolError, TransactionDataItem};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
pub use openid4vp::core::authorization_request::parameters::DelegateSdJwtTransactionDataFormat;
use openid4vp::core::authorization_request::parameters::{
    DelegateSdJwtTransactionData, TransactionDataItemTypeContent,
};
use serde_json::json;
use snafu::ResultExt;

pub const TRANSACTION_TYPE_DELEGATE: &str = "delegate";
pub const FORMAT_DSD_JWT: &str = "dSD-JWT";
pub const FORMAT_DSD_JWT_KB: &str = "dSD-JWT+KB";
pub const CLAIM_DELEGATE_PAYLOAD: &str = "delegate_payload";

/// Inputs for requesting delegation of a credential to *this* party (the Delegate Holder).
#[cfg(feature = "delegate-sd-jwt")]
#[derive(Debug, Clone)]
pub struct DelegationRequest {
    credential_ids: Vec<String>,
    /// Claims to carry in the delegate payload. Must not contain `cnf`/`_sd` claim.
    payload: serde_json::Map<String, serde_json::Value>,
    format: DelegateSdJwtTransactionDataFormat,
}

impl DelegationRequest {
    pub fn open(
        credential_ids: Vec<String>,
        payload: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, Error> {
        Self::validate_delegate_payload(&payload)?;
        Ok(DelegationRequest {
            credential_ids,
            payload,
            format: DelegateSdJwtTransactionDataFormat::Open,
        })
    }

    pub fn holder_binding(
        credential_ids: Vec<String>,
        delegate_jwk: ssi::jwk::JWK,
        mut payload: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, Error> {
        Self::validate_delegate_payload(&payload)?;

        let jwk_value = serde_json::to_value(delegate_jwk).map_err(|_| Protocol {
            source: ProtocolError::new(
                ErrorType::InvalidTransactionData,
                Some("failed to serialise delegate_cnf".to_string()),
                None,
            ),
        })?;
        payload.insert("cnf".to_string(), json!({ "jwk": jwk_value }));

        Ok(DelegationRequest {
            credential_ids,
            payload,
            format: DelegateSdJwtTransactionDataFormat::HolderBinding,
        })
    }

    fn validate_delegate_payload(
        payload_claims: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Error> {
        if payload_claims.contains_key("cnf") {
            return Err(Protocol {
                source: ProtocolError::new(
                    ErrorType::InvalidTransactionData,
                    Some("cnf must be supplied via delegate_cnf".to_string()),
                    None,
                ),
            });
        }
        // todo: need better sanitization https://datatracker.ietf.org/doc/html/draft-gco-oauth-delegate-sd-jwt-00#section-7.1-3
        if payload_claims.contains_key("_sd") {
            return Err(Protocol {
                source: ProtocolError::new(
                    ErrorType::InvalidTransactionData,
                    Some(
                        "delegate payload must not contain _sd (selective disclosure within the delegate payload is unsupported)".to_string(),
                    ),
                    None,
                ),
            });
        }
        Ok(())
    }
}

#[cfg(feature = "delegate-sd-jwt")]
pub(crate) fn decode_delegate_payload_disclosure(
    item: &DelegateSdJwtTransactionData,
    state: &Option<String>,
) -> Result<serde_json::Value, ProtocolError> {
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(&item.delegate_payload_disclosure)
        .map_err(|_| {
            ProtocolError::transaction_data(
                "malformed delegate_payload_disclosure: invalid base64url",
                state.to_owned(),
            )
        })?;
    let payload_disclosure: serde_json::Value = serde_json::from_slice(&decoded).map_err(|_| {
        ProtocolError::transaction_data(
            "malformed delegate_payload_disclosure: not valid JSON",
            state.to_owned(),
        )
    })?;
    let payload = payload_disclosure
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or_else(|| {
            ProtocolError::transaction_data(
                "malformed delegate_payload_disclosure: expected 2-element array",
                state.to_owned(),
            )
        })?;
    let payload = payload[1].clone();
    if !payload.is_object() {
        return Err(ProtocolError::transaction_data(
            "malformed delegate_payload_disclosure: payload is not a JSON object",
            state.to_owned(),
        ));
    }
    if payload.get("_sd").is_some() {
        return Err(ProtocolError::transaction_data(
            "malformed delegate_payload_disclosure: _sd is forbidden in delegate payloads",
            state.to_owned(),
        ));
    }
    Ok(payload)
}

/// Rejects the delegate payloads if any has an `exp` (RFC 7519 section 4.1.4) that has passed.
/// A payload without `exp` never expires.
///
/// # Errors
///
/// * Returns [`Error::TransactionDataExpired`] if `exp` is now or earlier.
/// * Returns [`Error::Protocol`] (`InvalidTransactionData`) if `exp` is not an integer.
#[cfg(feature = "delegate-sd-jwt")]
pub(crate) fn check_delegate_payloads_not_expired(
    payloads: &[serde_json::Value],
    state: &Option<String>,
) -> Result<(), Error> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for payload in payloads {
        let Some(exp) = payload.get("exp") else {
            continue;
        };
        let exp = exp.as_i64().ok_or_else(|| Protocol {
            source: ProtocolError::transaction_data(
                "malformed delegate payload: exp is not an integer",
                state.to_owned(),
            ),
        })?;
        if now >= exp {
            return Err(Error::TransactionDataExpired { exp });
        }
    }
    Ok(())
}

/// Builds a `delegate` Transaction Data for Authorization Request.
///
/// Assembles the Array Disclosure `base64url([salt, { cnf?, ...payload_claims }])`
/// (See `delegate_payload_disclosure` in dSD-JWT draft 00 section 7.1)
/// and wraps it in a [`TransactionDataItem`].
///
/// # Errors
///
/// * Returns [`Error::Internal`] if nonce generation fails.
/// * Returns [`Error::Protocol`] (`InvalidTransactionData`) if serialisation of the
///   disclosure array fails — `request` itself is already validated by
///   [`DelegationRequest::open`] / [`DelegationRequest::holder_binding`].
#[cfg(feature = "delegate-sd-jwt")]
pub async fn delegate_transaction_data_item(
    request: &DelegationRequest,
    nonce_handler: &dyn crate::nonce::NonceHandler,
) -> Result<TransactionDataItem, Error> {
    let salt = nonce_handler
        .generate()
        .await
        .context(NonceGenerationSnafu)
        .map_err(|e| Internal { source: e })?
        .secret()
        .to_owned();

    let disclosure_bytes =
        serde_json::to_vec(&json!([salt, request.payload])).map_err(|_| Protocol {
            source: ProtocolError::new(
                ErrorType::InvalidTransactionData,
                Some("failed to serialise disclosure array".to_string()),
                None,
            ),
        })?;
    let disclosure = BASE64_URL_SAFE_NO_PAD.encode(&disclosure_bytes);

    Ok(TransactionDataItem {
        credential_ids: request.credential_ids.to_owned(),
        transaction_data_hashes_alg: None,
        content: TransactionDataItemTypeContent::DelegateSdJwt(DelegateSdJwtTransactionData {
            format: request.format.to_owned(),
            delegate_payload_disclosure: disclosure,
            delegate_disclosures: None,
        }),
    })
}

#[cfg(all(test, feature = "delegate-sd-jwt"))]
mod tests {
    use super::check_delegate_payloads_not_expired;
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::vc::oid4vp::api::{DelegationRequest, as_delegate, delegate_transaction_data_item};
    use crate::vc::oid4vp::{Error, ErrorType};
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use rstest::*;

    fn delegate_payload() -> serde_json::Map<String, serde_json::Value> {
        let mut claims = serde_json::Map::new();
        claims.insert("scope".to_string(), serde_json::json!("purchase"));
        claims
    }

    fn open_delegation_request() -> DelegationRequest {
        DelegationRequest::open(vec!["cred-1".to_string()], delegate_payload()).unwrap()
    }

    fn holder_binding_delegation_request() -> DelegationRequest {
        let jwk: ssi::jwk::JWK = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }))
        .expect("valid Ed25519 JWK");
        DelegationRequest::holder_binding(vec!["cred-1".to_string()], jwk, delegate_payload())
            .unwrap()
    }

    #[rstest]
    #[case::open(open_delegation_request())]
    #[case::holder_binding(holder_binding_delegation_request())]
    #[tokio::test]
    async fn delegate_transaction_data_item_builds_array_disclosure(
        #[case] request: DelegationRequest,
    ) {
        let mut claims = serde_json::Map::new();
        claims.insert("scope".to_string(), serde_json::json!("purchase"));

        let nonce_handler = LocalNonceHandler::default();

        let item = delegate_transaction_data_item(&request, &nonce_handler)
            .await
            .expect("builder must succeed");

        assert_eq!(item.type_(), "delegate");
        assert_eq!(item.credential_ids, vec!["cred-1".to_string()]);

        let d = as_delegate(&item).expect("must be a delegate item");
        assert!(d.delegate_disclosures.is_none());

        // Decode disclosure: base64url([salt, payload])
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(&d.delegate_payload_disclosure)
            .expect("must be valid base64url");
        let arr: serde_json::Value = serde_json::from_slice(&decoded).expect("must be valid JSON");
        let arr = arr.as_array().expect("must be a JSON array");

        assert!(arr[0].is_string(), "arr[0] (salt) must be a string");
        assert_eq!(
            arr[1]["scope"],
            serde_json::json!("purchase"),
            "payload must contain scope=purchase"
        );
    }

    #[tokio::test]
    async fn holder_binding_delegate_item_carries_cnf_when_set() {
        let request = holder_binding_delegation_request();
        let nonce_handler = LocalNonceHandler::default();
        let item = delegate_transaction_data_item(&request, &nonce_handler)
            .await
            .expect("builder must succeed");

        let d = as_delegate(&item).expect("must be a delegate item");

        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(&d.delegate_payload_disclosure)
            .expect("must be valid base64url");
        let arr: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let arr = arr.as_array().unwrap();

        let cnf = &arr[1]["cnf"];
        assert!(cnf.is_object(), "payload must contain cnf object");
        assert!(cnf["jwk"].is_object(), "cnf must contain jwk field");
    }

    #[rstest]
    #[case::no_exp(serde_json::json!({ "scope": "purchase" }))]
    #[case::future_exp(serde_json::json!({ "exp": i64::MAX }))]
    fn unexpired_delegate_payload_passes(#[case] payload: serde_json::Value) {
        check_delegate_payloads_not_expired(&[payload], &None).expect("payload must pass");
    }

    #[rstest]
    #[case::past(1)]
    #[case::now(now())]
    fn expired_delegate_payload_is_rejected(#[case] exp: i64) {
        let err = check_delegate_payloads_not_expired(&[serde_json::json!({ "exp": exp })], &None)
            .expect_err("expired payload must be rejected");
        assert!(matches!(err, Error::TransactionDataExpired { exp: e } if e == exp));
    }

    #[test]
    fn one_expired_delegate_payload_rejects_all() {
        let payloads = [
            serde_json::json!({ "exp": i64::MAX }),
            serde_json::json!({ "exp": 1 }),
        ];
        let err = check_delegate_payloads_not_expired(&payloads, &None)
            .expect_err("an expired payload among several must be rejected");
        assert!(matches!(err, Error::TransactionDataExpired { exp: 1 }));
    }

    #[rstest]
    #[case::string(serde_json::json!("1"))]
    #[case::fraction(serde_json::json!(1.5))]
    #[case::null(serde_json::Value::Null)]
    fn non_integer_exp_is_invalid_transaction_data(#[case] exp: serde_json::Value) {
        let err = check_delegate_payloads_not_expired(&[serde_json::json!({ "exp": exp })], &None)
            .expect_err("non-integer exp must be rejected");
        assert!(matches!(
            err,
            Error::Protocol { source } if *source.error_type() == ErrorType::InvalidTransactionData
        ));
    }

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }
}
