use crate::utils::from_json_object;
use crate::vc::JsonObject;
use agent_sdk::vc::oid4vp;
use agent_sdk::vc::oid4vp::{
    AuthorizationResponse, AuthorizationResponseObject, HashAlgorithm, PresentationResult,
    TransactionDataHashes, TransactionDataHashesAlg, TransactionDataResponse,
};
use agent_sdk::vc::presentation_exchange::PresentationSubmission;
use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Status};
use napi_derive::napi;

pub mod builder;
pub mod delegate;
pub mod error;
pub mod holder;
pub mod verifier;

#[napi(js_name = "InnerPresentationResult", object)]
pub struct JsPresentationResult {
    pub type_: PresentationResultType,
    pub value: Option<serde_json::Value>,
}

#[napi(string_enum)]
pub enum PresentationResultType {
    AuthorizationResponse,
    RedirectUri,
    Presented,
}

/// An OID4VP authorization response.
/// It can be either plain object as below or the Jwe response string of the fields below
/// @property {any} vpToken - VP Token containing the Verifiable Presentation(s).
/// @property {string | null} [idToken] - The OpenID Connect ID token used in the SIOP flow.
/// @property {PresentationSubmission} presentationSubmission - Details of the submitted presentation.
/// @property {string | null} [state] - The state may be used by a verifier to link requests and responses.
#[napi(js_name = "AuthorizationResponseType")]
pub enum JsAuthorizationResponseType {
    Plain,
    Jwe,
}

#[napi(js_name = "InnerAuthorizationResponse", object)]
pub struct JsInnerAuthorizationResponse {
    pub type_: JsAuthorizationResponseType,
    pub object: Option<JsAuthorizationResponseObject>,
    pub jwe: Option<String>,
}

impl TryFrom<JsInnerAuthorizationResponse> for AuthorizationResponse {
    type Error = Error;

    fn try_from(value: JsInnerAuthorizationResponse) -> napi::Result<Self> {
        match value.type_ {
            JsAuthorizationResponseType::Plain => {
                let object = value.object.ok_or(Error::from_reason(
                    "AuthorizationResponseObject was expected but none",
                ))?;
                Ok(AuthorizationResponse::Plain(object.try_into()?))
            }
            JsAuthorizationResponseType::Jwe => {
                let jwe = value.jwe.ok_or(Error::from_reason(
                    "AuthorizationResponse Jwe was expected but none",
                ))?;
                Ok(AuthorizationResponse::Jwe(jwe))
            }
        }
    }
}

/// An OID4VP authorization response object.
///
/// @property {any} vpToken - VP Token containing the Verifiable Presentation(s).
/// @property {string | null} [idToken] - The OpenID Connect ID token used in the SIOP flow.
/// @property {PresentationSubmission} presentationSubmission - Details of the submitted presentation.
/// @property {string | null} [state] - The state may be used by a verifier to link requests and responses.
#[napi(js_name = "AuthorizationResponseObject", object)]
pub struct JsAuthorizationResponseObject {
    pub vp_token: serde_json::Value,
    pub id_token: Option<String>,
    #[napi(ts_type = "PresentationSubmission")]
    pub presentation_submission: Option<JsonObject>,
    pub state: Option<String>,
    pub transaction_data_response: Option<JsTransactionDataResponse>,
}

#[derive(Clone)]
#[napi(js_name = "TransactionDataResponse", object)]
pub struct JsTransactionDataResponse {
    pub hashes: Vec<String>,
    pub alg: Option<String>,
}

impl TryFrom<JsTransactionDataResponse> for TransactionDataResponse {
    type Error = Error;
    fn try_from(value: JsTransactionDataResponse) -> napi::Result<Self> {
        let transaction_data_hashes = TransactionDataHashes(value.hashes);
        let transaction_data_hashes_alg = match value.alg {
            None => None,
            Some(a) => {
                let hash_alg: HashAlgorithm = a
                    .try_into()
                    .map_err(|_| Error::from_reason("Unsupported Hash algorithm".to_string()))?;
                Some(TransactionDataHashesAlg(hash_alg))
            }
        };
        Ok(Self {
            transaction_data_hashes,
            transaction_data_hashes_alg,
        })
    }
}

impl TryFrom<JsAuthorizationResponseObject> for AuthorizationResponseObject {
    type Error = Error;

    fn try_from(value: JsAuthorizationResponseObject) -> napi::Result<Self> {
        let ps: Option<PresentationSubmission> = value
            .presentation_submission
            .map(from_json_object)
            .transpose()?;
        let transaction_data_response = match value.transaction_data_response {
            None => None,
            Some(tdr) => {
                let t = tdr.try_into()?;
                Some(t)
            }
        };
        Ok(Self {
            vp_token: value.vp_token,
            id_token: value.id_token,
            presentation_submission: ps,
            state: value.state,
            transaction_data_response,
        })
    }
}

impl TryFrom<PresentationResult> for JsPresentationResult {
    type Error = Error;

    fn try_from(value: PresentationResult) -> napi::Result<Self> {
        let result = match value {
            PresentationResult::AuthorizationResponse(auth_resp) => JsPresentationResult {
                type_: PresentationResultType::AuthorizationResponse,
                value: Some(serde_json::to_value(&auth_resp)?),
            },
            PresentationResult::RedirectUri(uri) => JsPresentationResult {
                type_: PresentationResultType::RedirectUri,
                value: Some(serde_json::to_value(&uri)?),
            },
            PresentationResult::Presented => JsPresentationResult {
                type_: PresentationResultType::Presented,
                value: None,
            },
        };

        Ok(result)
    }
}

/// A client identifier used in OpenID4VP protocol.
///
/// Construct one from a string, a DID, a redirect URI, a DNS name, or an X.509
/// certificate chain;
#[napi]
pub struct ClientId(oid4vp::ClientId);

#[napi]
impl ClientId {
    /// Creates a new ClientId instance from a string.
    ///
    /// @param {string} clientId - The client identifier string.
    /// @returns {ClientId} A client identifier used in OpenID4VP protocol.
    /// @throws {Error} If the client_id is invalid.
    #[napi(constructor)]
    pub fn new(client_id: String) -> napi::Result<Self> {
        oid4vp::ClientId::new(client_id)
            .map_err(|err| Error::new(Status::InvalidArg, err))
            .map(ClientId)
    }

    /// The full identifier, `<prefix>:<id>` — the exact value the verifier puts
    /// in the `client_id` of the authorization request.
    ///
    /// This is the value to persist, log, and return in a DTO. Because an
    /// `x509_hash` identifier is a hash of the leaf certificate, rotating that
    /// certificate changes this string: compare it against the stored one to
    /// detect that the relying party's identity has moved.
    ///
    /// @returns {string} The full client identifier.
    #[napi(getter)]
    pub fn full_id(&self) -> String {
        self.0.get_full_id()
    }

    /// The client id prefix on its own, e.g. `x509_hash`, `x509_san_dns`,
    /// `decentralized_identifier`, `redirect_uri`, or `pre-registered` for a
    /// string that carried no prefix.
    ///
    /// @returns {string} The client id prefix.
    #[napi(getter)]
    pub fn prefix(&self) -> String {
        self.0.get_prefix().to_string()
    }

    /// The identifier without its prefix — the DNS name for `x509_san_dns`, the
    /// leaf certificate hash for `x509_hash`, the DID for
    /// `decentralized_identifier`, and so on.
    ///
    /// @returns {string} The client identifier without its prefix.
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.0.get_id()
    }

    /// Creates a ClientId instance from a DID.
    ///
    /// @param {string} did - The DID of the client.
    /// @returns {ClientId} A new ClientId instance created from the DID used in OpenID4VP protocol.
    /// @throws {Error} If the DID is invalid or cannot be processed.
    #[napi]
    pub fn from_did(did: String) -> napi::Result<Self> {
        oid4vp::ClientId::from_did(did.as_str())
            .map_err(|err| Error::new(Status::InvalidArg, err))
            .map(ClientId)
    }

    /// Creates a ClientId instance from a redirect URI.
    ///
    /// @param {string} redirectUri - The redirect URI to create the client ID from.
    /// @returns {ClientId} A new ClientId instance created from the redirect URI used in OpenID4VP protocol.
    /// @throws {Error} If the redirect URI is invalid or cannot be processed.
    #[napi]
    pub fn from_redirect_uri(redirect_uri: String) -> napi::Result<Self> {
        let uri =
            url::Url::parse(&redirect_uri).map_err(|err| Error::new(Status::InvalidArg, err))?;

        oid4vp::ClientId::from_redirect_uri(&uri)
            .map_err(|err| Error::new(Status::InvalidArg, err))
            .map(ClientId)
    }

    /// Creates a ClientId instance from a DNS name, using the `x509_san_dns`
    /// prefix.
    ///
    /// The verifier's certificate chain must have `dnsName` as the Subject
    /// Alternative Name of its leaf, otherwise creating an authorization request
    /// fails. Use {@link ClientId.fromX509CertificateChain} to derive the value
    /// from the chain itself instead of restating it here.
    ///
    /// @param {string} dnsName - The DNS name of the verifier, e.g. `verifier.example`.
    /// @returns {ClientId} A new `x509_san_dns` ClientId instance.
    /// @throws {Error} If the resulting client id is invalid.
    #[napi]
    pub fn from_x509_san_dns(dns_name: String) -> napi::Result<Self> {
        let prefix = oid4vp::ClientIdPrefix::X509SanDns.to_string();
        let id = format!("{prefix}:{dns_name}");

        oid4vp::ClientId::new(id)
            .map_err(|err| Error::new(Status::InvalidArg, err))
            .map(ClientId)
    }

    /// Derives a ClientId from the verifier's X.509 certificate chain — the
    /// leaf's Subject Alternative Name for `x509_san_dns`, the leaf's hash for
    /// `x509_hash`.
    ///
    /// An `x509_hash` client id cannot be written by hand, and request
    /// generation rejects any client id the chain does not derive, so pass the
    /// same PEM here and to `OID4VPVerifierBuilder.withX509CertificateChain`.
    ///
    /// @param {Uint8Array} pemBytes - a PEM-encoded, leaf-first certificate chain.
    /// @param {X509Variant} variant - which prefix to derive.
    /// @returns {ClientId} A new X.509 ClientId instance.
    /// @throws {Error} If the chain cannot be parsed, is empty, or yields no client id for `variant`.
    #[napi]
    pub fn from_x509_certificate_chain(
        pem_bytes: Uint8Array,
        variant: JsX509Variant,
    ) -> napi::Result<Self> {
        let chain = oid4vp::Certificate::load_pem_chain(&pem_bytes)
            .map_err(|err| Error::new(Status::InvalidArg, err))?;

        oid4vp::client_id_from_x509_chain(&chain, variant.into())
            .map_err(|err| Error::new(Status::InvalidArg, err))
            .map(ClientId)
    }
}

/// Selects how an X.509 client id is derived from the verifier's leaf
/// certificate.
#[napi(js_name = "X509Variant", string_enum)]
pub enum JsX509Variant {
    /// `x509_san_dns:<leaf Subject Alternative Name>`.
    SanDns,
    /// `x509_hash:<hash of the leaf certificate>`.
    Hash,
}

impl From<JsX509Variant> for oid4vp::X509Variant {
    fn from(value: JsX509Variant) -> Self {
        match value {
            JsX509Variant::SanDns => oid4vp::X509Variant::SanDns,
            JsX509Variant::Hash => oid4vp::X509Variant::Hash,
        }
    }
}
