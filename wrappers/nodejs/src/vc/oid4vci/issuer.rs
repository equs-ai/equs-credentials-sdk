use crate::result::IntoNapiError;
use agent_sdk::vc::oid4vci;
use agent_sdk::vc::oid4vci::Issuer;
use napi::Result;
use napi_derive::napi;

use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use crate::vc::core::JsCredentialStatusInfo;

/// An async `oid4vci` `Issuer` API.
///
/// Supports issuance flow according to the `oid4vci` standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// # Supported features
///
/// * exposing metadata
/// * credential issuance (immediate)
/// * credential offer generation
///
/// @property getIssuerMetadata - {@link OID4VCIIssuer.getIssuerMetadata}
/// @property getCredDefMetadata - {@link OID4VCIIssuer.getCredDefMetadata}
/// @property createCredentialOffer - {@link OID4VCIIssuer.createCredentialOffer}
/// @property issueCredential - {@link OID4VCIIssuer.issueCredential}
#[napi]
pub struct OID4VCIIssuer(pub(crate) Box<dyn Issuer>);

#[napi]
impl OID4VCIIssuer {
    /// @returns {IssuerMetadata}
    #[napi(ts_return_type = "OID4VCIIssuerMetadata")]
    pub fn get_issuer_metadata(&self) -> Result<JsonObject> {
        let issuer_metadata = self.0.get_issuer_metadata();

        to_json_object(issuer_metadata)
    }

    /// @param {OID4VCICredentialRequest} credRequest - credential request
    ///
    /// @returns {OID4VCICredentialMetadata | null}
    /// * if `credRequest` contains valid values.
    /// * `null` otherwise
    #[napi(
        ts_args_type = "credRequest: OID4VCICredentialRequest",
        ts_return_type = "OID4VCICredentialMetadata | null"
    )]
    pub fn get_cred_def_metadata(&self, cred_request: JsonObject) -> Result<Option<JsonObject>> {
        self.0
            .get_cred_def_metadata(&from_json_object(cred_request)?)
            .map(to_json_object)
            .transpose()
    }

    /// Generate a fresh nonce by using {@link NonceHandler}
    ///
    /// Generated nonce inside the {@link NonceResponse} to be later used by `Holder` to create a proof of possession
    /// that will be incorporated into proofs in the {@link CredentialRequest}.
    ///
    ///
    /// @returns {NonceResponse} - A `NonceResponse` with the fresh nonce.
    #[napi]
    pub async fn generate_nonce(&self) -> Result<NonceResponse> {
        let response = self
            .0
            .generate_nonce()
            .await
            .map_err(IntoNapiError::into_napi_error)?;

        Ok(NonceResponse {
            c_nonce: response.c_nonce().secret().to_string(),
        })
    }

    /// Create a {@link CredentialOffer} for multiple `CredDef` ids.
    ///
    /// Generated {@link CredentialOffer} matches provided {@link CredentialDefinition}s
    /// and should be later used by `Holder` to create a corresponding {@link CredentialRequest}.
    ///
    /// @param {Array<string>} credDefIds - a vector with {@link CredentialDefinition} IDs.
    /// @param {CredentialOfferGrants} grants - grant types of the generated `Offer`, contains which flow is defined - pre-authorized/authorized.
    ///
    /// @returns {CredentialOffer} - A `CredentialOfferParams` and the corresponding Url to be shared with `Holder` on success.
    #[napi]
    pub fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,

        #[napi(ts_arg_type = "CredentialOfferGrants")] grants: JsonObject, // grant type (auth code, pre-auth code), etc.
    ) -> Result<CredentialOffer> {
        let (params, url) = self
            .0
            .create_credential_offer(cred_def_ids, &from_json_object(grants)?)
            .map_err(IntoNapiError::into_napi_error)?;

        Ok(CredentialOffer {
            params: to_json_object(params)?,
            url: url.to_string(),
        })
    }

    /// Issue a {@link Credential} based on the provided {@link CredentialRequest}.
    ///
    /// {@link CredentialRequest} should match some existing {@link CredentialDefinition} defined in the {@link IssuerMetadata}.
    /// `Proof of Possession` is mandatory.
    ///
    /// This method should be used for `Immediate` credential issuance.
    /// `Deferred` option is not supported yet.
    ///
    /// @param {OID4VCICredentialRequest} credRequest - a {@link CredentialRequest} used for {@link Credential} generation.
    /// @param {string} token - an access token used for authorization.
    /// @param {Claims} claims - claims to include into the {@link Credential}.
    /// @param {CredentialStatusInfo} [statusInfo] - an object which contains information for status validation.
    ///
    /// @returns {IssuanceResult} A {@link IssuanceResult} (containing serialized {@linkCredential}) on success.
    #[napi]
    pub async fn issue_credential(
        &self,
        #[napi(ts_arg_type = "OID4VCICredentialRequest")] cred_request: JsonObject,
        token: String,
        #[napi(ts_arg_type = "Claims")] claims: JsonObject,
        status_info: Option<JsCredentialStatusInfo>,
    ) -> Result<IssuanceResult> {
        let status_info = match status_info {
            Some(status) => Some(status.try_into()?),
            None => None,
        };

        let result = self
            .0
            .issue_credential(
                &from_json_object(cred_request)?,
                &token,
                &from_json_object(claims)?,
                status_info,
            )
            .await;

        match result {
            Ok(cred_response) => Ok(IssuanceResult {
                type_: IssuanceResultType::CredResponse,
                value: to_json_object(cred_response)?,
            }),
            Err(oid4vci::Error::Protocol { source }) => Ok(IssuanceResult {
                type_: IssuanceResultType::ProtocolError,
                value: to_json_object(source)?,
            }),
            Err(err) => Err(err.into_napi_error()),
        }
    }
}

#[napi(object)]
pub struct CredentialOffer {
    pub params: JsonObject,
    pub url: String,
}

#[napi(object)]
pub struct NonceResponse {
    #[napi(js_name = "c_nonce")]
    pub c_nonce: String,
}

#[napi]
pub enum IssuanceResultType {
    CredResponse,
    ProtocolError,
}

#[napi(object)]
pub struct IssuanceResult {
    pub type_: IssuanceResultType,
    pub value: JsonObject,
}
