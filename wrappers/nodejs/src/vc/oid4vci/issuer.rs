use agent_sdk::vc::oid4vci;
use agent_sdk::vc::oid4vci::Issuer;
use napi::{Error, Result};
use napi_derive::napi;

use crate::nonce::JsNonceData;
use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;

#[napi]
pub struct OID4VCIIssuer(pub(crate) Box<dyn Issuer>);

#[napi]
impl OID4VCIIssuer {
    #[napi]
    pub fn get_issuer_metadata(&self) -> Result<JsonObject> {
        let issuer_metadata = self.0.get_issuer_metadata();

        to_json_object(issuer_metadata)
    }

    #[napi]
    pub fn get_cred_def_metadata(&self, cred_request: JsonObject) -> Result<Option<JsonObject>> {
        self.0
            .get_cred_def_metadata(&from_json_object(cred_request)?)
            .map(to_json_object)
            .transpose()
    }

    #[napi]
    pub fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: JsonObject, // grant type (auth code, pre-auth code), etc.
    ) -> Result<CredentialOffer> {
        let (params, url) = self
            .0
            .create_credential_offer(cred_def_ids, &from_json_object(grants)?)
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(CredentialOffer {
            params: to_json_object(params)?,
            url: url.to_string(),
        })
    }

    #[napi]
    pub async fn issue_credential(
        &self,
        cred_request: JsonObject,
        token: String,
        claims: JsonObject,
        session: IssuanceSession,
    ) -> Result<IssuanceResult> {
        let mut oid4vci_session = session.try_into()?;

        let result = self
            .0
            .issue_credential(
                &from_json_object(cred_request)?,
                &token,
                &from_json_object(claims)?,
                &mut oid4vci_session,
            )
            .await;

        match result {
            Ok(cred_response) => Ok(IssuanceResult {
                type_: IssuanceResultType::CredResponse,
                value: to_json_object(cred_response)?,
                session: oid4vci_session.into(),
            }),
            Err(oid4vci::Error::Protocol { source }) => Ok(IssuanceResult {
                type_: IssuanceResultType::ProtocolError,
                value: to_json_object(source)?,
                session: oid4vci_session.into(),
            }),
            Err(err) => Err(Error::from_reason(format!("{:?}", err))),
        }
    }
}

#[napi(object)]
pub struct CredentialOffer {
    pub params: JsonObject,
    pub url: String,
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
    pub session: IssuanceSession,
}

#[napi(object)]
pub struct IssuanceSession {
    pub nonce: Option<JsNonceData>,
    pub notification_id: Option<String>,
    pub transaction_id: Option<String>,
}

impl TryFrom<IssuanceSession> for oid4vci::IssuanceSession {
    type Error = Error;

    fn try_from(value: IssuanceSession) -> Result<Self> {
        let nonce = value.nonce.map(|nonce| nonce.try_into()).transpose()?;

        Ok(Self {
            nonce,
            notification_id: value.notification_id,
            transaction_id: value.transaction_id,
        })
    }
}

impl From<oid4vci::IssuanceSession> for IssuanceSession {
    fn from(value: oid4vci::IssuanceSession) -> Self {
        Self {
            nonce: value.nonce.map(|nonce| nonce.into()),
            notification_id: value.notification_id,
            transaction_id: value.transaction_id,
        }
    }
}
