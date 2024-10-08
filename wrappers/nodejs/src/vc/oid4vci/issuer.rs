use crate::utils::{parse_string_arg, to_result_string};
use crate::vc::oid4vci::NonceData;
use agent_sdk::vc::oid4vci;
use agent_sdk::vc::oid4vci::Issuer;
use napi::{Error, Result};
use napi_derive::napi;

#[napi]
pub struct JsIssuer(pub(crate) Box<dyn Issuer>);

#[napi]
impl JsIssuer {
    #[napi]
    pub fn get_issuer_metadata(&self) -> Result<String> {
        let issuer_metadata = self.0.get_issuer_metadata();
        to_result_string(&issuer_metadata)
    }

    #[napi]
    pub fn get_cred_def_metadata(&self, cred_request: String) -> Result<Option<String>> {
        self.0
            .get_cred_def_metadata(&parse_string_arg(&cred_request)?)
            .map(|value| to_result_string(&value))
            .transpose()
    }

    #[napi]
    pub fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: String, // grant type (auth code, pre-auth code), etc.
    ) -> Result<CredentialOffer> {
        let (params, url) = self
            .0
            .create_credential_offer(cred_def_ids, &parse_string_arg(&grants)?)
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(CredentialOffer {
            params: to_result_string(&params)?,
            url: url.to_string(),
        })
    }

    #[napi]
    pub async fn issue_credential(
        &self,
        cred_request: String,
        token: String,
        claims: String,
        session: IssuanceSession,
    ) -> Result<IssuanceResult> {
        let mut oid4vci_session = session.try_into()?;

        let result = self
            .0
            .issue_credential(
                &parse_string_arg(&cred_request)?,
                &token,
                &parse_string_arg(&claims)?,
                &mut oid4vci_session,
            )
            .await;

        match result {
            Ok(cred_response) => Ok(IssuanceResult {
                type_: IssuanceResultType::CredResponse,
                value: to_result_string(&cred_response)?,
                session: oid4vci_session.try_into()?,
            }),
            Err(oid4vci::Error::Protocol { source }) => Ok(IssuanceResult {
                type_: IssuanceResultType::ProtocolError,
                value: to_result_string(&source)?,
                session: oid4vci_session.try_into()?,
            }),
            Err(err) => Err(Error::from_reason(format!("{:?}", err))),
        }
    }
}

#[napi(object)]
pub struct CredentialOffer {
    pub params: String,
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
    pub value: String,
    pub session: IssuanceSession,
}

#[napi(object)]
pub struct IssuanceSession {
    pub nonce: Option<NonceData>,
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

impl TryFrom<oid4vci::IssuanceSession> for IssuanceSession {
    type Error = Error;

    fn try_from(value: oid4vci::IssuanceSession) -> Result<Self> {
        let nonce = value.nonce.map(|nonce| nonce.try_into()).transpose()?;

        Ok(Self {
            nonce,
            notification_id: value.notification_id,
            transaction_id: value.transaction_id,
        })
    }
}
