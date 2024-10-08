use crate::utils::{parse_string_arg, to_result_string};
use crate::vc::core::{JsCredential, JsCredentialMetadata, JsKeyMetadata};
use crate::vc::oid4vci::NonceData;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci::{
    CredentialResponseResolved, CredentialResult, Holder, IssuerMetadata, TokenResponse,
};
use agent_sdk::vc::{oid4vci, Credential, CredentialMetadata};
use async_trait::async_trait;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::Either;
use napi_derive::napi;
use oauth2::AccessToken;
use tokio::runtime::Handle;
use url::Url;

#[napi]
pub struct JsHolder(Box<dyn _HolderWrapperTrait>);

impl JsHolder {
    pub fn from_holder<H: Holder + 'static>(holder: H) -> JsHolder {
        JsHolder(Box::new(_HolderWrapper(holder)))
    }
}

#[napi]
impl JsHolder {
    #[napi]
    pub fn get_issuer_metadata(&self) -> napi::Result<String> {
        let issuer_metadata = self.0.get_issuer_metadata();
        to_result_string(&issuer_metadata)
    }

    #[napi]
    pub async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    ) -> napi::Result<String> {
        let token_response = self
            .0
            .authz_code_flow_with_scope(
                scope,
                Box::new(move |url| {
                    // TODO: Refactor `authorization_callback` to allow asynchronous execution and handling of errors.
                    Handle::current().block_on(async {
                        authorization_callback
                            .call_async(url.to_string())
                            .await
                            .unwrap()
                    })
                }),
            )
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))?;

        to_result_string(&token_response)
    }

    #[napi]
    pub async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> napi::Result<String> {
        let token_response = self
            .0
            .pre_authz_code_flow(pre_authorized_code, tx_code, cred_def_id)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))?;

        to_result_string(&token_response)
    }

    #[napi]
    pub async fn request_credential(
        &self,
        token: String,
        cred_def_id: String,
        nonce: Option<String>,
        key_metadata: JsKeyMetadata,
    ) -> napi::Result<CredentialResponse> {
        let nonce = nonce.map(|value| parse_string_arg(&value)).transpose()?;
        let token = parse_string_arg(&token)?;
        let key_metadata = key_metadata.into();

        let result = self
            .0
            .request_credential(&token, &cred_def_id, nonce, &key_metadata)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))?;

        result.try_into()
    }

    #[napi]
    pub async fn store_credential(
        &self,
        credential: JsCredential,
        credential_metadata: JsCredentialMetadata,
    ) -> napi::Result<()> {
        self.0
            .store_credential(&credential.try_into()?, &credential_metadata.into())
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))
    }
}

#[napi(object)]
pub struct CredentialDeferred {
    pub transaction_id: String,
}

#[napi(object)]
pub struct CredentialImmediate {
    pub credential: JsCredential,
    pub notification_id: Option<String>,
}

#[napi(object)]
pub struct CredentialResponse {
    pub data: Either<CredentialDeferred, CredentialImmediate>,
    pub nonce_data: Option<NonceData>,
}

impl TryFrom<CredentialResponseResolved> for CredentialResponse {
    type Error = napi::Error;

    fn try_from(value: CredentialResponseResolved) -> napi::Result<Self> {
        let data = match value.data {
            CredentialResult::Deferred { transaction_id } => {
                Either::A(CredentialDeferred { transaction_id })
            }
            CredentialResult::Credential {
                credential,
                notification_id,
            } => Either::B(CredentialImmediate {
                credential: credential.try_into()?,
                notification_id,
            }),
        };

        Ok(Self {
            data,
            nonce_data: value.nonce_data.map(|value| value.try_into()).transpose()?,
        })
    }
}

#[async_trait]
trait _HolderWrapperTrait: Send + Sync {
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: Box<dyn FnOnce(url::Url) -> String + Send>,
    ) -> oid4vci::Result<TokenResponse>;

    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> oid4vci::Result<TokenResponse>;

    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        nonce: Option<agent_sdk::nonce::NonceData>,
        key_metadata: &KeyMetadata,
    ) -> oid4vci::Result<CredentialResponseResolved>;

    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> oid4vci::Result<()>;
}

pub struct _HolderWrapper<H: Holder>(pub(crate) H);

#[async_trait]
impl<H: Holder> _HolderWrapperTrait for _HolderWrapper<H> {
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.0.get_issuer_metadata()
    }

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: Box<dyn FnOnce(Url) -> String + Send>,
    ) -> oid4vci::Result<TokenResponse> {
        self.0
            .authz_code_flow_with_scope(scope, authorization_callback)
            .await
    }

    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> oid4vci::Result<TokenResponse> {
        self.0
            .pre_authz_code_flow(pre_authorized_code, tx_code, cred_def_id)
            .await
    }

    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        nonce: Option<agent_sdk::nonce::NonceData>,
        key_metadata: &KeyMetadata,
    ) -> oid4vci::Result<CredentialResponseResolved> {
        self.0
            .request_credential(token, cred_def_id, nonce.as_ref(), key_metadata)
            .await
    }

    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> oid4vci::Result<()> {
        self.0
            .store_credential(credential, credential_metadata)
            .await
    }
}
