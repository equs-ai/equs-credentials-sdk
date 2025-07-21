use crate::http::HttpClient;
use crate::nonce::Nonce;
use crate::utils::wasm::WasmNotSend;
use crate::vc;
use crate::vc::core::{CredentialOffer, CredentialOfferContent, KeyMetadata, Proof as AsdkProof};
use crate::vc::oid4vci::AuthzFlow::Authorize;
use crate::vc::oid4vci::internal_error::{
    AuthorizationCallbackSnafu, DiscoverySnafu, HolderServiceSnafu, MetadataSnafu, ParseSnafu,
    TypeConversionSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::protocol_error::ProtocolSnafu;
use crate::vc::oid4vci::{
    AuthorizationMetadata, AuthzFlow, CredDefMetadata, CredentialOfferParams, CredentialResponse,
    CredentialResponseResolved, CredentialResult, IssuerMetadata, PreAuthorizedCode, TxCode,
    metadata,
};
use crate::vc::{Credential, CredentialMetadata};
use crate::vc::{HasVCFormat, oid4vci as api};
use async_trait::async_trait;
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthorizationCode, ClientId, CsrfToken, HttpRequest, HttpResponse,
    PkceCodeChallenge, RedirectUrl, ResponseType, Scope,
};
use oid4vci::core::authorization::AuthorizationDetailsObject;
use oid4vci::core::client::Client;
use oid4vci::core::profiles::CoreProfilesCredentialResponseType;
use oid4vci::credential::{CredentialId, ErrorType, ResponseEnum};
use oid4vci::metadata::MetadataDiscovery;
use oid4vci::metadata::credential_issuer::BatchCredentialIssuance;
use oid4vci::proof_of_possession::{Proof as SpruceProof, Proof};
use oid4vci::token;
use oid4vci::types::{CredentialConfigurationId, IssuerUrl};
use snafu::{ResultExt, ensure};
use std::future::Future;
use std::pin::Pin;
use std::string::ToString;
use std::sync::Arc;
use tracing::{Level, debug, info, instrument, trace};

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum AuthzOption {
    Scope(String),
    Details(AuthorizationDetailsObject),
}

pub struct HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient,
{
    holder: HL,
    http_client: Arc<HC>,
    client_id: String,
    issuer_metadata: IssuerMetadata,
    client: Client,
}

impl<HL, HC> HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient + 'static,
{
    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    pub async fn from_iss_url(
        holder: HL,
        http_client: Arc<HC>,
        issuer_url: String,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        info!("oid4vci-holder service initialization is started");

        let holder_service = Self::from_iss_url_with_configs(
            holder,
            http_client,
            issuer_url,
            client_id,
            redirect_url,
        )
        .await;

        info!("oid4vci-holder service is initialized");

        holder_service
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    pub async fn from_credential_offer(
        holder: HL,
        http_client: Arc<HC>,
        offer: &CredentialOfferParams,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        info!("oid4vci-holder service initialization is started");

        let iss_url = offer.credential_issuer.clone();

        let holder_service = Self::from_iss_url_with_configs(
            holder,
            http_client,
            iss_url.to_string(),
            client_id,
            redirect_url,
        )
        .await;

        info!("oid4vci-holder service is initialized");

        holder_service
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    async fn from_iss_url_with_configs(
        holder: HL,
        http_client: Arc<HC>,
        issuer_url: String,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        let client = http_client.clone();
        let http_closure = move |req| {
            let client = client.clone();
            Box::pin(async move { client.async_call(req).await })
        };

        let issuer_url = IssuerUrl::new(issuer_url.clone()).context(UrlParseSnafu)?;
        let issuer_metadata = IssuerMetadata::discover_async(&issuer_url, &http_closure)
            .await
            .context(DiscoverySnafu)?;
        debug!(resolved_issuer_metadata = ?issuer_metadata);

        let auth_srv_url = issuer_metadata
            .authorization_servers()
            .and_then(|vec| vec.iter().next());

        let authz_metadata = AuthorizationMetadata::discover_async(
            auth_srv_url.unwrap_or(&issuer_url),
            &http_closure,
        )
        .await
        .context(DiscoverySnafu)?;
        debug!(resolved_authorization_server_metadata = ?authz_metadata);

        Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            client_id,
            redirect_url,
        )
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    pub fn from_metadata(
        holder: HL,
        http_client: Arc<HC>,
        issuer_metadata: IssuerMetadata,
        authz_metadata: AuthorizationMetadata,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        let holder_service = Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            client_id,
            redirect_url,
        );
        info!("oid4vci-holder service is initialized");

        holder_service
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    fn new(
        holder: HL,
        http_client: Arc<HC>,
        issuer_metadata: IssuerMetadata,
        authz_metadata: AuthorizationMetadata,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        let client = Client::from_issuer_metadata(
            ClientId::new(client_id.clone()),
            RedirectUrl::new(redirect_url.clone()).context(UrlParseSnafu)?,
            issuer_metadata.clone(),
            authz_metadata,
        );

        info!("oid4vci-holder service is initialized");

        Ok(Self {
            holder,
            http_client,
            client_id,
            issuer_metadata,
            client,
        })
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn exchange_pre_auth_code_for_token(
        &self,
        issuer_url: Option<&IssuerUrl>,
        pre_authorized_code: PreAuthorizedCode,
        transaction_code: TxCode,
    ) -> Result<token::Response> {
        let mut req = self
            .client
            .exchange_pre_authorized_code(pre_authorized_code)
            .set_tx_code(&transaction_code);

        if let Some(issuer_url) = issuer_url {
            let auth_serv_metadata =
                AuthorizationMetadata::discover_async(issuer_url, &self.http_closure())
                    .await
                    .context(DiscoverySnafu)?;

            req = req.set_token_url(auth_serv_metadata.token_endpoint().clone())
        }
        let token = req.request_async(&self.http_closure()).await.map_err(|e| {
            HolderServiceSnafu {
                details: format!("Could not exchange preauthorized code to token: {e}"),
            }
            .build()
        })?;

        Ok(token)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<HL, HC> api::Holder for HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient + 'static,
{
    #[instrument(level = Level::TRACE, skip_all, ret())]
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    #[instrument(level = Level::TRACE, skip(self, authorization_callback), err(), ret())]
    async fn authz_code_flow_with_scope<AC, F, E>(
        &self,
        scope: String,
        authorization_callback: AC,
    ) -> Result<token::Response>
    where
        AC: FnOnce(Url) -> F + WasmNotSend,
        F: Future<Output = std::result::Result<String, E>> + WasmNotSend,
        E: std::error::Error + 'static,
    {
        info!("authorization code flow is started");

        let response = self
            .authz_code_flow(
                // TODO: advanced AuthDetail by cred_def_id, scope is enough for MVP
                AuthzOption::Scope(scope),
                authorization_callback,
            )
            .await?;

        info!("authorization code flow is succeeded");

        Ok(response)
    }

    #[instrument(level = Level::TRACE, skip(self, authorization_callback), err(), ret())]
    async fn get_access_token<AC, F, E>(
        &self,
        offer_params: &CredentialOfferParams,
        authorization_callback: AC,
    ) -> Result<api::TokenResponse>
    where
        AC: FnOnce(AuthzFlow) -> F + WasmNotSend,
        F: Future<Output = std::result::Result<String, E>> + WasmNotSend,
        E: std::error::Error + 'static,
    {
        let grants = offer_params.grants.as_ref().ok_or_else(|| {
            HolderServiceSnafu {
                details: "credential offer grants is not provided",
            }
            .build()
        })?;

        if let Some(pre_auth_code) = &grants.pre_authorized_code {
            let tx_code = authorization_callback(AuthzFlow::Preauthorized)
                .await
                .map_err(|e| {
                    AuthorizationCallbackSnafu {
                        details: e.to_string(),
                    }
                    .build()
                })?;

            return self
                .exchange_pre_auth_code_for_token(
                    pre_auth_code.authorization_server(),
                    pre_auth_code.pre_authorized_code().to_owned(),
                    TxCode::new(tx_code),
                )
                .await;
        }

        if let Some(authorization) = &grants.authorization_code {
            let scope = offer_params
                .credential_configuration_ids
                .iter()
                .find_map(|cc| {
                    self.resolve_cred_def(cc)
                        .map(|c| c.scope().map(|s| s.to_string()))
                        .unwrap_or(None)
                })
                .ok_or_else(|| {
                    ProtocolSnafu::new(
                        ErrorType::UnsupportedCredentialType,
                        format!(
                            "Unsupported credential definition IDs: {}",
                            offer_params
                                .credential_configuration_ids
                                .iter()
                                .map(|c| c.to_string())
                                .collect::<Vec<String>>()
                                .join(", ")
                        ),
                    )
                    .build()
                })?;

            return self
                .authz_code_flow_with_scope(scope, |url| authorization_callback(Authorize(url)))
                .await;
        }

        HolderServiceSnafu {
            details:
                "credential offer authorization code or pre-authorized grants are not provided",
        }
        .fail()?
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        keys_metadata: &[KeyMetadata],
    ) -> Result<CredentialResponseResolved> {
        info!("requesting a credential flow is started");

        let cred_def = self.resolve_cred_def(cred_def_id)?;

        let supported_proofs = metadata::supported_proofs(&cred_def).context(MetadataSnafu)?;
        let offer = &CredentialOffer {
            cred_offer_id: None,
            issuer_id: self.issuer_metadata.credential_issuer().to_string(),
            cred_def_id: cred_def_id.to_owned(),
            content: CredentialOfferContent::SupportedProofs(supported_proofs),
            protocol_data: None,
        };
        trace!(credential_offer = ?offer);

        let nonce = self.request_nonce().await?;
        trace!(resolved_nonce = ?nonce);

        let proof = self.resolve_proof(keys_metadata, offer, nonce).await?;

        let credential_request = self
            .client
            .request_credential(
                token.to_owned(),
                CredentialId::CredentialConfigurationId(cred_def.id().to_owned()),
            )
            .set_proof(proof);

        let resp = credential_request
            .request_async(&self.http_closure())
            .await?;

        let cred_result: CredentialResult = (&resp).try_into()?;

        if let CredentialResult::Credential { credentials, .. } = &cred_result {
            info!("credential(s) is received");

            for credential in credentials {
                self.holder
                    .verify_credential(credential)
                    .await
                    .context(VCSnafu)?;
            }
            info!("credential(s) is verified");
        }

        info!("requesting a credential flow is succeeded");

        Ok(CredentialResponseResolved { data: cred_result })
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<String> {
        info!("storing credential is started");

        let id = self
            .holder
            .store_credential(credential, credential_metadata)
            .await
            .context(VCSnafu)?;

        info!("credential is stored");

        Ok(id)
    }
}

impl<HL, HC> HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient + 'static,
{
    #[instrument(level = Level::TRACE, skip(self, callback), err(), ret())]
    async fn authz_code_flow<AC, F, E>(
        &self,
        opt: AuthzOption,
        callback: AC,
    ) -> Result<token::Response>
    where
        AC: FnOnce(Url) -> F + WasmNotSend,
        F: Future<Output = std::result::Result<String, E>> + WasmNotSend,
        E: std::error::Error + 'static,
    {
        info!("authorization is started");

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let in_csrf = CsrfToken::new_random();
        let push_request = self
            .client
            .pushed_authorization_request(|| in_csrf.clone())
            .map_err(|e| {
                ProtocolSnafu::new(ErrorType::InvalidCredentialRequest, e.to_string()).build()
            })?
            .set_pkce_challenge(pkce_challenge);

        let push_request = match opt {
            AuthzOption::Scope(scope) => push_request
                .set_scope(Scope::new(scope))
                .set_response_type(&ResponseType::new("code".into())),
            AuthzOption::Details(detail) => push_request
                .set_authorization_details(vec![detail])
                .context(ParseSnafu)?,
        };
        info!("holder is sending auth request");

        let (auth_url, out_csrf) = push_request.async_request(&self.http_closure()).await?;

        ensure!(
            in_csrf.secret() == out_csrf.secret(),
            ProtocolSnafu::new(
                ErrorType::InvalidCredentialRequest,
                "CSRF failure".to_string()
            ),
        );

        info!("authentication is started");
        let code = callback(auth_url).await.map_err(|e| {
            AuthorizationCallbackSnafu {
                details: e.to_string(),
            }
            .build()
        })?;
        info!("authentication is completed");
        trace!(authorization_code = %code);

        let token_req = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier);
        trace!(code_to_token_request = ?token_req);

        let token = token_req
            .request_async(&self.http_closure())
            .await
            .map_err(|e| {
                ProtocolSnafu::new(ErrorType::InvalidCredentialRequest, e.to_string()).build()
            })?;

        info!("authorization is succeeded");

        Ok(token)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn deferred(
        &self,
        token: AccessToken,
        transaction_id: String,
    ) -> Result<CredentialResult> {
        unimplemented!()
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn request_nonce(&self) -> Result<Option<Nonce>> {
        let resp = match self.client.request_nonce() {
            Some(req) => req.request_async(&self.http_closure()).await.map_err(|e| {
                HolderServiceSnafu {
                    details: format!("Could not fetch a nonce: {e}"),
                }
                .build()
            })?,

            None => {
                debug!("Issuer does not support a nonce endpoint");

                return Ok(None);
            }
        };

        Ok(Some(Nonce::from_secret(resp.c_nonce().secret().to_owned())))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_cred_def(&self, cred_def_id: &str) -> Result<CredDefMetadata> {
        let configs = self.issuer_metadata.credential_configurations_supported();
        debug!(supported_credential_configs = ?configs);

        let data = configs
            .iter()
            .find(|config| config.id() == &CredentialConfigurationId::new(cred_def_id.to_owned()))
            .ok_or_else(|| {
                ProtocolSnafu::new(
                    ErrorType::UnsupportedCredentialType,
                    format!("Unsupported credential definition ID: {cred_def_id}"),
                )
                .build()
            })?;

        debug!(resolved_credential_metadata = ?data);

        Ok(data.to_owned())
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn resolve_proof(
        &self,
        keys_metadata: &[KeyMetadata],
        offer: &CredentialOffer,
        nonce: Option<Nonce>,
    ) -> Result<Option<oid4vci::credential::Proof>> {
        let mut proofs: Vec<SpruceProof> = vec![];
        for key_metadata in keys_metadata {
            let req = self
                .holder
                .request_credential(offer, nonce.clone(), key_metadata)
                .await
                .context(VCSnafu)?;

            proofs.push(req.proof.try_into()?);
        }

        let proof = match proofs.as_slice() {
            [] => None,
            [proof] => Some(oid4vci::credential::Proof::One(proof.clone())),
            _ => Some(self.resolve_proofs_for_batch_issuance(proofs)?),
        };

        Ok(proof)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_proofs_for_batch_issuance(
        &self,
        proofs: Vec<SpruceProof>,
    ) -> Result<oid4vci::credential::Proof> {
        match self.issuer_metadata.batch_credential_issuance() {
            None => {
                ProtocolSnafu::new(
                    ErrorType::InvalidCredentialRequest,
                    "Batch credential issuance is not supported by the issuer. Please provide a single key metadata".to_string(),
                ).fail()?
            }
            Some(&BatchCredentialIssuance { batch_size }) if (batch_size as usize) < proofs.len() => {
                ProtocolSnafu::new(
                    ErrorType::InvalidCredentialRequest,
                    format!("Batch credential issuance limit exceeded. Please provide keys metadata size less or equal to {batch_size}"),
                ).fail()?
            }
            _ => {
                let jwt_proofs: Vec<_> = proofs
                    .into_iter()
                    .filter_map(|proof| match proof {
                        Proof::Jwt { jwt } => Some(jwt),
                        Proof::LdpVp { .. } => ProtocolSnafu::new(
                            ErrorType::InvalidProof,
                            "Unsupported proof type: ldp_vp".to_string(),
                        )
                            .fail()
                            .ok(),
                    })
                    .collect();

                Ok(oid4vci::credential::Proof::Many(
                    oid4vci::credential::ProofMany::Jwt(jwt_proofs),
                ))
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn http_closure(
        &self,
    ) -> impl Fn(HttpRequest) -> Pin<Box<dyn Future<Output = crate::http::Result<HttpResponse>> + Send>>
    {
        let client = self.http_client.clone();
        move |req| {
            let client = client.clone();
            Box::pin(async move { client.async_call(req).await })
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn http_closure(
        &self,
    ) -> impl Fn(HttpRequest) -> Pin<Box<dyn Future<Output = crate::http::Result<HttpResponse>>>>
    {
        let client = self.http_client.clone();
        move |req| {
            let client = client.clone();
            Box::pin(async move { client.async_call(req).await })
        }
    }
}

impl TryInto<CredentialResult> for &CredentialResponse {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<CredentialResult, Self::Error> {
        let result = match self.response_kind() {
            ResponseEnum::Immediate { credentials } => {
                let mut creds: Vec<Credential> = vec![];
                for cred in credentials {
                    creds.push(cred.try_into()?)
                }

                CredentialResult::Credential {
                    credentials: creds,
                    notification_id: self.notification_id().map(|v| v.to_owned()),
                }
            }
            ResponseEnum::Deferred { transaction_id } => CredentialResult::Deferred {
                transaction_id: transaction_id.clone().ok_or(
                    TypeConversionSnafu {
                        details: "Deferred credential response must contain transaction ID"
                            .to_string(),
                    }
                    .build(),
                )?,
            },
        };

        Ok(result)
    }
}

impl TryInto<Credential> for &CoreProfilesCredentialResponseType {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<Credential, Self::Error> {
        let credential = match self {
            CoreProfilesCredentialResponseType::VcSdJwt { credential } => {
                Credential::SdJwt(credential.to_owned())
            }
            CoreProfilesCredentialResponseType::LdpVc { credential } => Credential::LdpVc(
                serde_json::from_value(credential.to_owned()).context(ParseSnafu)?,
            ),
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!("Unsupported credential format: {}", self.format()),
            )
            .fail()?,
        };
        Ok(credential)
    }
}

impl TryInto<SpruceProof> for AsdkProof {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<SpruceProof, Self::Error> {
        let proof = match self.format.as_str() {
            "jwt" => SpruceProof::Jwt {
                jwt: self.proof.to_owned(),
            },
            _ => ProtocolSnafu::new(
                ErrorType::InvalidProof,
                format!("Unsupported proof type: {}", self.format),
            )
            .fail()?,
        };

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::{mock_http_once, mock_http_req_predicate};
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vault::{MockVault, Vault};
    use crate::vc::VCFormat;
    use crate::vc::oid4vci::tests::fixtures::{
        ACCESS_TOKEN, AUTH_URL, CRED_DEF_ID, ISSUER_URL, NOTIFICATION_ID, REQ_URI_CODE, SCOPE,
        SD_JWT_CREDS, SampleIssuerMetadata, fake_access_token, sample_access_token,
        sample_authorization_metadata, sample_batch_cred_response, sample_cred_response,
        sample_credential_definition, sample_offer_with_auth_code_grant,
        sample_offer_with_pre_auth_code_grant,
    };
    use crate::vc::oid4vci::{CredentialRequest, CredentialResult, Holder};
    use oauth2::http::{Method, StatusCode};
    use rstest::rstest;
    use serde_json::json;
    use std::io;

    #[tokio::test]
    async fn authorization_code_flow_with_scope_works_correctly() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::POST,
            par_request_endpoint(),
            json!({
               "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + REQ_URI_CODE,
               "expires_in": 86400,
            }),
            StatusCode::CREATED,
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            access_token_endpoint(),
            sample_access_token_response(),
            StatusCode::OK,
        );

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let token_response = holder_service
            .authz_code_flow_with_scope(SCOPE.into(), |url| {
                assert!(url.to_string().starts_with(AUTH_URL));
                assert!(url.query().unwrap().contains(REQ_URI_CODE));

                async { Ok::<String, io::Error>("fake_auth_code".to_string()) }
            })
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(&token_response).unwrap(),
            sample_access_token_response()
        );
    }

    #[rstest]
    #[case::offer_with_auth_code_grant_success(
        sample_offer_with_auth_code_grant(None),
        "auth_code",
        json!(sample_authorization_metadata()),
        "grant_type=authorization_code&code=auth_code"
    )]
    #[case::offer_with_pre_auth_code_grant_success(
        sample_offer_with_pre_auth_code_grant("pre_auth_code"),
        "pre_auth_code",
        json!(sample_authorization_metadata()),
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=pre_auth_code&tx_code=pre_auth_code&client_id=fake_client_id"
    )]
    #[should_panic(expected = "Unsupported credential definition IDs: invalid_scope")]
    #[case::fals_when_offer_with_auth_code_grant_contains_invalid_scope(
        sample_offer_with_auth_code_grant(Some("invalid_scope")),
        "auth_code",
        json!(sample_authorization_metadata()),
        "grant_type=authorization_code&code=auth_code"
    )]
    #[should_panic(expected = "Discovery error")]
    #[case::fails_when_offer_with_pre_auth_code_grant_refers_to_invalid_auth_srv_metadata(sample_offer_with_pre_auth_code_grant("pre_auth_code"),
        "pre_auth_code",
        json!(SampleIssuerMetadata::with_sdjwtvc_conf()),
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=pre_auth_code&tx_code=pre_auth_code&client_id=fake_client_id"
    )]
    #[tokio::test]
    async fn get_access_token(
        #[case] offer: CredentialOfferParams,
        #[case] code: &str,
        #[case] auth_srv_metadata: serde_json::Value,
        #[case] token_req_body: &str,
    ) {
        let mut http_client = MockHttpClient::new();

        if code == "auth_code" {
            mock_http_once(
                &mut http_client,
                Method::POST,
                par_request_endpoint(),
                json!({
                   "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + REQ_URI_CODE,
                   "expires_in": 86400,
                }),
                StatusCode::CREATED,
            );
        } else {
            mock_http_once(
                &mut http_client,
                Method::GET,
                auth_srv_metadata_request_endpoint(),
                auth_srv_metadata,
                StatusCode::OK,
            );
        }

        let token_req_body = token_req_body.to_owned();
        mock_http_req_predicate(
            &mut http_client,
            Method::POST,
            access_token_endpoint(),
            move |req_body| {
                assert!(req_body.contains(&token_req_body));
                true
            },
            sample_access_token_response(),
            StatusCode::OK,
            1.into(),
        );

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let token_response = holder_service
            .get_access_token(&offer, |authz_flow: AuthzFlow| {
                match authz_flow {
                    AuthzFlow::Preauthorized => {}
                    AuthzFlow::Authorize(url) => {
                        assert!(url.to_string().starts_with(AUTH_URL));
                        assert!(url.query().unwrap().contains(REQ_URI_CODE));
                    }
                }
                async { Ok::<String, io::Error>(code.to_string()) }
            })
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(&token_response).unwrap(),
            sample_access_token_response()
        );
    }

    #[tokio::test]
    async fn holder_requests_nonce_correctly() {
        let mut http_client = MockHttpClient::new();
        let nonce = "nOnCe";

        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({
               "c_nonce": nonce,
            }),
            StatusCode::CREATED,
        );

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let nonce_to_check = holder_service.request_nonce().await.unwrap().unwrap();

        assert_eq!(nonce_to_check.secret(), nonce)
    }

    #[tokio::test]
    async fn holder_resolves_credential_definition_pop_lifetime_correctly() {
        let http_client = MockHttpClient::new();

        let kms = LocalKms::new();
        let vault = InMemVault::new();
        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            vault,
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let cred_def_to_check = holder_service.resolve_cred_def(CRED_DEF_ID).unwrap();
        assert_eq!(cred_def_to_check, sample_credential_definition());
    }

    #[tokio::test]
    async fn holder_requests_credentials_correctly() {
        let mut http_client = MockHttpClient::new();

        // validate that CredentialRequest is formed correctly and sent to an Issuer
        mock_http_req_predicate(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            |req_body| {
                serde_json::from_str::<CredentialRequest>(&req_body)
                    .expect("invalid credential request");
                true
            },
            sample_cred_response(),
            StatusCode::OK,
            1.into(),
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({
               "c_nonce": "nOnCe",
            }),
            StatusCode::CREATED,
        );

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let _ = holder
            .request_credential(&sample_access_token(), CRED_DEF_ID, &[key_metadata])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn holder_receives_issued_credential_correctly() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            sample_cred_response(),
            StatusCode::OK,
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({
               "c_nonce": "nOnCe",
            }),
            StatusCode::CREATED,
        );

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let response = holder
            .request_credential(&sample_access_token(), CRED_DEF_ID, &[key_metadata])
            .await
            .unwrap();

        let CredentialResult::Credential {
            credentials,
            notification_id: Some(notification_id),
        } = response.data
        else {
            panic!("did not receive credential");
        };

        assert_eq!(credentials.len(), 1);

        match &credentials[0] {
            Credential::SdJwt(cred) => {
                assert_eq!(cred, SD_JWT_CREDS);
                assert_eq!(notification_id, NOTIFICATION_ID);
            }
            _ => {
                panic!("did not receive sd-jwt credential");
            }
        }
    }

    #[tokio::test]
    async fn holder_requests_multiple_credentials_correctly() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            sample_batch_cred_response(),
            StatusCode::OK,
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({
               "c_nonce": "nOnCe",
            }),
            StatusCode::CREATED,
        );

        let kms = LocalKms::new();
        let (_, key_metadata_1) = create_did_and_key_metadata(&kms).await;
        let (_, key_metadata_2) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let response = holder
            .request_credential(
                &sample_access_token(),
                CRED_DEF_ID,
                &[key_metadata_1, key_metadata_2],
            )
            .await
            .unwrap();

        let CredentialResult::Credential {
            credentials,
            notification_id: Some(notification_id),
        } = response.data
        else {
            panic!("did not receive credential");
        };

        assert_eq!(credentials.len(), 2);

        for credential in credentials {
            match &credential {
                Credential::SdJwt(cred) => {
                    assert_eq!(cred, SD_JWT_CREDS);
                    assert_eq!(notification_id, NOTIFICATION_ID);
                }
                _ => {
                    panic!("did not receive sd-jwt credential");
                }
            }
        }
    }

    #[tokio::test]
    async fn holder_stores_credentials_correctly() {
        let mut vault = MockVault::new();
        vault
            .expect_store_credential()
            .times(1)
            .returning(|arg0, arg2| Ok(String::from("fake_cred_id")));

        let kms = LocalKms::new();

        let holder_service = holder_service_from_issuer_metadata(
            MockHttpClient::new(),
            vault,
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;
        let credential = Credential::SdJwt("fake_sdjwt".to_string());

        let cred_metadata = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            fields: vec![],
        };

        let result = holder_service
            .store_credential(&credential, &cred_metadata)
            .await;

        result.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported credential definition ID")]
    async fn holder_fails_processing_incorrect_cred_def_id() {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder_service = holder_service_from_issuer_metadata(
            MockHttpClient::new(),
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let result = holder_service
            .request_credential(
                &sample_access_token(),
                "unexpected_cred_def_id",
                &[key_metadata],
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Batch credential issuance is not supported by the issuer")]
    async fn holder_fails_requesting_credentials_when_issuer_does_not_support_batch_issuance() {
        let mut issuer_metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        issuer_metadata = issuer_metadata.set_batch_credential_issuance(None);

        let mut http_client = MockHttpClient::new();
        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({
               "c_nonce": "nOnCe",
            }),
            StatusCode::CREATED,
        );

        let kms = LocalKms::new();
        let (_, key_metadata_1) = create_did_and_key_metadata(&kms).await;
        let (_, key_metadata_2) = create_did_and_key_metadata(&kms).await;

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            issuer_metadata,
        )
        .await;

        let result = holder_service
            .request_credential(
                &sample_access_token(),
                CRED_DEF_ID,
                &[key_metadata_1, key_metadata_2],
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Batch credential issuance limit exceeded")]
    async fn holder_fails_requesting_credentials_when_batch_issuance_size_exceeded() {
        let mut issuer_metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        issuer_metadata = issuer_metadata
            .set_batch_credential_issuance(Some(BatchCredentialIssuance { batch_size: 2 }));

        let mut http_client = MockHttpClient::new();
        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({
               "c_nonce": "nOnCe",
            }),
            StatusCode::CREATED,
        );

        let kms = LocalKms::new();
        let (_, key_metadata_1) = create_did_and_key_metadata(&kms).await;
        let (_, key_metadata_2) = create_did_and_key_metadata(&kms).await;
        let (_, key_metadata_3) = create_did_and_key_metadata(&kms).await;

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            issuer_metadata,
        )
        .await;

        let result = holder_service
            .request_credential(
                &sample_access_token(),
                CRED_DEF_ID,
                &[key_metadata_1, key_metadata_2, key_metadata_3],
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Could not fetch a nonce: Server returned invalid response")]
    async fn holder_fails_when_nonce_endpoint_returns_error() {
        let mut http_client = MockHttpClient::new();

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            json!({}),
            StatusCode::OK,
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({}),
            StatusCode::INTERNAL_SERVER_ERROR,
        );

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let result = holder_service
            .request_credential(&sample_access_token(), CRED_DEF_ID, &[key_metadata])
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Could not parse the access token")]
    async fn holder_shows_informative_error_display_on_wrong_access_token() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            json!({
               "error": ErrorType::InvalidToken,
               "error_description": "Could not parse the access token",
            }),
            StatusCode::BAD_REQUEST,
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            nonce_endpoint(),
            json!({
               "c_nonce": "nOnCe",
            }),
            StatusCode::CREATED,
        );

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let response = holder
            .request_credential(&fake_access_token(), CRED_DEF_ID, &[key_metadata])
            .await
            .unwrap();
    }

    async fn holder_service_from_issuer_metadata(
        http_client: impl HttpClient + 'static,
        vault: impl Vault,
        kms: LocalKms,
        issuer_metadata: IssuerMetadata,
    ) -> HolderService<impl vc::core::Holder, impl HttpClient> {
        let http_client = Arc::new(http_client);
        let client_id = "fake_client_id";
        let holder_metadata = vc::core::HolderMetadata {
            client_id: client_id.to_owned(),
            pop_lifetime: time::Duration::minutes(5),
        };

        let inner = vc::core::HolderService::new(
            kms,
            vault,
            holder_metadata,
            UniversalResolver::default(),
            http_client.clone(),
        );

        HolderService::from_metadata(
            inner,
            http_client,
            issuer_metadata,
            sample_authorization_metadata(),
            client_id.to_owned(),
            "urn:ietf:wg:oauth:2.0:oob".to_string(),
        )
        .unwrap()
    }

    fn sample_access_token_response() -> serde_json::Value {
        json!({
            "access_token": ACCESS_TOKEN,
            "token_type": "bearer",
            "expires_in": 86400,
        })
    }

    fn par_request_endpoint() -> Url {
        Url::parse(AUTH_URL).unwrap().join("/par/request").unwrap()
    }
    fn access_token_endpoint() -> Url {
        Url::parse(AUTH_URL).unwrap().join("/token").unwrap()
    }
    fn credential_endpoint() -> Url {
        Url::parse(ISSUER_URL).unwrap().join("/credential").unwrap()
    }
    fn nonce_endpoint() -> Url {
        Url::parse(ISSUER_URL).unwrap().join("/nonce").unwrap()
    }
    fn auth_srv_metadata_request_endpoint() -> Url {
        Url::parse(AUTH_URL)
            .unwrap()
            .join("/.well-known/openid-configuration")
            .unwrap()
    }
}
