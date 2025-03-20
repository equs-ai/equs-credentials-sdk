use crate::http::HttpClient;
use crate::nonce::{Nonce, NonceData};
use crate::utils::wasm::WasmNotSend;
use crate::vc;
use crate::vc::core::{CredentialOfferContent, KeyMetadata, Proof as AsdkProof};
use crate::vc::oid4vci::internal_error::{
    AuthorizationCallbackSnafu, DiscoverySnafu, HolderServiceSnafu, IssuerServiceSnafu,
    MetadataSnafu, ParseSnafu, TypeConversionSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::protocol_error::ProtocolSnafu;
use crate::vc::oid4vci::AuthzFlow::Authorize;
use crate::vc::oid4vci::{
    metadata, AuthorizationMetadata, AuthzFlow, CredDefMetadata, CredentialOfferParams,
    CredentialResponse, CredentialResponseResolved, CredentialResult, IssuerMetadata,
    PreAuthorizedCode, TxCode,
};
use crate::vc::{oid4vci as api, HasVCFormat};
use crate::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthorizationCode, ClientId, CsrfToken, HttpRequest, HttpResponse,
    PkceCodeChallenge, RedirectUrl, ResponseType, Scope,
};
use oid4vci::core::authorization::AuthorizationDetailsObject;
use oid4vci::core::client::Client;
use oid4vci::core::profiles::{
    ldp_vc, vc_sd_jwt, CoreProfilesCredentialConfiguration, CoreProfilesCredentialRequest,
    CoreProfilesCredentialResponseType, CredentialRequestWithFormat,
};
use oid4vci::credential::{ErrorType, ResponseEnum};
use oid4vci::metadata::MetadataDiscovery;
use oid4vci::proof_of_possession::Proof as SpruceProof;
use oid4vci::token;
use oid4vci::types::{CredentialConfigurationId, IssuerUrl};
use snafu::{ensure, ResultExt};
use std::future::Future;
use std::pin::Pin;
use std::string::ToString;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info, instrument, trace, Level};

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
        http_client: HC,
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
        http_client: HC,
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
        http_client: HC,
        issuer_url: String,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        let http_client = Arc::new(http_client);

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
        http_client: HC,
        issuer_metadata: IssuerMetadata,
        authz_metadata: AuthorizationMetadata,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        let holder_service = Self::new(
            holder,
            Arc::new(http_client),
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
        nonce: Option<&NonceData>,
        key_metadata: &KeyMetadata,
    ) -> Result<CredentialResponseResolved> {
        info!("requesting a credential flow is started");

        let cred_def = self.resolve_cred_def(cred_def_id)?;

        let req_with_format = match &cred_def.profile_specific_fields() {
            CoreProfilesCredentialConfiguration::VcSdJwt(det) => {
                CredentialRequestWithFormat::VcSdJwt(vc_sd_jwt::CredentialRequestWithFormat::new(
                    det.vct().to_owned(),
                    Default::default(),
                ))
            }
            CoreProfilesCredentialConfiguration::LdpVc(det) => {
                CredentialRequestWithFormat::LdpVc(ldp_vc::CredentialRequestWithFormat::new(
                    ldp_vc::authorization_detail::CredentialDefinition::default()
                        .set_context(det.credential_definition().context().to_owned())
                        .set_type(det.credential_definition().r#type().to_owned()),
                ))
            }
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!(
                    "Unsupported credential format: {}",
                    cred_def.profile_specific_fields().format()
                ),
            )
            .fail()?,
        };

        let req_base = CoreProfilesCredentialRequest::WithFormat {
            inner: req_with_format,
            _credential_identifier: (),
        };
        trace!(request_profile = ?req_base);

        let supported_proofs = metadata::supported_proofs(&cred_def).context(MetadataSnafu)?;
        let offer = &vc::core::CredentialOffer {
            cred_offer_id: None,
            issuer_id: self.issuer_metadata.credential_issuer().to_string(),
            cred_def_id: cred_def_id.to_owned(),
            content: CredentialOfferContent::SupportedProofs(supported_proofs),
            protocol_data: None,
        };
        trace!(credential_offer = ?offer);

        let nonce = match nonce {
            Some(val) => val,
            None => &self.request_nonce(token.clone(), req_base.clone()).await?,
        };
        trace!(resolved_nonce = ?nonce);

        let req = self
            .holder
            .request_credential(offer, &nonce.value, key_metadata)
            .await
            .context(VCSnafu)?;
        trace!(resolved_request = ?req);

        let credential_request = self
            .client
            .request_credential(token.to_owned(), req_base)
            .set_proof(Some(req.proof.try_into()?));

        let resp = credential_request
            .request_async(&self.http_closure())
            .await?;

        let cred_result: CredentialResult = (&resp).try_into()?;

        if let CredentialResult::Credential { credential, .. } = &cred_result {
            info!("credential is received");

            self.holder
                .verify_credential(credential)
                .await
                .context(VCSnafu)?;

            info!("credential is verified");
        }

        info!("requesting a credential flow is succeeded");

        Ok(CredentialResponseResolved {
            data: cred_result,
            nonce_data: Self::extract_nonce(&resp),
        })
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
    async fn request_nonce(
        &self,
        token: AccessToken,
        cred_req: CoreProfilesCredentialRequest,
    ) -> Result<NonceData> {
        // TODO: Returning nonce should be optional
        let resp = self
            .client
            .request_credential(token, cred_req)
            .request_async(&self.http_closure())
            .await
            .map_err(|e| e.into());

        trace!(nonce_response = ?resp);

        match resp {
            Ok(_) => IssuerServiceSnafu {
                details: "Issuer does not provide a nonce",
            }
            .fail()?,

            Err(Error::Protocol { source }) => {
                let nonce = source.nonce().ok_or(
                    HolderServiceSnafu {
                        details: "Providing PoP without nonce is unsupported",
                    }
                    .build(),
                )?;

                Ok(NonceData {
                    value: nonce.to_owned(),
                    expires_in: source.nonce_expiration().map(|e| e.to_owned()),
                    created: OffsetDateTime::now_utc(),
                })
            }

            Err(error) => Err(error)?,
        }
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

    #[instrument(level = Level::TRACE, ret())]
    fn extract_nonce(resp: &oid4vci::core::credential::Response) -> Option<NonceData> {
        resp.c_nonce().map(|nonce| NonceData {
            value: Nonce::from_secret(nonce.secret().to_owned()),
            expires_in: resp
                .c_nonce_expires_in()
                .map(|e| Duration::seconds(e.to_owned())),
            created: time::OffsetDateTime::now_utc(),
        })
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
            ResponseEnum::Immediate { credential } => CredentialResult::Credential {
                credential: credential.try_into()?,
                notification_id: self.notification_id().map(|v| v.to_owned()),
            },
            ResponseEnum::Deferred { transaction_id } => CredentialResult::Deferred {
                transaction_id: transaction_id.clone().ok_or(
                    TypeConversionSnafu {
                        details: "Deferred credential response must contain transaction ID"
                            .to_string(),
                    }
                    .build(),
                )?,
            },
            ResponseEnum::ImmediateMany { .. } => ProtocolSnafu::new(
                ErrorType::InvalidCredentialRequest,
                "'ImmediateMany' credential response type is not supported".to_string(),
            )
            .fail()?,
        };

        Ok(result)
    }
}

impl TryInto<Credential> for &CoreProfilesCredentialResponseType {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<Credential, Self::Error> {
        let credential = match self {
            CoreProfilesCredentialResponseType::VcSdJwt(sd_jwt) => {
                Credential::SdJwt(sd_jwt.to_owned())
            }
            CoreProfilesCredentialResponseType::LdpVc(ldp_vc) => {
                Credential::LdpVc(serde_json::from_value(ldp_vc.to_owned()).context(ParseSnafu)?)
            }
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
            "cwt" => SpruceProof::Cwt {
                cwt: self.proof.to_owned(),
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
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::{mock_http_once, mock_http_req_predicate};
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vault::{MockVault, Vault};
    use crate::vc::oid4vci::tests::fixtures::{
        fake_access_token, sample_access_token, sample_authorization_metadata,
        sample_cred_response, sample_credential_definition, sample_nonce,
        sample_offer_with_auth_code_grant, sample_offer_with_pre_auth_code_grant,
        SampleIssuerMetadata, ACCESS_TOKEN, AUTH_URL, CRED_DEF_ID, ISSUER_URL, NOTIFICATION_ID,
        REQ_URI_CODE, SCOPE, SD_JWT_CREDS,
    };
    use crate::vc::oid4vci::{CredentialRequest, CredentialResult, Holder};
    use crate::vc::VCFormat;
    use oauth2::http::{Method, StatusCode};
    use oid4vci::core::profiles::CoreProfilesCredentialRequest;
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
            credential_endpoint(),
            json!({
               "error": "invalid_proof",
               "error_description": "Provide PoP",
               "c_nonce": nonce,
               "c_nonce_expires_in": 8600,
            }),
            StatusCode::BAD_REQUEST,
        );

        let token = AccessToken::new(ACCESS_TOKEN.to_owned());
        let cred_req = CoreProfilesCredentialRequest::WithFormat {
            _credential_identifier: (),
            inner: CredentialRequestWithFormat::VcSdJwt(
                vc_sd_jwt::CredentialRequestWithFormat::new(
                    CRED_DEF_ID.to_owned(),
                    Default::default(),
                ),
            ),
        };

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let nonce_to_check = holder_service.request_nonce(token, cred_req).await.unwrap();

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
            .request_credential(
                &sample_access_token(),
                CRED_DEF_ID,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await;
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
            .request_credential(
                &sample_access_token(),
                CRED_DEF_ID,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();

        assert!(matches!(
            response.data,
            CredentialResult::Credential {
                credential: Credential::SdJwt(jwt),
                notification_id: Some(notification_id)
            } if jwt == SD_JWT_CREDS && notification_id == NOTIFICATION_ID
        ));
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
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case(SampleIssuerMetadata::with_jwtvc_conf())]
    #[case(SampleIssuerMetadata::with_jwtldvc_conf())]
    #[case(SampleIssuerMetadata::with_isomdl_conf())]
    #[tokio::test]
    #[should_panic(expected = "Unsupported credential format")]
    async fn holder_fails_on_unsupported_credential_formats(#[case] test_metadata: IssuerMetadata) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder_service = holder_service_from_issuer_metadata(
            MockHttpClient::new(),
            InMemVault::new(),
            kms,
            test_metadata,
        )
        .await;

        let result = holder_service
            .request_credential(
                &sample_access_token(),
                SCOPE,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Issuer does not provide a nonce")]
    async fn holder_fails_with_no_nonce_provided() {
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

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let result = holder_service
            .request_credential(&sample_access_token(), CRED_DEF_ID, None, &key_metadata)
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
               "c_nonce": "n0nce",
               "c_nonce_expires_in": 8600,
            }),
            StatusCode::BAD_REQUEST,
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
            .request_credential(
                &fake_access_token(),
                CRED_DEF_ID,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();
    }

    async fn holder_service_from_issuer_metadata(
        http_client: impl HttpClient + 'static,
        vault: impl Vault,
        kms: LocalKms,
        issuer_metadata: IssuerMetadata,
    ) -> HolderService<impl vc::core::Holder, impl HttpClient> {
        let client_id = "fake_client_id";
        let holder_metadata = vc::core::HolderMetadata {
            client_id: client_id.to_owned(),
            pop_lifetime: time::Duration::minutes(5),
        };

        let inner = vc::core::HolderService::new(kms, vault, holder_metadata);

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
    fn auth_srv_metadata_request_endpoint() -> Url {
        Url::parse(AUTH_URL)
            .unwrap()
            .join("/.well-known/openid-configuration")
            .unwrap()
    }
}
