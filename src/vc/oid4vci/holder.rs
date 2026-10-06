use crate::did::DIDURLBuf;
use crate::did::didweb::DIDWeb;
use crate::http::HttpClient;
use crate::nonce::Nonce;
use crate::utils::wasm::WasmNotSend;
use crate::vc;
use crate::vc::core::{
    CredentialOffer, CredentialOfferContent, InvalidDIDUrlSnafu, KeyMetadata, Proof as EqusSdkProof,
};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::oid4vci::AuthzFlow::Authorize;
use crate::vc::oid4vci::credential_issuer_identifier::CredentialIssuerIdentifier;
use crate::vc::oid4vci::internal_error::{
    AuthorizationCallbackSnafu, AuthorizationRequestSnafu, HolderServiceSnafu, MetadataSnafu,
    ParseSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::metadata::MetadataDiscovery;
use crate::vc::oid4vci::protocol_error::{CredentialEndpointError, ProtocolSnafu};
use crate::vc::oid4vci::{
    AuthorizationMetadata, AuthzFlow, CredDefMetadata, CredentialExtraVerification,
    CredentialOfferParams, CredentialResponse, CredentialResponseResolved, CredentialResult,
    IssuerMetadata, PreAuthorizedCode, TxCode, metadata,
};
use crate::vc::{Credential, CredentialMetadata};
use crate::vc::{HasVCFormat, oid4vci as api};
use async_trait::async_trait;
use futures::future;
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthorizationCode, ClientId, CsrfToken, HttpRequest, HttpResponse,
    PkceCodeChallenge, RedirectUrl, ResponseType, Scope,
};
use oid4vci::core::authorization::AuthorizationDetailsObject;
use oid4vci::core::client::Client;
use oid4vci::core::profiles::CoreProfilesCredentialResponseType;
use oid4vci::credential::{CredentialId, Proofs, RequestBuilder, ResponseEnum};
use oid4vci::metadata::authorization_server::GrantType;
use oid4vci::metadata::credential_issuer::BatchCredentialIssuance;
use oid4vci::proof_of_possession::{Proof as SpruceProof, Proof};
use oid4vci::token;
use oid4vci::types::{CredentialConfigurationId, IssuerState, IssuerUrl};
use snafu::{ResultExt, ensure};
use std::future::Future;
use std::pin::Pin;
use std::string::ToString;
use std::sync::Arc;
use tracing::{Level, debug, info, instrument, trace, warn};

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
    pre_authorized_server: Option<IssuerUrl>,
    credential_extra_verification: Vec<CredentialExtraVerification>,
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
        credential_extra_verification: Option<Vec<CredentialExtraVerification>>,
    ) -> Result<Self> {
        info!("oid4vci-holder service initialization is started");

        let holder_service = Self::from_iss_url_with_configs(
            holder,
            http_client,
            issuer_url,
            AuthServerHint::AuthorizationCode(None),
            client_id,
            redirect_url,
            credential_extra_verification,
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
        credential_extra_verification: Option<Vec<CredentialExtraVerification>>,
    ) -> Result<Self> {
        info!("oid4vci-holder service initialization is started");

        let iss_url = offer.credential_issuer().to_owned();

        // The client is bound to one authorization server at construction. A pre-authorized grant
        // resolves the server it names on every token request, so only an offer without one lets
        // the authorization code grant pick the server to discover (OID4VCI 1.0 §4.1.1)
        let hint = match offer.grants() {
            Some(grants) if grants.pre_authorized_code.is_some() => AuthServerHint::PreAuthorized,
            grants => AuthServerHint::AuthorizationCode(
                grants
                    .and_then(|grants| grants.authorization_code.as_ref())
                    .and_then(|grant| grant.authorization_server()),
            ),
        };

        let holder_service = Self::from_iss_url_with_configs(
            holder,
            http_client,
            iss_url.to_string(),
            hint,
            client_id,
            redirect_url,
            credential_extra_verification,
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
        hint: AuthServerHint<'_>,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
        credential_extra_verification: Option<Vec<CredentialExtraVerification>>,
    ) -> Result<Self> {
        let issuer_metadata: IssuerMetadata =
            MetadataDiscovery::discover_metadata(http_client.as_ref(), &issuer_url).await?;
        debug!(resolved_issuer_metadata = ?issuer_metadata);

        let mut pre_authorized_server = None;
        let authz_metadata: AuthorizationMetadata =
            match select_authorization_server(&issuer_metadata, hint) {
                AuthServerChoice::Issuer => {
                    MetadataDiscovery::discover_metadata(http_client.as_ref(), &issuer_url).await?
                }
                AuthServerChoice::Server(server) => {
                    MetadataDiscovery::discover_metadata(http_client.as_ref(), server).await?
                }
                AuthServerChoice::FirstSupportingAuthorizationCode(servers) => {
                    let metadata =
                        discover_first_supporting_authorization_code(http_client.as_ref(), servers)
                            .await?;
                    // A pre-authorized grant naming no server still goes where it went before
                    // selection by capability: the first advertised server
                    pre_authorized_server = servers
                        .first()
                        .filter(|first| *first != metadata.issuer())
                        .cloned();
                    metadata
                }
            };
        debug!(resolved_authorization_server_metadata = ?authz_metadata);

        let mut holder_service = Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            client_id,
            redirect_url,
            credential_extra_verification,
        )?;
        holder_service.pre_authorized_server = pre_authorized_server;

        Ok(holder_service)
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    pub fn from_metadata(
        holder: HL,
        http_client: Arc<HC>,
        issuer_metadata: IssuerMetadata,
        authz_metadata: AuthorizationMetadata,
        client_id: String,
        redirect_url: String,
        credential_extra_verification: Option<Vec<CredentialExtraVerification>>,
    ) -> Result<Self> {
        let holder_service = Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            client_id,
            redirect_url,
            credential_extra_verification,
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
        credential_extra_verification: Option<Vec<CredentialExtraVerification>>,
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
            pre_authorized_server: None,
            credential_extra_verification: credential_extra_verification.unwrap_or_default(),
        })
    }

    fn pre_authorized_token_server<'a>(
        &'a self,
        named: Option<&'a IssuerUrl>,
    ) -> Option<&'a IssuerUrl> {
        if named.is_some() {
            return named;
        }
        if let Some(server) = &self.pre_authorized_server {
            debug!(
                authorization_server = %server.as_str(),
                "exchanging the pre-authorized code at the issuer's first advertised server"
            );
        }
        self.pre_authorized_server.as_ref()
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

        if let Some(issuer_url) = self.pre_authorized_token_server(issuer_url) {
            let auth_serv_metadata: AuthorizationMetadata =
                MetadataDiscovery::discover_metadata(self.http_client.as_ref(), issuer_url).await?;

            req = req.set_token_url(auth_serv_metadata.token_endpoint().clone())
        }
        let token = req
            .request_async(&self.http_closure())
            .await
            .map_err(Error::from)?;

        Ok(token)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_credential_issuer_identifier(&self, credential: &Credential) -> Result<()> {
        let credential_issuer = match credential {
            Credential::SdJwt(credential) => SdJwtAPI::extract_issuer_identifier(credential),
            Credential::LdpVc(credential) => JsonLdAPI::extract_issuer_identifier(credential),
            format => Err(vc::formats::FormatNotSupportedSnafu {
                format: format.format().to_string(),
            }
            .build()),
        }
        .context(vc::core::VCSnafu)
        .context(VCSnafu)?;

        let credential_issuer = if let Some(credential_issuer) = credential_issuer {
            credential_issuer
        } else {
            Err(vc::core::VCNotValidSnafu {
                details: "Credential does not contain issuer identifier".to_owned(),
            }
            .build())
            .context(VCSnafu)?
        };
        match credential_issuer {
            CredentialIssuerIdentifier::OID4VCI(url) => {
                self.verify_credential_issuer_url_matches_identifier(&url)
            }
            CredentialIssuerIdentifier::DID(did_url) => {
                self.verify_credential_issuer_did_matches_identifier(&did_url)
            }
            CredentialIssuerIdentifier::Other(id) => {
                self.verify_credential_issuer_other_matches_identifier(&id)
            }
        }
    }

    fn verify_credential_issuer_url_matches_identifier(
        &self,
        credential_issuer_url: &IssuerUrl,
    ) -> Result<()> {
        let credential_issuer_identifier = self.issuer_metadata.credential_issuer();
        if credential_issuer_identifier.eq(credential_issuer_url) {
            Ok(())
        } else {
            Err(vc::core::VCNotValidSnafu {
                details: format!(
                    "Credential issuer url {} does not match Credential Issuer Identifier {}",
                    credential_issuer_url.url(),
                    credential_issuer_identifier.url()
                )
                .to_owned(),
            }
            .build())
            .context(VCSnafu)?
        }
    }

    fn verify_credential_issuer_did_matches_identifier(
        &self,
        credential_issuer_did: &DIDURLBuf,
    ) -> Result<()> {
        let credential_issuer_identifier = self.issuer_metadata.credential_issuer();

        let metadata_did = DIDWeb::generate_did_from_url(credential_issuer_identifier.as_str())
            .map_err(|e| // Practically unreachable
                InvalidDIDUrlSnafu {
                    input: credential_issuer_identifier.to_string(),
                }
                    .build())
            .context(VCSnafu)?;

        if credential_issuer_did.did().to_string().eq(&metadata_did) {
            Ok(())
        } else {
            Err(vc::core::VCNotValidSnafu {
                details: format!(
                    "Credential issuer did {} does not match Credential Issuer Identifier {}",
                    credential_issuer_did, metadata_did,
                )
                .to_owned(),
            }
            .build())
            .context(VCSnafu)?
        }
    }

    fn verify_credential_issuer_other_matches_identifier(
        &self,
        credential_issuer: &String,
    ) -> Result<()> {
        if self
            .issuer_metadata
            .credential_issuer()
            .to_string()
            .eq(credential_issuer)
        {
            Ok(())
        } else {
            Err(vc::core::VCNotValidSnafu {
                details: format!(
                    "Credential contains issuer identifier {}, \
                        which association with OID4VCI Credential Issuer Identifier {} can not be verified",
                    credential_issuer,
                    self.issuer_metadata.credential_issuer().url()
                )
                    .to_owned(),
            }
                .build()).context(VCSnafu)?
        }
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
                None,
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
        let grants = offer_params.grants().ok_or_else(|| {
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
                .credential_configuration_ids()
                .iter()
                .find_map(|cc| {
                    self.resolve_cred_def(cc)
                        .map(|c| c.scope().map(|s| s.to_string()))
                        .unwrap_or(None)
                })
                .ok_or_else(|| {
                    AuthorizationRequestSnafu {
                        details: format!(
                            "Could not resolve \"scope\" value: Unknown credential identifier(s): {}",
                            offer_params
                                .credential_configuration_ids()
                                .iter()
                                .map(|c| c.to_string())
                                .collect::<Vec<String>>()
                                .join(", ")
                        )
                    }
                        .build()
                })?;

            return self
                .authz_code_flow(
                    AuthzOption::Scope(scope),
                    authorization.issuer_state(),
                    |url| authorization_callback(Authorize(url)),
                )
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

        let proofs = self.resolve_proofs(keys_metadata, offer, nonce).await?;

        let credential_request = self
            .client
            .request_credential(
                token.to_owned(),
                CredentialId::CredentialConfigurationId(cred_def.id().to_owned()),
            )
            .set_proofs(proofs);

        let result = self.request_credential_inner(credential_request).await;

        info!("requesting a credential flow is succeeded");

        result
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn request_deferred_credential(
        &self,
        token: &AccessToken,
        transaction_id: &str,
    ) -> api::Result<CredentialResponseResolved> {
        info!("requesting a deferred credential");

        let request = self
            .client
            .request_deferred_credential(token.to_owned(), transaction_id.to_string())
            .map_err(|e| {
                HolderServiceSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        let result = self.request_credential_inner(request).await;

        info!("requested deferred credential");

        result
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_credential_extra(&self, credential: &Credential) -> Result<()> {
        for option in &self.credential_extra_verification {
            match option {
                CredentialExtraVerification::CredentialIssuerIdentifier => {
                    self.verify_credential_issuer_identifier(credential).await?
                }
            }
        }
        Ok(())
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

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn send_notification(
        &self,
        token: &AccessToken,
        notification: api::Notification,
    ) -> api::Result<()> {
        info!("sending notification");

        let request = self
            .client
            .send_notification(token.to_owned(), notification)
            .map_err(|e| {
                HolderServiceSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        request
            .request_async(&self.http_closure())
            .await
            .map_err(Error::from)?;

        info!("sent notification");

        Ok(())
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
        issuer_state: Option<&IssuerState>,
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
                AuthorizationRequestSnafu {
                    details: format!("Could not create a pushed authorization request: {e}"),
                }
                .build()
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
        let push_request = match issuer_state {
            Some(issuer_state) => {
                debug!("passing the offer's issuer_state to the authorization request");
                push_request.set_issuer_state(issuer_state)
            }
            None => push_request,
        };
        info!("holder is sending auth request");

        let (auth_url, out_csrf) = push_request.async_request(&self.http_closure()).await?;

        ensure!(
            in_csrf.secret() == out_csrf.secret(),
            AuthorizationRequestSnafu {
                details: "CSRF failure".to_string()
            },
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
            .map_err(Error::from)?;

        info!("authorization is succeeded");

        Ok(token)
    }

    async fn request_credential_inner<T: serde::Serialize>(
        &self,
        credential_request: RequestBuilder<T>,
    ) -> Result<CredentialResponseResolved> {
        let resp = credential_request
            .request_async(&self.http_closure())
            .await
            .map_err(Error::from)?;

        let cred_result: CredentialResult = (&resp).try_into()?;

        if let CredentialResult::Credential { credentials, .. } = &cred_result {
            info!("credential(s) is received");

            future::try_join_all(credentials.iter().map(|credential| async {
                self.holder
                    .verify_credential(credential)
                    .await
                    .context(VCSnafu)
            }))
            .await?;
            info!("credential(s) is verified");
        }

        Ok(CredentialResponseResolved { data: cred_result })
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
                ProtocolSnafu::credential_endpoint(
                    CredentialEndpointError::UnknownCredentialIdentifier,
                    format!("Unknown credential identifier: {cred_def_id}"),
                )
                .build()
            })?;

        debug!(resolved_credential_metadata = ?data);

        Ok(data.to_owned())
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn resolve_proofs(
        &self,
        keys_metadata: &[KeyMetadata],
        offer: &CredentialOffer,
        nonce: Option<Nonce>,
    ) -> Result<Option<Proofs>> {
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
            [Proof::Jwt { jwt: proof_value }] => Some(Proofs::Jwt(vec![proof_value.clone()])),
            [Proof::DiVp { di_vp: proof_value }] => Some(Proofs::DiVp(vec![proof_value.clone()])),
            _ => Some(self.resolve_proofs_for_batch_issuance(proofs)?),
        };

        Ok(proof)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_proofs_for_batch_issuance(&self, proofs: Vec<SpruceProof>) -> Result<Proofs> {
        match self.issuer_metadata.batch_credential_issuance() {
            None => {
                ProtocolSnafu::credential_endpoint(
                    CredentialEndpointError::InvalidCredentialRequest,
                    "Batch credential issuance is not supported by the issuer. Please provide a single key metadata".to_string(),
                ).fail()?
            }
            Some(&BatchCredentialIssuance { batch_size }) if (batch_size as usize) < proofs.len() => {
                ProtocolSnafu::credential_endpoint(
                    CredentialEndpointError::InvalidCredentialRequest,
                    format!("Batch credential issuance limit exceeded. Please provide keys metadata size less or equal to {batch_size}"),
                ).fail()?
            }
            _ => {
                let jwt_proofs: Vec<_> = proofs
                    .into_iter()
                    .filter_map(|proof| match proof {
                        Proof::Jwt { jwt } => Some(jwt),
                        Proof::DiVp { .. } => ProtocolSnafu::credential_endpoint(
                            CredentialEndpointError::InvalidProof,
                            "Unsupported proof type: di_vp".to_string(),
                        )
                            .fail()
                            .ok(),
                    })
                    .collect();

                Ok(Proofs::Jwt(jwt_proofs))
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
            ResponseEnum::Deferred {
                transaction_id,
                interval,
            } => CredentialResult::Deferred {
                transaction_id: transaction_id.to_owned(),
                interval: interval.to_owned(),
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
            _ => ProtocolSnafu::credential_endpoint(
                CredentialEndpointError::UnknownCredentialConfiguration,
                format!("Unknown credential configuration: {}", self.format()),
            )
            .fail()?,
        };
        Ok(credential)
    }
}

impl TryInto<SpruceProof> for EqusSdkProof {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<SpruceProof, Self::Error> {
        let proof = match self.format.as_str() {
            "jwt" => SpruceProof::Jwt {
                jwt: self.proof.to_owned(),
            },
            _ => ProtocolSnafu::credential_endpoint(
                CredentialEndpointError::InvalidProof,
                format!("Unsupported proof type: {}", self.format),
            )
            .fail()?,
        };

        Ok(proof)
    }
}

/// What the holder knows, at construction, about the grant it will use.
#[derive(Debug, Clone, Copy)]
enum AuthServerHint<'o> {
    /// The offer carries a pre-authorized grant, which resolves its own server per token request.
    PreAuthorized,
    /// The holder will run the authorization code grant; the server the offer names, if any.
    AuthorizationCode(Option<&'o IssuerUrl>),
}

/// Where the holder takes its authorization server metadata from.
#[derive(Debug, PartialEq)]
enum AuthServerChoice<'a> {
    Issuer,
    Server(&'a IssuerUrl),
    /// The first of these advertised servers whose metadata supports the authorization code flow.
    FirstSupportingAuthorizationCode(&'a [IssuerUrl]),
}

fn select_authorization_server<'a>(
    issuer_metadata: &'a IssuerMetadata,
    hint: AuthServerHint<'_>,
) -> AuthServerChoice<'a> {
    let offered = match hint {
        AuthServerHint::AuthorizationCode(offered) => offered,
        AuthServerHint::PreAuthorized => None,
    };

    let servers = match issuer_metadata.authorization_servers() {
        Some(servers) if !servers.is_empty() => servers.as_slice(),
        _ => {
            if let Some(offered) = offered {
                warn!(
                    authorization_server = %offered.as_str(),
                    "ignoring the offered authorization server: the issuer metadata lists none"
                );
            }
            return AuthServerChoice::Issuer;
        }
    };

    if servers.len() == 1 || matches!(hint, AuthServerHint::PreAuthorized) {
        if let Some(offered) = offered.filter(|offered| *offered != &servers[0]) {
            warn!(
                authorization_server = %offered.as_str(),
                "ignoring the offered authorization server: the issuer metadata lists a single other one"
            );
        }
        return AuthServerChoice::Server(&servers[0]);
    }

    let Some(offered) = offered else {
        return AuthServerChoice::FirstSupportingAuthorizationCode(servers);
    };

    // The returned URL always comes from the issuer metadata, never from the offer
    if let Some(server) = servers.iter().find(|server| *server == offered) {
        debug!(
            authorization_server = %server.as_str(),
            "using the authorization server named by the offer"
        );
        return AuthServerChoice::Server(server);
    }

    warn!(
        authorization_server = %offered.as_str(),
        advertised = ?servers,
        "ignoring the offered authorization server: the issuer metadata does not list it"
    );
    AuthServerChoice::FirstSupportingAuthorizationCode(servers)
}

fn supports_authorization_code(metadata: &AuthorizationMetadata) -> bool {
    metadata
        .grant_types_supported()
        .0
        .contains(&GrantType::AuthorizationCode)
        && metadata.authorization_endpoint().is_some()
        && metadata.pushed_authorization_request_endpoint().is_some()
}

/// Discovers the advertised servers in order and returns the first that supports the authorization
/// code flow. A server whose metadata cannot be fetched is skipped. When none supports it, the first
/// discovered server is used.
async fn discover_first_supporting_authorization_code<HC: HttpClient>(
    http_client: &HC,
    servers: &[IssuerUrl],
) -> Result<AuthorizationMetadata> {
    let mut first_discovered: Option<AuthorizationMetadata> = None;
    let mut last_error: Option<Error> = None;

    for server in servers {
        let metadata = match MetadataDiscovery::discover_metadata::<_, AuthorizationMetadata>(
            http_client,
            server,
        )
        .await
        {
            Ok(metadata) => metadata,
            Err(e) => {
                warn!(
                    authorization_server = %server.as_str(),
                    error = ?e,
                    "could not discover the authorization server metadata, trying the next one"
                );
                last_error = Some(e.into());
                continue;
            }
        };

        if supports_authorization_code(&metadata) {
            debug!(
                authorization_server = %server.as_str(),
                "using the first advertised authorization server supporting the authorization code flow"
            );
            return Ok(metadata);
        }

        debug!(
            authorization_server = %server.as_str(),
            "skipping an authorization server that cannot serve the authorization code flow"
        );
        first_discovered.get_or_insert(metadata);
    }

    if let Some(metadata) = first_discovered {
        warn!(
            advertised = ?servers,
            "no advertised authorization server supports the authorization code flow, using the first discovered one"
        );
        return Ok(metadata);
    }

    // Selection only asks for this with at least two servers, so every one of them failed
    Err(last_error.unwrap_or_else(|| {
        HolderServiceSnafu {
            details: "the issuer advertises no authorization server",
        }
        .build()
        .into()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::{mock_http, mock_http_once, mock_http_req_predicate};
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vault::{MockVault, Vault};
    use crate::vc::VCFormat;
    use crate::vc::core::ProofOfPossessionMetadata;
    use crate::vc::formats::json_ld_vc::VC;
    use crate::vc::oid4vci::protocol_error::TokenEndpointError;
    use crate::vc::oid4vci::tests::fixtures::{
        AUTH_URL, CRED_DEF_ID, ISSUER_URL, NOTIFICATION_ID, REQ_URI_CODE, SCOPE,
        SampleIssuerMetadata, access_token, fake_access_token, sample_access_token,
        sample_authorization_metadata, sample_batch_cred_response, sample_cred_response,
        sample_credential_definition, sample_offer_with_auth_code_grant,
        sample_offer_with_pre_auth_code_grant, sd_jwt_creds,
    };
    use crate::vc::oid4vci::{
        CredentialRequest, CredentialResult, Holder, Notification, protocol_error,
    };
    use oauth2::http::{Method, StatusCode};
    use oid4vci::core::profiles::CoreProfilesCredentialResponse;
    use oid4vci::credential::Response;
    use oid4vci::notification::NotificationRequestEvent;
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

    #[tokio::test]
    async fn authorization_code_flow_uses_the_authorization_server_named_by_the_offer() {
        let mut http_client = MockHttpClient::new();
        mock_discovery(&mut http_client, SECOND_AUTH_URL);
        mock_http_once(
            &mut http_client,
            Method::POST,
            Url::parse(&format!("{SECOND_AUTH_URL}/par/request")).unwrap(),
            json!({
               "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + REQ_URI_CODE,
               "expires_in": 86400,
            }),
            StatusCode::CREATED,
        );
        mock_http_once(
            &mut http_client,
            Method::POST,
            Url::parse(&format!("{SECOND_AUTH_URL}/token")).unwrap(),
            sample_access_token_response(),
            StatusCode::OK,
        );

        let holder_service = holder_service_from_offer(
            http_client,
            offer_with_grants(Some(auth_code_grant_naming(Some(SECOND_AUTH_URL))), None),
        )
        .await;

        let token_response = holder_service
            .authz_code_flow_with_scope(SCOPE.into(), |url| {
                assert!(url.to_string().starts_with(SECOND_AUTH_URL));
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
    #[case::offer_names_a_server_the_issuer_does_not_list(offer_with_grants(
        Some(auth_code_grant_naming(Some("https://attacker-authz.com"))),
        None
    ))]
    #[case::offer_names_no_server(offer_with_grants(Some(auth_code_grant_naming(None)), None))]
    #[tokio::test]
    async fn offer_naming_no_usable_server_stops_at_the_first_server_supporting_the_flow(
        #[case] offer: CredentialOfferParams,
    ) {
        let mut http_client = MockHttpClient::new();
        // Only the first advertised server is mocked, and it supports the authorization code flow:
        // discovering any other one fails the test
        mock_discovery(&mut http_client, AUTH_URL);

        holder_service_from_offer(http_client, offer).await;
    }

    #[tokio::test]
    async fn offer_with_a_pre_authorized_grant_keeps_the_first_advertised_authorization_server() {
        let mut http_client = MockHttpClient::new();
        // Only the first advertised server is mocked: discovering any other one fails the test
        mock_discovery(&mut http_client, AUTH_URL);

        let offer = offer_with_grants(
            Some(auth_code_grant_naming(Some(SECOND_AUTH_URL))),
            Some(api::PreAuthorizedCodeGrant::new(PreAuthorizedCode::new(
                "pre_auth_code".to_string(),
            ))),
        );

        holder_service_from_offer(http_client, offer).await;
    }

    #[rstest]
    #[case::offered_among_several(json!([AUTH_URL, SECOND_AUTH_URL]), Some(SECOND_AUTH_URL), SECOND_AUTH_URL)]
    #[case::offered_is_the_first_of_several(json!([AUTH_URL, SECOND_AUTH_URL]), Some(AUTH_URL), AUTH_URL)]
    #[case::offered_is_the_only_one(json!([SECOND_AUTH_URL]), Some(SECOND_AUTH_URL), SECOND_AUTH_URL)]
    #[case::offered_differs_from_the_only_one(json!([AUTH_URL]), Some(SECOND_AUTH_URL), AUTH_URL)]
    #[case::none_offered_and_only_one_listed(json!([SECOND_AUTH_URL]), None, SECOND_AUTH_URL)]
    #[case::offered_is_not_listed(json!([AUTH_URL, SECOND_AUTH_URL]), Some("https://attacker-authz.com"), BY_CAPABILITY)]
    #[case::offered_differs_by_a_trailing_slash(json!([AUTH_URL, SECOND_AUTH_URL]), Some("https://second-authz-backend.com/"), BY_CAPABILITY)]
    #[case::none_offered(json!([AUTH_URL, SECOND_AUTH_URL]), None, BY_CAPABILITY)]
    #[case::metadata_lists_none(serde_json::Value::Null, Some(SECOND_AUTH_URL), ISSUER_ITSELF)]
    #[case::metadata_lists_an_empty_array(json!([]), Some(SECOND_AUTH_URL), ISSUER_ITSELF)]
    fn selects_the_authorization_server_to_discover(
        #[case] advertised: serde_json::Value,
        #[case] offered: Option<&str>,
        #[case] expected: &str,
    ) {
        let mut metadata = serde_json::to_value(SampleIssuerMetadata::with_sdjwtvc_conf()).unwrap();
        if advertised.is_null() {
            metadata
                .as_object_mut()
                .unwrap()
                .remove("authorization_servers");
        } else {
            metadata["authorization_servers"] = advertised;
        }
        let metadata: IssuerMetadata = serde_json::from_value(metadata).unwrap();
        let offered = offered.map(|url| IssuerUrl::new(url.to_string()).unwrap());

        let selected = select_authorization_server(
            &metadata,
            AuthServerHint::AuthorizationCode(offered.as_ref()),
        );

        assert_eq!(describe(&selected), expected);
    }

    #[test]
    fn pre_authorized_grant_selects_the_first_advertised_server() {
        let metadata: IssuerMetadata =
            serde_json::from_value(issuer_metadata_with_two_auth_servers()).unwrap();

        let selected = select_authorization_server(&metadata, AuthServerHint::PreAuthorized);

        assert_eq!(describe(&selected), AUTH_URL);
    }

    #[rstest]
    #[case::wallet_initiated_skips_a_server_without_an_authorization_endpoint(
        None,
        Some(pre_authorized_only_metadata_of(AUTH_URL)),
        Some(authorization_metadata_of(SECOND_AUTH_URL)),
        SECOND_AUTH_URL
    )]
    #[case::wallet_initiated_skips_a_server_without_a_par_endpoint(
        None,
        Some(metadata_without_par_of(AUTH_URL)),
        Some(authorization_metadata_of(SECOND_AUTH_URL)),
        SECOND_AUTH_URL
    )]
    #[case::wallet_initiated_skips_a_server_not_supporting_the_grant(
        None,
        Some(metadata_without_the_grant_of(AUTH_URL)),
        Some(authorization_metadata_of(SECOND_AUTH_URL)),
        SECOND_AUTH_URL
    )]
    #[case::wallet_initiated_skips_a_server_whose_metadata_cannot_be_fetched(
        None,
        None,
        Some(authorization_metadata_of(SECOND_AUTH_URL)),
        SECOND_AUTH_URL
    )]
    #[case::wallet_initiated_keeps_the_first_server_supporting_the_flow(
        None,
        Some(authorization_metadata_of(AUTH_URL)),
        None,
        AUTH_URL
    )]
    #[case::offer_naming_no_server_skips_a_pre_authorized_only_server(
        Some(offer_with_grants(Some(auth_code_grant_naming(None)), None)),
        Some(pre_authorized_only_metadata_of(AUTH_URL)),
        Some(authorization_metadata_of(SECOND_AUTH_URL)),
        SECOND_AUTH_URL
    )]
    #[case::offer_naming_an_unlisted_server_skips_a_pre_authorized_only_server(
        Some(offer_with_grants(
            Some(auth_code_grant_naming(Some("https://attacker-authz.com"))),
            None
        )),
        Some(pre_authorized_only_metadata_of(AUTH_URL)),
        Some(authorization_metadata_of(SECOND_AUTH_URL)),
        SECOND_AUTH_URL
    )]
    #[tokio::test]
    async fn authorization_code_flow_uses_the_first_advertised_server_supporting_it(
        #[case] offer: Option<CredentialOfferParams>,
        #[case] first: Option<serde_json::Value>,
        #[case] second: Option<serde_json::Value>,
        #[case] expected: &'static str,
    ) {
        let mut http_client = MockHttpClient::new();
        mock_discovery_of_two_servers(&mut http_client, first, second);
        mock_authorization_at(&mut http_client, expected);

        let holder_service = holder_service_from(http_client, offer).await;

        holder_service
            .authz_code_flow_with_scope(SCOPE.into(), |url| {
                assert!(
                    url.to_string().starts_with(expected),
                    "authorized at {url}, expected {expected}"
                );
                async { Ok::<String, io::Error>("fake_auth_code".to_string()) }
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn wallet_initiated_issuance_falls_back_to_the_first_server_when_none_supports_the_flow()
    {
        let mut http_client = MockHttpClient::new();
        // Both servers are discovered, neither can serve the flow: the first one is kept and the
        // pushed authorization request then fails on it rather than on a server chosen at random
        mock_discovery_of_two_servers(
            &mut http_client,
            Some(pre_authorized_only_metadata_of(AUTH_URL)),
            Some(pre_authorized_only_metadata_of(SECOND_AUTH_URL)),
        );

        let holder_service = holder_service_from(http_client, None).await;

        let error = holder_service
            .authz_code_flow_with_scope(SCOPE.into(), |_| async {
                Ok::<String, io::Error>("fake_auth_code".to_string())
            })
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Could not create a pushed authorization request"),
            "unexpected error: {error}"
        );
    }

    #[rstest]
    #[case::grant_carries_issuer_state(
        Some("issuer-context-123"),
        "issuer_state=issuer-context-123"
    )]
    #[case::grant_carries_a_base64_issuer_state(Some("eyJ0+a/b="), "issuer_state=eyJ0%2Ba%2Fb%3D")]
    #[case::grant_carries_no_issuer_state(None, "")]
    #[tokio::test]
    async fn authorization_request_sends_the_issuer_state_of_the_offer(
        #[case] issuer_state: Option<&'static str>,
        #[case] expected_param: &'static str,
    ) {
        let mut http_client = MockHttpClient::new();
        mock_http_req_predicate(
            &mut http_client,
            Method::POST,
            par_request_endpoint(),
            move |req_body| {
                match issuer_state {
                    Some(_) => assert!(
                        req_body.contains(expected_param),
                        "PAR body without the offer's issuer_state: {req_body}"
                    ),
                    None => assert!(
                        !req_body.contains("issuer_state"),
                        "PAR body with an issuer_state the offer did not carry: {req_body}"
                    ),
                }
                true
            },
            json!({
               "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + REQ_URI_CODE,
               "expires_in": 86400,
            }),
            StatusCode::CREATED,
            1.into(),
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
        let offer = offer_with_grants(
            Some(api::AuthorizationCodeGrant::new(
                issuer_state.map(|state| IssuerState::new(state.to_string())),
                None,
            )),
            None,
        );

        holder_service
            .get_access_token(&offer, |_: AuthzFlow| async {
                Ok::<String, io::Error>("auth_code".to_string())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn holder_built_from_the_issuer_url_exchanges_a_pre_authorized_code_at_the_first_server()
    {
        let mut http_client = MockHttpClient::new();
        mock_http_once(
            &mut http_client,
            Method::GET,
            well_known(ISSUER_URL, "openid-credential-issuer"),
            issuer_metadata_with_two_auth_servers(),
            StatusCode::OK,
        );
        // Discovered once by capability selection, which skips it, and once for the exchange
        mock_http(
            &mut http_client,
            Method::GET,
            well_known(AUTH_URL, "oauth-authorization-server"),
            pre_authorized_only_metadata_of(AUTH_URL),
            StatusCode::OK,
            2.into(),
        );
        mock_http_once(
            &mut http_client,
            Method::GET,
            well_known(SECOND_AUTH_URL, "oauth-authorization-server"),
            authorization_metadata_of(SECOND_AUTH_URL),
            StatusCode::OK,
        );
        // Only the first server's token endpoint is mocked: exchanging at the second fails the test
        mock_http_req_predicate(
            &mut http_client,
            Method::POST,
            access_token_endpoint(),
            |req_body| req_body.contains("pre-authorized_code=pre_auth_code"),
            sample_access_token_response(),
            StatusCode::OK,
            1.into(),
        );

        let holder_service = holder_service_from(http_client, None).await;
        let offer = offer_with_grants(
            None,
            Some(api::PreAuthorizedCodeGrant::new(PreAuthorizedCode::new(
                "pre_auth_code".to_string(),
            ))),
        );

        holder_service
            .get_access_token(&offer, |_: AuthzFlow| async {
                Ok::<String, io::Error>("tx_code".to_string())
            })
            .await
            .unwrap();
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
    #[should_panic(
        expected = "Could not resolve \"scope\" value: Unknown credential identifier(s): invalid_scope"
    )]
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

    #[rstest]
    #[case::invalid_request(TokenEndpointError::InvalidRequest, "Invalid request")]
    #[case::invalid_client(TokenEndpointError::InvalidClient, "Invalid client")]
    #[case::invalid_grant(TokenEndpointError::InvalidGrant, "Invalid grant")]
    #[case::unauthorized_client(TokenEndpointError::UnauthorizedClient, "Unauthorized client")]
    #[case::unsupported_grant_type(
        TokenEndpointError::UnsupportedGrantType,
        "Unsupported grant type"
    )]
    #[case::invalid_scope(TokenEndpointError::InvalidScope, "Invalid scope")]
    #[tokio::test]
    async fn holder_get_access_token_returns_protocol_errors_when_auth_server_returns_errors(
        #[case] error_type: TokenEndpointError,
        #[case] error_description: &str,
    ) {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::GET,
            auth_srv_metadata_request_endpoint(),
            sample_authorization_metadata(),
            StatusCode::OK,
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            access_token_endpoint(),
            json!({
               "error": error_type,
               "error_description": error_description,
            }),
            StatusCode::BAD_REQUEST,
        );

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let offer = sample_offer_with_pre_auth_code_grant("pre_auth_code");
        let result = holder_service
            .get_access_token(&offer, |_| async {
                Ok::<String, io::Error>("pre_auth_code".to_string())
            })
            .await;

        assert!(result.is_err());

        let Error::Protocol { source: err } = result.unwrap_err() else {
            panic!("Expected Protocol");
        };

        assert_eq!(
            err.error_type().to_owned(),
            protocol_error::ErrorType::TokenEndpoint(error_type)
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
                assert_eq!(cred, &sd_jwt_creds());
                assert_eq!(notification_id, NOTIFICATION_ID);
            }
            _ => {
                panic!("did not receive sd-jwt credential");
            }
        }
    }

    #[rstest]
    #[case::positive_deferred(
        SampleIssuerMetadata::with_sdjwtvc_conf(),
        json![
        {
            "transaction_id": "8xLOxBtZp8".to_string(),
            "interval": 300,
        }],
    )]
    #[case::positive_credential(
        SampleIssuerMetadata::with_sdjwtvc_conf(),
        json![
        {
            "credentials": [{"credential": sd_jwt_creds()}],
            "notification_id": Some("notification_id".to_string()),
        }],
    )]
    #[should_panic(expected = "Deferred credential issuance is not supported by this issuer")]
    #[case::deferred_issance_not_supported_by_issuer(
        SampleIssuerMetadata::with_sdjwtvc_no_deferred_endpoint_conf(),
        json![
        {
            "transaction_id": "8xLOxBtZp8".to_string(),
            "interval": 300,
        }],
    )]
    #[tokio::test]
    async fn holder_handles_deferred_credential_flow(
        #[case] issuer_metadata: IssuerMetadata,
        #[case] expected_response: serde_json::Value,
    ) {
        let oid4vci_response =
            serde_json::from_value::<Response<CoreProfilesCredentialResponse>>(expected_response)
                .unwrap();
        let expected_response: CredentialResult = (&oid4vci_response).try_into().unwrap();
        let mut http_client = MockHttpClient::new();
        mock_http_once(
            &mut http_client,
            Method::POST,
            deferred_credential_endpoint(),
            oid4vci_response,
            StatusCode::OK,
        );
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            issuer_metadata,
        )
        .await;

        let response = holder
            .request_deferred_credential(&sample_access_token(), "transaction_id")
            .await
            .unwrap()
            .data;

        match expected_response {
            CredentialResult::Deferred {
                transaction_id: expected_transaction_id,
                interval: expected_interval,
            } => match response {
                CredentialResult::Deferred {
                    transaction_id: actual_transaction_id,
                    interval: actual_interval,
                } => {
                    assert_eq!(expected_transaction_id, actual_transaction_id);
                    assert_eq!(expected_interval, actual_interval);
                }
                actual => {
                    panic!(
                        "actual response is not a deferred credential response: {:?}",
                        actual
                    );
                }
            },
            CredentialResult::Credential {
                credentials: expected_credentials,
                notification_id: expected_notification_id,
            } => match response {
                CredentialResult::Credential {
                    credentials: actual_credentials,
                    notification_id: actual_notification_id,
                } => {
                    assert_eq!(expected_credentials.len(), actual_credentials.len());
                    assert_eq!(expected_notification_id, actual_notification_id);
                }
                actual => {
                    panic!("actual response is not a credential response: {:?}", actual);
                }
            },
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
                    assert_eq!(cred, &sd_jwt_creds());
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
    #[should_panic(expected = "Unknown credential identifier")]
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
               "error": CredentialEndpointError::InvalidToken,
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

    //noinspection HttpUrlsUsage
    #[rstest]
    #[case::ldpvc(ISSUER_URL, Credential::LdpVc(ldp_vc_credential()))]
    #[case::sdjwt_iss_oid4vci(ISSUER_URL, sd_jwt_credential(json!({ "iss": "https://issuer-backend.com", "id": "1234", "_sd_alg": "SHA-256" })))]
    #[case::sdjwt_iss_did(ISSUER_URL, sd_jwt_credential(json!({ "iss": "did:web:issuer-backend.com/ignored-path", "id": "1234", "_sd_alg": "SHA-256" })))]
    #[should_panic(
        expected = "Credential contains issuer identifier notadid:web:issuer-backend.com"
    )]
    #[case::sdjwt_iss_other_invalid(
        ISSUER_URL,
        sd_jwt_credential(json!({ "iss": "notadid:web:issuer-backend.com", "id": "1234", "_sd_alg": "SHA-256" }))
    )]
    #[case::sdjwt_iss_other_valid(
        "http://issuer-backend.com",
        sd_jwt_credential(json!({ "iss": "http://issuer-backend.com", "id": "1234" }))
    )]
    #[should_panic(expected = "Credential does not contain issuer identifier")]
    #[case::sdjwt_iss_none(ISSUER_URL, sd_jwt_credential(json!({ "id": "1234", "_sd_alg": "SHA-256" })))]
    #[should_panic(expected = "Unsupported format: jwt_vc_json")]
    #[case::unsupported_format_jwt_vc_json(ISSUER_URL, Credential::JwtVcJson("MOCK_CREDENTIAL".to_owned()
    ))]
    #[should_panic(expected = "Unsupported format: jwt_vc_json-ld")]
    #[case::unsupported_format_jwt_vc_json_ld(
        ISSUER_URL,
        Credential::JwtVcJsonLd("MOCK_CREDENTIAL".to_owned())
    )]
    #[tokio::test]
    async fn verify_credential_issuer_identifier(
        #[case] credential_issuer_identifier: &str,
        #[case] credential: Credential,
    ) {
        let mut issuer_metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        issuer_metadata = issuer_metadata.set_credential_issuer(
            IssuerUrl::new(credential_issuer_identifier.to_string()).unwrap(),
        );

        let holder_service = holder_service_from_issuer_metadata(
            MockHttpClient::new(),
            InMemVault::new(),
            LocalKms::new(),
            issuer_metadata,
        )
        .await;
        holder_service
            .verify_credential_issuer_identifier(&credential)
            .await
            .unwrap();
    }

    #[rstest]
    #[case::positive(SampleIssuerMetadata::with_sdjwtvc_conf())]
    #[should_panic(expected = "Notification are not supported by this issuer")]
    #[case::notifications_unsupported(
        SampleIssuerMetadata::with_sdjwtvc_no_notification_endpoint_conf()
    )]
    #[tokio::test]
    async fn send_notification(#[case] issuer_metadata: IssuerMetadata) {
        let mut http_client = MockHttpClient::new();
        mock_http_once(
            &mut http_client,
            Method::POST,
            notification_endpoint(),
            (),
            StatusCode::OK,
        );
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            issuer_metadata,
        )
        .await;

        let notification = Notification::new(
            "notification_id".to_string(),
            NotificationRequestEvent::CredentialAccepted,
            Some("Issued credential has been accepted".to_string()),
        );

        holder
            .send_notification(&sample_access_token(), notification)
            .await
            .unwrap()
    }

    /// `sd+jwt` credential over `claims` without disclosures, signed by the fixture issuer key.
    fn sd_jwt_credential(claims: serde_json::Value) -> Credential {
        Credential::SdJwt(test_fixtures::sd_jwt(
            &json!({ "typ": "sd+jwt", "alg": "ES256" }),
            &claims,
            &[],
            &test_fixtures::keys().issuer,
        ))
    }

    fn ldp_vc_credential() -> VC {
        serde_json::from_str(
            r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "https://issuer-backend.com",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                }
            }
        }"#,
        )
        .unwrap()
    }

    const SECOND_AUTH_URL: &str = "https://second-authz-backend.com";

    /// What `select_authorization_server` returned, in a form a test case can spell out
    const BY_CAPABILITY: &str = "first supporting the authorization code flow";
    const ISSUER_ITSELF: &str = "the issuer itself";

    fn describe(choice: &AuthServerChoice<'_>) -> String {
        match choice {
            AuthServerChoice::Issuer => ISSUER_ITSELF.to_string(),
            AuthServerChoice::Server(server) => server.as_str().to_string(),
            AuthServerChoice::FirstSupportingAuthorizationCode(_) => BY_CAPABILITY.to_string(),
        }
    }

    fn pre_authorized_only_metadata_of(auth_url: &str) -> serde_json::Value {
        // Shaped like an issuer's own pre-authorized code server: no `grant_types_supported`, so
        // RFC 8414 defaults it to `authorization_code`, but no authorization endpoint either
        json!({ "issuer": auth_url, "token_endpoint": format!("{auth_url}/token") })
    }

    fn metadata_without_par_of(auth_url: &str) -> serde_json::Value {
        let mut metadata = authorization_metadata_of(auth_url);
        metadata
            .as_object_mut()
            .unwrap()
            .remove("pushed_authorization_request_endpoint");
        metadata
    }

    fn metadata_without_the_grant_of(auth_url: &str) -> serde_json::Value {
        let mut metadata = authorization_metadata_of(auth_url);
        metadata["grant_types_supported"] =
            json!(["urn:ietf:params:oauth:grant-type:pre-authorized_code"]);
        metadata
    }

    /// Mocks discovery of the issuer and of its two advertised servers.
    fn mock_discovery_of_two_servers(
        http_client: &mut MockHttpClient,
        first: Option<serde_json::Value>,
        second: Option<serde_json::Value>,
    ) {
        mock_http_once(
            http_client,
            Method::GET,
            well_known(ISSUER_URL, "openid-credential-issuer"),
            issuer_metadata_with_two_auth_servers(),
            StatusCode::OK,
        );
        match first {
            Some(metadata) => mock_http_once(
                http_client,
                Method::GET,
                well_known(AUTH_URL, "oauth-authorization-server"),
                metadata,
                StatusCode::OK,
            ),
            None => mock_http_once(
                http_client,
                Method::GET,
                well_known(AUTH_URL, "oauth-authorization-server"),
                json!({}),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        }
        if let Some(metadata) = second {
            mock_http_once(
                http_client,
                Method::GET,
                well_known(SECOND_AUTH_URL, "oauth-authorization-server"),
                metadata,
                StatusCode::OK,
            );
        }
    }

    fn mock_authorization_at(http_client: &mut MockHttpClient, server: &str) {
        mock_http_once(
            http_client,
            Method::POST,
            Url::parse(&format!("{server}/par/request")).unwrap(),
            json!({
               "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + REQ_URI_CODE,
               "expires_in": 86400,
            }),
            StatusCode::CREATED,
        );
        mock_http_once(
            http_client,
            Method::POST,
            Url::parse(&format!("{server}/token")).unwrap(),
            sample_access_token_response(),
            StatusCode::OK,
        );
    }

    /// Issuer metadata advertising two authorization servers, the first of which an
    /// authorization code offer does not name (e.g. an internal pre-authorized code server)
    fn issuer_metadata_with_two_auth_servers() -> serde_json::Value {
        let mut metadata = serde_json::to_value(SampleIssuerMetadata::with_sdjwtvc_conf()).unwrap();
        metadata["authorization_servers"] = json!([AUTH_URL, SECOND_AUTH_URL]);
        metadata
    }

    fn authorization_metadata_of(auth_url: &str) -> serde_json::Value {
        let metadata = serde_json::to_string(&sample_authorization_metadata()).unwrap();
        serde_json::from_str(&metadata.replace(AUTH_URL, auth_url)).unwrap()
    }

    fn well_known(server: &str, suffix: &str) -> Url {
        Url::parse(&format!("{server}/.well-known/{suffix}")).unwrap()
    }

    fn auth_code_grant_naming(auth_url: Option<&str>) -> api::AuthorizationCodeGrant {
        api::AuthorizationCodeGrant::new(None, None)
            .set_authorization_server(auth_url.map(|url| IssuerUrl::new(url.to_string()).unwrap()))
    }

    fn offer_with_grants(
        authorization_code: Option<api::AuthorizationCodeGrant>,
        pre_authorized_code: Option<api::PreAuthorizedCodeGrant>,
    ) -> CredentialOfferParams {
        CredentialOfferParams::new(
            IssuerUrl::new(ISSUER_URL.to_string()).unwrap(),
            vec![CredentialConfigurationId::new(CRED_DEF_ID.to_string())],
            Some(api::CredentialOfferGrants::new(
                authorization_code,
                pre_authorized_code,
            )),
            Default::default(),
        )
    }

    async fn holder_service_from_offer(
        http_client: impl HttpClient + 'static,
        offer: CredentialOfferParams,
    ) -> HolderService<impl vc::core::Holder, impl HttpClient> {
        holder_service_from(http_client, Some(offer)).await
    }

    async fn holder_service_from(
        http_client: impl HttpClient + 'static,
        offer: Option<CredentialOfferParams>,
    ) -> HolderService<impl vc::core::Holder, impl HttpClient> {
        let http_client = Arc::new(http_client);
        let client_id = "fake_client_id";
        let inner = vc::core::HolderService::new(
            LocalKms::new(),
            InMemVault::new(),
            vc::core::HolderMetadata {
                client_id: client_id.to_owned(),
                pop: ProofOfPossessionMetadata {
                    lifetime: time::Duration::minutes(5),
                    not_before: None,
                },
            },
            UniversalResolver::default(),
            http_client.clone(),
        );

        let redirect_url = "urn:ietf:wg:oauth:2.0:oob".to_string();
        match offer {
            Some(offer) => {
                HolderService::from_credential_offer(
                    inner,
                    http_client,
                    &offer,
                    client_id.to_owned(),
                    redirect_url,
                    None,
                )
                .await
            }
            None => {
                HolderService::from_iss_url(
                    inner,
                    http_client,
                    ISSUER_URL.to_string(),
                    client_id.to_owned(),
                    redirect_url,
                    None,
                )
                .await
            }
        }
        .unwrap()
    }

    fn mock_discovery(http_client: &mut MockHttpClient, auth_url: &str) {
        mock_http_once(
            http_client,
            Method::GET,
            well_known(ISSUER_URL, "openid-credential-issuer"),
            issuer_metadata_with_two_auth_servers(),
            StatusCode::OK,
        );
        mock_http_once(
            http_client,
            Method::GET,
            well_known(auth_url, "oauth-authorization-server"),
            authorization_metadata_of(auth_url),
            StatusCode::OK,
        );
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
            pop: ProofOfPossessionMetadata {
                lifetime: time::Duration::minutes(5),
                not_before: None,
            },
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
            // CredentialVerification::default(),
            issuer_metadata,
            sample_authorization_metadata(),
            client_id.to_owned(),
            "urn:ietf:wg:oauth:2.0:oob".to_string(),
            Some(vec![
                CredentialExtraVerification::CredentialIssuerIdentifier,
            ]),
        )
        .unwrap()
    }

    fn sample_access_token_response() -> serde_json::Value {
        json!({
            "access_token": access_token(),
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

    fn notification_endpoint() -> Url {
        Url::parse(ISSUER_URL)
            .unwrap()
            .join("/notification")
            .unwrap()
    }

    fn deferred_credential_endpoint() -> Url {
        Url::parse(ISSUER_URL)
            .unwrap()
            .join("/deferred_credential")
            .unwrap()
    }

    fn nonce_endpoint() -> Url {
        Url::parse(ISSUER_URL).unwrap().join("/nonce").unwrap()
    }

    fn auth_srv_metadata_request_endpoint() -> Url {
        Url::parse(AUTH_URL)
            .unwrap()
            .join("/.well-known/oauth-authorization-server")
            .unwrap()
    }
}
