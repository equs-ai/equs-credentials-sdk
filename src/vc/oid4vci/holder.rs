use crate::did::DIDURLBuf;
use crate::did::didweb::DIDWeb;
use crate::http::HttpClient;
use crate::nonce::Nonce;
use crate::utils::wasm::WasmNotSend;
use crate::vc;
use crate::vc::core::{
    CredentialOffer, CredentialOfferContent, InvalidDIDUrlSnafu, KeyMetadata, Proof as AsdkProof,
};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::oid4vci::AuthzFlow::Authorize;
use crate::vc::oid4vci::credential_issuer_identifier::CredentialIssuerIdentifier;
use crate::vc::oid4vci::internal_error::{
    AuthorizationCallbackSnafu, AuthorizationRequestSnafu, HolderServiceSnafu, MetadataSnafu,
    ParseSnafu, TypeConversionSnafu, UrlParseSnafu, VCSnafu,
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
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthorizationCode, ClientId, CsrfToken, HttpRequest, HttpResponse,
    PkceCodeChallenge, RedirectUrl, ResponseType, Scope,
};
use oid4vci::core::authorization::AuthorizationDetailsObject;
use oid4vci::core::client::Client;
use oid4vci::core::profiles::CoreProfilesCredentialResponseType;
use oid4vci::credential::{CredentialId, Proofs, ResponseEnum};
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

        let holder_service = Self::from_iss_url_with_configs(
            holder,
            http_client,
            iss_url.to_string(),
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
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
        credential_extra_verification: Option<Vec<CredentialExtraVerification>>,
    ) -> Result<Self> {
        let issuer_metadata: IssuerMetadata =
            MetadataDiscovery::discover_metadata(http_client.as_ref(), &issuer_url).await?;
        debug!(resolved_issuer_metadata = ?issuer_metadata);

        let auth_srv_url = issuer_metadata
            .authorization_servers()
            .and_then(|vec| vec.iter().next());

        let authz_metadata: AuthorizationMetadata = MetadataDiscovery::discover_metadata(
            http_client.as_ref(),
            &auth_srv_url
                .map(|url| url.to_string())
                .unwrap_or(issuer_url),
        )
        .await?;
        debug!(resolved_authorization_server_metadata = ?authz_metadata);

        Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            client_id,
            redirect_url,
            credential_extra_verification,
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
            credential_extra_verification: credential_extra_verification.unwrap_or_default(),
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

        let proofs = self.resolve_proofs(keys_metadata, offer, nonce).await?;

        let credential_request = self
            .client
            .request_credential(
                token.to_owned(),
                CredentialId::CredentialConfigurationId(cred_def.id().to_owned()),
            )
            .set_proofs(proofs);

        let resp = credential_request
            .request_async(&self.http_closure())
            .await
            .map_err(Error::from)?;

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
            _ => ProtocolSnafu::credential_endpoint(
                CredentialEndpointError::UnknownCredentialConfiguration,
                format!("Unknown credential configuration: {}", self.format()),
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
            _ => ProtocolSnafu::credential_endpoint(
                CredentialEndpointError::InvalidProof,
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
    use crate::vc::core::ProofOfPossessionMetadata;
    use crate::vc::formats::json_ld_vc::VC;
    use crate::vc::oid4vci::protocol_error::TokenEndpointError;
    use crate::vc::oid4vci::tests::fixtures::{
        ACCESS_TOKEN, AUTH_URL, CRED_DEF_ID, ISSUER_URL, NOTIFICATION_ID, REQ_URI_CODE, SCOPE,
        SD_JWT_CREDS, SampleIssuerMetadata, fake_access_token, sample_access_token,
        sample_authorization_metadata, sample_batch_cred_response, sample_cred_response,
        sample_credential_definition, sample_offer_with_auth_code_grant,
        sample_offer_with_pre_auth_code_grant,
    };
    use crate::vc::oid4vci::{CredentialRequest, CredentialResult, Holder, protocol_error};
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
    #[case::sdjwt_iss_oid4vci(ISSUER_URL, Credential::SdJwt(SD_JWT_CREDENTIAL_ISS_OID4VCI.to_owned()
    ))]
    #[case::sdjwt_iss_did(ISSUER_URL, Credential::SdJwt(SD_JWT_CREDENTIAL_ISS_DID.to_owned()))]
    #[should_panic(
        expected = "Credential contains issuer identifier notadid:web:issuer-backend.com"
    )]
    #[case::sdjwt_iss_other_invalid(ISSUER_URL, Credential::SdJwt(SD_JWT_CREDENTIAL_ISS_OTHER_INVALID.to_owned()
    ))]
    #[case::sdjwt_iss_other_valid("http://issuer-backend.com", Credential::SdJwt(SD_JWT_CREDENTIAL_ISS_OTHER_VALID.to_owned()
    ))]
    #[should_panic(expected = "Credential does not contain issuer identifier")]
    #[case::sdjwt_iss_none(ISSUER_URL, Credential::SdJwt(SD_JWT_CREDENTIAL_ISS_NONE.to_owned()))]
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

    // Payload: { "iss": "https://issuer-backend.com", "id": "1234" }
    const SD_JWT_CREDENTIAL_ISS_OID4VCI: &str = "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9\
    .eyJpc3MiOiJodHRwczovL2lzc3Vlci1iYWNrZW5kLmNvbSIsImlkIjoiMTIzNCIsIl9zZF9hbGciOiJTSEEtMjU2In0\
    .-ZfBXDOJhhpA448q5oxGUl7VcxZAYFg9C0gYTbAweDKBxsB2KNrBIh9UK3hAJsSizBRdA0wKnu_Tn5ZLyW-Ouw~";

    // Payload: { "iss": "did:web:issuer-backend.com/ignored-path", "id": "1234" }
    const SD_JWT_CREDENTIAL_ISS_DID: &str = "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9\
    .eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci1iYWNrZW5kLmNvbS9pZ25vcmVkLXBhdGgiLCJpZCI6IjEyMzQiLCJfc2RfYWxnIjoiU0hBLTI1NiJ9\
    .3peUWSXL3NZL6Ye2c7apa_czw4SCwUMpVk0ryxK4F_xr_SwS14AIz9SqrN3o1ZGC5goT1vVDmEczI9kMmHCCmA~";

    // Payload: { "iss": "notadid:web:issuer-backend.com", "id": "1234" }
    const SD_JWT_CREDENTIAL_ISS_OTHER_INVALID: &str = "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9\
    .eyJpc3MiOiJub3RhZGlkOndlYjppc3N1ZXItYmFja2VuZC5jb20iLCJpZCI6IjEyMzQiLCJfc2RfYWxnIjoiU0hBLTI1NiJ9\
    .GcD3futV-qHM0WsTPxxVk_DCyAOlcjUAGXbikeSM7AkWgyk7QDVqS5Z_FUpQ0tdrzaG8lAzlNJMrUAf4FKkk9A~";

    // Payload: { "iss": "http://issuer-backend.com", "id": "1234" }
    // Note that Credential Issuer Identifier is URL with https protocol.
    const SD_JWT_CREDENTIAL_ISS_OTHER_VALID: &str = "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9\
    .eyJpc3MiOiJodHRwOi8vaXNzdWVyLWJhY2tlbmQuY29tIiwiaWQiOiIxMjM0In0\
    .8n5Y2hzrT3nKuqtJ6ofppryjOAHVCKvvcEAv3NUrsPEIEFNTQe0lShRdcJqIeJjaJEu9FF4kmYru9QXfgB5-ug~";

    // Payload: { "id": "1234" }
    const SD_JWT_CREDENTIAL_ISS_NONE: &str = "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9\
    .eyJpZCI6IjEyMzQiLCJfc2RfYWxnIjoiU0hBLTI1NiJ9\
    .J1Lu6onzdyVbPM2QQg9mFUShMCI-4VPBe4rSss0O8g3H0Bc9klzB1eVdHjbEKxkB79Vt3fjg83UM-Ya4tXySzg~";

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
            .join("/.well-known/oauth-authorization-server")
            .unwrap()
    }
}
