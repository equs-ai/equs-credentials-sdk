use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::kms::{KeyHandle, Kms};
use crate::nonce::{Nonce, NonceHandler};
use crate::utils::http::MimeType;
use crate::vault::CredentialEntry;
use crate::vc::core::PresentationInput;
use crate::vc::dcql::DCQL;
use crate::vc::oid4vp::internal_error::{
    AuthorizationResponseSnafu, CredentialNotFoundSnafu, DCQLSnafu, HttpClientSnafu,
    IdTokenGenerationSnafu, IdTokenMetadataNotFoundSnafu, IdTokenParseSnafu, JsonSnafu, KMSSnafu,
    ParseSnafu, PresentationExchangeSnafu, VCSnafu,
};
use crate::vc::oid4vp::metadata::default_wallet_metadata;
use crate::vc::oid4vp::signer::Signer;
use crate::vc::oid4vp::{
    AuthorizationResponseMetadata, CredentialMapping, CredentialsFindResult, CredentialsMapping,
    ProtocolError, ResolvedAuthRequest, ResolvedPresentationQuery, ResponseMode,
};
use crate::vc::presentation_exchange::PresentationDefinition;
use crate::vc::{RequestedPresentation, dcql, oid4vp as api, presentation_exchange};
use crate::{utils, vc};
use async_trait::async_trait;
use futures::future;
use oauth2::http::{Request, Response};
use openid4vp::core::authorization_request::parameters::{ResponseType, WalletNonce};
use openid4vp::core::authorization_request::verification::{RequestVerifier, did};
use openid4vp::core::authorization_request::{AuthorizationRequest, AuthorizationRequestObject};
use openid4vp::core::metadata::WalletMetadata;
use openid4vp::core::presentation_submission::PresentationSubmission;
use openid4vp::core::response::parameters::{IdToken, VpToken};
use openid4vp::core::response::{AuthorizationResponse, UnencodedAuthorizationResponse};
use openid4vp::core::util::http::AsyncHttpClient;
use openid4vp::wallet::{IdTokenParams, Wallet};
use snafu::ResultExt;
use ssi::dids::DIDURLBuf;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{Level, info, instrument};
use url::Url;

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;
pub struct HolderService<HL, HC, KH, KMS>
where
    HL: vc::core::Holder,
    HC: HttpClient,
    KH: KeyHandle,
    KMS: Kms<KH>,
{
    holder: HL,
    public_jwk_resolver: UniversalResolver,
    metadata: WalletMetadata,
    kms: KMS,
    http_client: Arc<HC>,
    _marker: PhantomData<KH>,
    nonce_handler: Option<Box<dyn NonceHandler>>,
}

impl<HL, HC, KH, KMS> HolderService<HL, HC, KH, KMS>
where
    HL: vc::core::Holder,
    HC: HttpClient,
    KH: KeyHandle,
    KMS: Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(holder, http_client, kms, resolver, nonce_handler))]
    pub fn new(
        holder: HL,
        http_client: Arc<HC>,
        kms: KMS,
        resolver: UniversalResolver,
        metadata: Option<WalletMetadata>,
        nonce_handler: Option<Box<dyn NonceHandler>>,
    ) -> Self {
        let metadata = metadata.unwrap_or(default_wallet_metadata());

        info!("oid4vp-holder service is initialized");

        Self {
            holder,
            metadata,
            public_jwk_resolver: resolver,
            kms,
            http_client,
            _marker: Default::default(),
            nonce_handler,
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn submit_presentation(
        &self,
        presentations: Vec<RequestedPresentation>,
        auth_request: &ResolvedAuthRequest,
        auth_response_metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>> {
        let id_token = match auth_request.response_type {
            ResponseType::VpTokenIdToken => Some(
                self.generate_id_token(auth_request, auth_response_metadata)
                    .await?,
            ),
            _ => None,
        };

        let auth_resp = Self::create_auth_response(&presentations, id_token, auth_request)?;

        let redirect_url = self
            .submit_response(
                &auth_request.response_uri,
                &auth_request.response_mode,
                auth_resp,
            )
            .await?;

        Ok(redirect_url)
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    fn create_auth_response(
        requested_presentations: &[RequestedPresentation],
        id_token: Option<IdToken>,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<AuthorizationResponse> {
        let (vp_token, ps) = match auth_request.resolved_presentation_query.clone() {
            ResolvedPresentationQuery::DCQL(dcql) => {
                let vp_token_json =
                    dcql::prepare_vp_token_response_for_dcql(requested_presentations)
                        .context(DCQLSnafu)?;
                let vp_token =
                    VpToken::try_from(vp_token_json).context(AuthorizationResponseSnafu)?;
                (vp_token, None)
            }
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                let pr = presentation_exchange::prepare_presentation_response(
                    requested_presentations,
                    &pd,
                )
                .context(PresentationExchangeSnafu)?;
                let vp_token =
                    VpToken::try_from(pr.presentations).context(AuthorizationResponseSnafu)?;
                let ps_json =
                    serde_json::to_value(pr.presentation_submission).context(JsonSnafu)?;
                let ps = PresentationSubmission::try_from(ps_json)
                    .context(AuthorizationResponseSnafu)?;
                (vp_token, Some(ps))
            }
        };

        let auth_resp = AuthorizationResponse::Unencoded(UnencodedAuthorizationResponse {
            vp_token,
            presentation_submission: ps,
            id_token,
            state: auth_request.state.clone(),
        });

        Ok(auth_resp)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn generate_id_token(
        &self,
        auth_request: &ResolvedAuthRequest,
        auth_response_metadata: &AuthorizationResponseMetadata,
    ) -> Result<IdToken> {
        let metadata = auth_response_metadata
            .id_token_metadata
            .as_ref()
            .ok_or_else(|| IdTokenMetadataNotFoundSnafu.build())?;

        let key = self
            .kms
            .get(&metadata.key_metadata.kid)
            .await
            .context(KMSSnafu)?;

        let did_url = DIDURLBuf::from_str(&metadata.key_metadata.did_url).map_err(|e| {
            ParseSnafu {
                details: e.to_string(),
            }
            .build()
        })?;
        let params = IdTokenParams {
            audience: auth_request.client_id.to_owned(),
            nonce: auth_request.nonce.secret().to_owned().into(),
            lifetime: metadata.lifetime,
            other: None,
        };

        let raw = self
            .generate_did_based_id_token(&did_url, params, Signer::new(key)?)
            .await
            .context(IdTokenGenerationSnafu)?;

        let id_token = raw.try_into().context(IdTokenParseSnafu)?;

        Ok(id_token)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn create_presentation_by_input(
        &self,
        credential: &CredentialEntry,
        presentation_input: &PresentationInput,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<RequestedPresentation> {
        let presentation = self
            .holder
            .create_presentation(
                &auth_request.nonce,
                auth_request.client_id.as_str(),
                presentation_input,
                credential,
            )
            .await
            .context(VCSnafu)?;

        Ok(RequestedPresentation {
            id: presentation_input.id.to_owned(),
            presentation,
        })
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn resolve_auth_resp_endpoint_and_mode(
        &self,
        request_uri: &Url,
    ) -> Result<(Url, ResponseMode)> {
        let auth_req =
            AuthorizationRequest::from_url(request_uri, &self.metadata.authorization_endpoint().0)?;

        let (url, mode) = match auth_req {
            AuthorizationRequest::Plain(aro) => {
                (aro.return_uri().to_owned(), aro.response_mode().to_owned())
            }
            AuthorizationRequest::Signed(signed_req) => {
                signed_req.resolve_response_uri_and_mode(self).await?
            }
        };

        Ok((url, mode))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn handle_auth_error_resp(
        &self,
        response_uri: &Url,
        response_mode: &ResponseMode,
        mut error: ProtocolError,
    ) -> Result<ProtocolError> {
        let encoded = serde_urlencoded::to_string(&error).map_err(|e| {
            ParseSnafu {
                details: format!("could not serialize protocol error into form-urlencoded: {e}"),
            }
            .build()
        })?;

        match response_mode {
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
                let req = utils::http::generate_post_req(
                    response_uri,
                    MimeType::AppFormUrlEnc,
                    MimeType::AppJson,
                    encoded.into_bytes(),
                )
                .context(HttpClientSnafu)?;

                let _ = self
                    .http_client
                    .async_call(req)
                    .await
                    .context(HttpClientSnafu)?;

                info!("authorization error response is sent to verifier");

                Ok(error)
            }
            _ => {
                let mut response_uri = response_uri.clone();
                response_uri.set_fragment(Some(&encoded));

                error.set_redirect_uri(Some(response_uri));

                Ok(error)
            }
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn create_presentation_from_creds_map(
        &self,
        cred_map: &CredentialMapping,
        presentation_input: &PresentationInput,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<RequestedPresentation> {
        let Some(cred) = cred_map.get(&presentation_input.id) else {
            let err = ProtocolError::access_denied(
                "matching credentials are not found",
                auth_request.state.clone(),
            );
            let source = self
                .handle_auth_error_resp(
                    &auth_request.response_uri,
                    &auth_request.response_mode,
                    err,
                )
                .await?;

            return Err(Error::Protocol { source });
        };

        self.create_presentation_by_input(cred, presentation_input, auth_request)
            .await
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn validate_against_supported_vp_formats(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<()> {
        match auth_request.resolved_presentation_query.clone() {
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                let formats_map = pd.input_descriptors().iter().flat_map(|d| &d.format);
                for (format, payload) in formats_map {
                    let found = self
                        .metadata
                        .vp_formats_supported()
                        .contains_claim_format_with_payload(format, payload);

                    if !found {
                        let body = ProtocolError::vp_formats_not_supported(
                            &format!(
                                "vp format = '{}' with {} algorithms is not supported",
                                String::from(format.to_owned()),
                                serde_json::to_string(&payload).unwrap_or_else(|_| "".to_string())
                            ),
                            auth_request.state.clone(),
                        );

                        let err = self
                            .handle_auth_error_resp(
                                &auth_request.response_uri,
                                &auth_request.response_mode,
                                body,
                            )
                            .await?;

                        return Err(Error::Protocol { source: err });
                    }
                }
            }
            ResolvedPresentationQuery::DCQL(dcql) => {
                let formats = dcql.credentials().iter().map(|d| d.format());
                for format in formats {
                    let found = self
                        .metadata
                        .vp_formats_supported()
                        .0
                        .to_owned()
                        .keys()
                        .any(|k| k == format);

                    if !found {
                        let body = ProtocolError::vp_formats_not_supported(
                            &format!(
                                "vp format = '{}' is not supported",
                                String::from(format.to_owned()),
                            ),
                            auth_request.state.clone(),
                        );
                        let err = self
                            .handle_auth_error_resp(
                                &auth_request.response_uri,
                                &auth_request.response_mode,
                                body,
                            )
                            .await?;

                        return Err(Error::Protocol { source: err });
                    }
                }
            }
        }

        Ok(())
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn present_credentials_auto_with_pd(
        &self,
        auth_request: &ResolvedAuthRequest,
        pd: PresentationDefinition,
        claims_to_exclude: Option<&HashMap<String, Vec<String>>>,
    ) -> Result<Vec<RequestedPresentation>> {
        let presentation_inputs =
            presentation_exchange::split_to_inputs_for_pd(&pd, claims_to_exclude)
                .context(PresentationExchangeSnafu)?;
        let presentations =
            future::try_join_all(presentation_inputs.iter().map(|presentation_input| async {
                let creds = self
                    .holder
                    .find_vcs_for_presentation(presentation_input)
                    .await
                    .context(VCSnafu)?;

                if let CredentialsFindResult::Credentials(credentials) = creds {
                    if let Some(cred_entry) = credentials.first() {
                        return self
                            .create_presentation_by_input(
                                cred_entry,
                                presentation_input,
                                auth_request,
                            )
                            .await;
                    }
                }

                let err = ProtocolError::access_denied(
                    "matching credentials are not found",
                    auth_request.state.clone(),
                );

                let err = self
                    .handle_auth_error_resp(
                        &auth_request.response_uri,
                        &auth_request.response_mode,
                        err,
                    )
                    .await?;

                Err(Error::Protocol { source: err })
            }))
            .await?;
        Ok(presentations)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn present_credentials_auto_with_dcql(
        &self,
        auth_request: &ResolvedAuthRequest,
        dcql: DCQL,
    ) -> Result<Vec<RequestedPresentation>> {
        let presentations: Vec<RequestedPresentation>;
        let presentation_inputs = dcql::split_to_inputs_for_dcql(dcql.credentials());
        let mut id_to_pres_input: HashMap<String, PresentationInput> = HashMap::new();
        dcql.credentials().iter().for_each(|cred| {
            if let Some(pi) = presentation_inputs
                .iter()
                .find(|&p| p.id == *cred.id().as_str())
            {
                id_to_pres_input.insert(cred.id().as_str().to_owned(), pi.clone());
            }
        });

        let pairs = future::try_join_all(dcql.credentials().iter().map(|credential| async {
            if !id_to_pres_input.contains_key(credential.id().as_str()) {
                CredentialNotFoundSnafu.fail()?;
            }
            let pi = id_to_pres_input[credential.id().as_str()].clone();
            let creds = self
                .holder
                .find_vcs_for_presentation(&pi)
                .await
                .context(VCSnafu)?;

            if let CredentialsFindResult::Credentials(credentials) = creds {
                if let Some(cred_entry) = credentials.first() {
                    return Ok((credential.id().as_str(), cred_entry.clone()));
                }
            }

            let err = ProtocolError::access_denied(
                "matching credentials are not found",
                auth_request.state.clone(),
            );

            let err = self
                .handle_auth_error_resp(
                    &auth_request.response_uri,
                    &auth_request.response_mode,
                    err,
                )
                .await?;

            Err(Error::Protocol { source: err })
        }))
        .await?;
        let id_to_cred: HashMap<_, _> = pairs.into_iter().collect();
        let to_be_returned_credentials =
            dcql::filter_creds_with_cred_sets(id_to_cred.clone(), dcql.to_owned());
        if let Ok(to_be_returned_credentials) = to_be_returned_credentials {
            presentations =
                future::try_join_all(to_be_returned_credentials.iter().map(|credential| async {
                    if !id_to_pres_input.contains_key(credential.id().as_str()) {
                        CredentialNotFoundSnafu.fail()?;
                    }
                    let pi = id_to_pres_input[credential.id().as_str()].clone();
                    if !id_to_cred.contains_key(credential.id().as_str()) {
                        CredentialNotFoundSnafu.fail()?;
                    }
                    let cred = id_to_cred[credential.id().as_str()].clone();
                    self.create_presentation_by_input(&cred, &pi, auth_request)
                        .await
                }))
                .await?
        } else {
            presentations = vec![];
        }
        Ok(presentations)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<HL, HC, KH, KMS> api::Holder for HolderService<HL, HC, KH, KMS>
where
    HL: vc::core::Holder,
    HC: HttpClient,
    KH: KeyHandle,
    KMS: Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn get_authorization_request(&self, request_uri: &Url) -> Result<ResolvedAuthRequest> {
        let aro_result = self
            .validate_request(request_uri)
            .await
            .map_err(Error::from);

        let aro = match aro_result {
            Ok(aro) => aro,
            Err(Error::Protocol { source }) => {
                let (response_uri, response_mode) = self
                    .resolve_auth_resp_endpoint_and_mode(request_uri)
                    .await?;

                info!(
                    "authorization request validation is failed, handling an authorization error response..."
                );
                let source = self
                    .handle_auth_error_resp(&response_uri, &response_mode, source)
                    .await?;

                return Err(Error::Protocol { source });
            }
            Err(e) => return Err(e),
        };

        let rpq = match aro
            .resolve_presentation_query(self)
            .await
            .map_err(Error::from)
        {
            Ok(p) => p,
            Err(Error::Protocol { source }) => {
                info!(
                    "presentation definition resolution is failed, handling an authorization error response..."
                );
                let source = self
                    .handle_auth_error_resp(aro.return_uri(), aro.response_mode(), source)
                    .await?;

                return Err(Error::Protocol { source });
            }
            Err(e) => return Err(e),
        };

        Ok(ResolvedAuthRequest {
            client_id: aro.client_id().get_full_id(),
            client_metadata: aro.client_metadata().to_owned(),
            resolved_presentation_query: rpq,
            nonce: Nonce::from_secret(aro.nonce().as_str().to_owned()),
            response_type: aro.response_type().to_owned(),
            response_mode: aro.response_mode().to_owned(),
            response_uri: aro.return_uri().to_owned(),
            state: aro.state(),
        })
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        auth_response_metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>> {
        info!("presenting verifiable presentation is started");

        self.validate_against_supported_vp_formats(auth_request)
            .await?;

        let presentations = match auth_request.clone().resolved_presentation_query {
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                info!("presentation exchange flow is used");
                self.present_credentials_auto_with_pd(
                    auth_request,
                    pd,
                    auth_response_metadata.claims_to_exclude.as_ref(),
                )
                .await?
            }
            ResolvedPresentationQuery::DCQL(dcql) => {
                info!("dcql flow is used");
                self.present_credentials_auto_with_dcql(auth_request, dcql)
                    .await?
            }
        };

        let redirect_url = self
            .submit_presentation(presentations, auth_request, auth_response_metadata)
            .await?;

        info!("verifiable presentations are successfully presented");

        Ok(redirect_url)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn find_vcs_for_presentation(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<CredentialsMapping> {
        let mut creds_map = CredentialsMapping::new();
        let presentation_inputs = match auth_request.clone().resolved_presentation_query {
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                presentation_exchange::split_to_inputs_for_pd(&pd, None)
                    .context(PresentationExchangeSnafu)?
            }
            ResolvedPresentationQuery::DCQL(dcql) => {
                dcql::split_to_inputs_for_dcql(dcql.credentials())
            }
        };
        for pres_input in presentation_inputs.iter() {
            let creds = self
                .holder
                .find_vcs_for_presentation(pres_input)
                .await
                .context(VCSnafu)?;
            creds_map.insert(pres_input.id.to_owned(), creds);
        }

        Ok(creds_map)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        cred_map: &CredentialMapping,
        auth_response_metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>> {
        info!("presenting verifiable presentations is started");

        let presentation_inputs = match auth_request.clone().resolved_presentation_query {
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                presentation_exchange::split_to_inputs_for_pd(
                    &pd,
                    auth_response_metadata.claims_to_exclude.as_ref(),
                )
                .context(PresentationExchangeSnafu)?
            }
            ResolvedPresentationQuery::DCQL(dcql) => {
                dcql::split_to_inputs_for_dcql(dcql.credentials())
            }
        };
        let presentations: Vec<RequestedPresentation> =
            future::try_join_all(presentation_inputs.iter().map(|presentation_input| async {
                self.create_presentation_from_creds_map(cred_map, presentation_input, auth_request)
                    .await
            }))
            .await?;

        let redirect_url = self
            .submit_presentation(presentations, auth_request, auth_response_metadata)
            .await?;

        info!("verifiable presentations are successfully presented");

        Ok(redirect_url)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn decline_authorization_request(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<Option<Url>> {
        info!(
            "presentation request is declined, sending an authorization error response to the verifier..."
        );
        let err = ProtocolError::access_denied(
            "consent to share the presentation is not given",
            auth_request.state.clone(),
        );
        let err = self
            .handle_auth_error_resp(&auth_request.response_uri, &auth_request.response_mode, err)
            .await?;

        Ok(err.redirect_uri().cloned())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<HL, HC, KH, KMS> AsyncHttpClient for HolderService<HL, HC, KH, KMS>
where
    HL: vc::core::Holder,
    HC: HttpClient,
    KH: KeyHandle,
    KMS: Kms<KH>,
{
    async fn execute(&self, request: Request<Vec<u8>>) -> anyhow::Result<Response<Vec<u8>>> {
        Ok(self.http_client.async_call(request).await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<HL, HC, KH, KMS> Wallet for HolderService<HL, HC, KH, KMS>
where
    HL: vc::core::Holder,
    HC: HttpClient,
    KH: KeyHandle,
    KMS: Kms<KH>,
{
    type HttpClient = Self;

    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }

    fn http_client(&self) -> &Self::HttpClient {
        self
    }
    async fn generate_nonce(&self) -> anyhow::Result<Option<WalletNonce>> {
        match &self.nonce_handler {
            Some(nh) => {
                let nonce = nh.generate().await.map_err(anyhow::Error::new)?;
                Ok(Some(WalletNonce(nonce.secret().to_string())))
            }
            None => Ok(None),
        }
    }

    async fn validate_nonce(&self, nonce: &WalletNonce) -> anyhow::Result<bool> {
        match &self.nonce_handler {
            Some(nh) => {
                let nonce = Nonce::from_secret(nonce.0.clone());
                nh.validate(&nonce).await.map_err(anyhow::Error::new)
            }
            None => Ok(true),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<HL, HC, KH, KMS> RequestVerifier for HolderService<HL, HC, KH, KMS>
where
    HL: vc::core::Holder,
    HC: HttpClient,
    KH: KeyHandle,
    KMS: Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<(), openid4vp::core::error::Error> {
        did::verify_with_resolver(
            self.metadata(),
            decoded_request,
            request_jwt,
            None,
            &self.public_jwk_resolver,
        )
        .await
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        redirect_uri: String,
    ) -> anyhow::Result<(), openid4vp::core::error::Error> {
        let supported = self
            .metadata()
            .is_client_id_schema_supported(decoded_request.client_id().get_scheme());
        if !supported {
            return Err(openid4vp::core::error::Error::protocol_invalid_req(
                format!(
                    "The scheme '{}' is not supported",
                    decoded_request.client_id().get_scheme()
                )
                .as_str(),
                decoded_request.state(),
            ));
        }
        let client_id_value = &decoded_request.client_id().get_id();
        let client_id_as_uri = Url::parse(client_id_value).map_err(|_| {
            openid4vp::core::error::Error::protocol_invalid_req(
                format!("could not parse 'client_id' = {client_id_value} as uri, in 'redirect_uri' response method it must be uri").as_str(),
                decoded_request.state(),
            )
        })?;
        let redirect_uri = Url::parse(redirect_uri.as_str()).map_err(|_| {
            openid4vp::core::error::Error::protocol_invalid_req(
                "could not parse 'redirect_uri' = {redirect_uri} as uri, in 'redirect_uri' response method it must be uri",
                decoded_request.state(),
            )
        })?;

        if client_id_as_uri != redirect_uri {
            return Err(openid4vp::core::error::Error::protocol_invalid_req(
                &format!(
                    "in 'redirect_uri' response mode 'client_id' = {} must be equal to 'redirect_uri' = {}",
                    client_id_value, redirect_uri
                ),
                decoded_request.state(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::MockKms;
    use crate::kms::{CreateOptions, KeyType, Kms};
    use crate::utils::http::test::{
        mock_http_fn, mock_http_fn_with_plain_text_resp, mock_http_req_predicate,
    };
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::utils::test_utils::{failed_signer_key, no_jwk_key};
    use crate::vc;
    use crate::vc::claims::{Claim, Claims};
    use crate::vc::core::KeyMetadata;
    use crate::vc::oid4vp::protocol_error::ErrorType;
    use crate::vc::oid4vp::tests::fixtures::single_presentation::sd_jwt::{
        AUTH_REQUEST, AUTH_REQUEST_JWT, AUTH_REQUEST_WITH_NON_URL_SCHEME,
        AUTH_REQUEST_WITH_REDIRECT_URI, AUTH_REQUEST_WITH_STATE_JWT,
        AUTH_REQUEST_WITH_UNSUPPORTED_CLIENT_ID_SCHEME, AUTH_REQUEST_WITH_WRONG_CLIENT_ID,
    };
    use crate::vc::oid4vp::tests::fixtures::{
        REQUEST_URI, STATE, VERIFIER_URL, multi_presentation, single_presentation,
    };
    use crate::vc::oid4vp::tests::utils::{
        PresentationTestCase, build_url, holder_service, request_verifier, validate_claims,
    };
    use crate::vc::oid4vp::{
        AuthorizationResponseMetadata, CredentialsFindResult, Error, FindVCsFailReason, Holder,
        IdTokenMetadata, InternalError, ProtocolError, ResolvedPresentationQuery, ResponseType,
    };
    use crate::vc::presentation_exchange::ClaimFormatMap;
    use crate::vc::{ClaimFormatDesignation, Credential};
    use oauth2::HttpResponse;
    use oauth2::http::Method;
    use oauth2::reqwest::StatusCode;
    use openid4vp::core::authorization_request::AuthorizationRequestObject;
    use openid4vp::core::authorization_request::parameters::ResponseMode;
    use openid4vp::core::authorization_request::verification::RequestVerifier;
    use openid4vp::core::response::PostRedirection;
    use rstest::rstest;
    use sd_jwt_rs::SDJWTSerializationFormat;
    use sd_jwt_rs::utils::decode_sd_jwt;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn get_auth_request_success() {
        let mut http_client = MockHttpClient::new();
        mock_http_fn_with_plain_text_resp(
            &mut http_client,
            Method::GET,
            build_url(VERIFIER_URL, "request"),
            AUTH_REQUEST_JWT,
            1.into(),
        );
        let holder = holder_service(http_client, LocalKms::new(), InMemVault::new()).await;

        // Get request object
        let request_obj = holder
            .get_authorization_request(&REQUEST_URI.parse().unwrap())
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(&request_obj).unwrap(),
            AUTH_REQUEST.parse::<serde_json::Value>().unwrap()
        );
    }

    #[tokio::test]
    async fn request_verifier_verifies_for_did_successfully() {
        let request_verifier =
            request_verifier(MockHttpClient::new(), LocalKms::new(), InMemVault::new()).await;
        let aro: AuthorizationRequestObject = serde_json::from_str(AUTH_REQUEST).unwrap();
        request_verifier
            .did(&aro, AUTH_REQUEST_JWT.to_string())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "DIDs from 'kid' (did:key:zDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV) and 'client_id' (did:key:1) do not match"
    )]
    async fn request_verifier_verifies_for_did_unsuccessfully() {
        let request_verifier =
            request_verifier(MockHttpClient::new(), LocalKms::new(), InMemVault::new()).await;
        let aro: AuthorizationRequestObject =
            serde_json::from_str(AUTH_REQUEST_WITH_WRONG_CLIENT_ID).unwrap();
        request_verifier
            .did(&aro, AUTH_REQUEST_JWT.to_string())
            .await
            .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "The scheme 'web-origin' is not supported")]
    #[case(
        AUTH_REQUEST_WITH_UNSUPPORTED_CLIENT_ID_SCHEME,
        "https://localhost:8080"
    )]
    #[should_panic(
        expected = "could not parse 'client_id' = non-link-id as uri, in 'redirect_uri' response method it must be uri"
    )]
    #[case(AUTH_REQUEST_WITH_NON_URL_SCHEME, "https://localhost:8080")]
    #[should_panic(
        expected = "in 'redirect_uri' response mode 'client_id' = https://localhost:8080 must be equal to 'redirect_uri' = https://wronglink:8080/"
    )]
    #[case(AUTH_REQUEST_WITH_REDIRECT_URI, "https://wronglink:8080")]
    #[tokio::test]
    async fn request_verifier_for_redirect_gets_unsupported_scheme(
        #[case] auth_request: &str,
        #[case] redirect_uri: String,
    ) {
        let request_verifier =
            request_verifier(MockHttpClient::new(), LocalKms::new(), InMemVault::new()).await;
        let aro: AuthorizationRequestObject = serde_json::from_str(auth_request).unwrap();
        request_verifier
            .redirect_uri(&aro, redirect_uri)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn request_verifier_for_redirect_successfully() {
        let request_verifier =
            request_verifier(MockHttpClient::new(), LocalKms::new(), InMemVault::new()).await;
        let aro: AuthorizationRequestObject =
            serde_json::from_str(AUTH_REQUEST_WITH_REDIRECT_URI).unwrap();
        request_verifier
            .redirect_uri(&aro, "https://localhost:8080".to_string())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_auth_request_with_state_success() {
        let mut http_client = MockHttpClient::new();
        mock_http_fn_with_plain_text_resp(
            &mut http_client,
            Method::GET,
            build_url(VERIFIER_URL, "request"),
            AUTH_REQUEST_WITH_STATE_JWT,
            1.into(),
        );
        let holder = holder_service(http_client, LocalKms::new(), InMemVault::new()).await;
        pub const REQUEST_URI: &str = "openid4vp://?client_id=did%3Akey%3AzDnaexoypPeJHz5xfdshV9NqsWT3BUmHvDUDe8VxWf6Ln23Uh&request_uri=http%3A%2F%2F127.0.0.1%3A55796%2Frequest";

        let request_obj = holder
            .get_authorization_request(&REQUEST_URI.parse().unwrap())
            .await
            .unwrap();

        assert_eq!(request_obj.state, Some(STATE.to_string()));
    }

    #[rstest]
    #[case::single_presentation::single_presentation_success(
        single_presentation::sd_jwt::presentation_test_case()
    )]
    #[case::single_presentation::single_presentation_with_state_success(
        single_presentation::sd_jwt::presentation_test_case_with_state()
    )]
    #[case::multi_presentation_success(multi_presentation::presentation_test_case())]
    #[case::multi_presentation_with_state_success(
        multi_presentation::presentation_test_case_with_state()
    )]
    #[tokio::test]
    async fn present_credential_auto_success(#[case] test_case: PresentationTestCase) {
        let mut http_client = MockHttpClient::new();
        test_case.mock_http_auth_response_endpoint(&mut http_client, None);

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn present_credential_auto_with_siop_success() {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let test_case = siop_case(key_metadata);

        let mut http_client = MockHttpClient::new();
        test_case.mock_http_auth_response_endpoint(&mut http_client, None);

        let vault = test_case.prepare_vault(&kms).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn present_credential_auto_success_with_excluded_claims() {
        let test_case = single_presentation::sd_jwt::presentation_test_case();

        let mut auth_response_metadata = AuthorizationResponseMetadata::default();
        auth_response_metadata
            .add_claims_to_exclude("Identity-1".to_string(), "$.name".to_string());

        let mut http_client = MockHttpClient::new();
        mock_http_req_predicate(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            move |request| {
                let form = serde_urlencoded::from_bytes(request.as_bytes()).unwrap();
                let claims = PresentationTestCase::extract_claims(&form);

                let expected_claim = claims.first().unwrap().get("name");

                assert_eq!(expected_claim, None, "Claim is not excluded");

                true
            },
            PostRedirection {
                redirect_uri: build_url(VERIFIER_URL, "redirect"),
            },
            StatusCode::OK,
            1.into(),
        );

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        let result = holder
            .present_credentials_auto(&test_case.request, &auth_response_metadata)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn auth_response_metadata_creates_with_claims() {
        let id = "id-1".to_string();
        let claim = "claim_to_exclude".to_string();
        let mut claims = HashMap::new();
        claims.insert(id.clone(), vec![claim.clone()]);
        let metadata = AuthorizationResponseMetadata::with_excluded_claims(claims);

        assert_eq!(
            metadata.claims_to_exclude.unwrap().get(&id).unwrap()[0],
            claim,
            "Claims does not match"
        )
    }

    #[tokio::test]
    async fn auth_response_metadata_adds_claims_correctly() {
        let id = "id-1".to_string();
        let claim = "claim_to_exclude".to_string();
        let mut metadata = AuthorizationResponseMetadata::default();
        metadata.add_claims_to_exclude(id.clone(), claim.clone());

        assert_eq!(
            metadata.claims_to_exclude.unwrap().get(&id).unwrap()[0],
            claim,
            "Claims does not match"
        )
    }

    #[rstest]
    #[should_panic(
        expected = "vp format = 'jwt_vc_json' with {\"alg_values_supported\":[\"RS256\"]} algorithms is not supported"
    )]
    #[case::request_unsupported_credential_format(request_unsupported_credential_format_case())]
    #[should_panic(
        expected = "vp format = 'dc+sd-jwt' with {\"sd-jwt_alg_values\":[\"RS256\"],\"kb-jwt_alg_values\":[\"RS256\"]} algorithms is not supported"
    )]
    #[case::request_unsupported_credential_alg(request_unsupported_credential_alg_case())]
    #[tokio::test]
    async fn present_credential_auto_fails(#[case] test_case: PresentationTestCase) {
        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;

        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |req| {
                let err: ProtocolError =
                    serde_urlencoded::from_bytes(req.body().as_slice()).unwrap();
                assert_eq!(err.error_type(), &ErrorType::VpFormatsNotSupported);
                assert!(
                    err.description()
                        .clone()
                        .unwrap()
                        .contains("algorithms is not supported")
                );

                let mut response = HttpResponse::new(vec![]);
                *response.status_mut() = StatusCode::OK;

                Ok(response)
            },
            1.into(),
        );

        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn same_device_flow_present_credential_auto_failure_case_returns_redirect_uri_in_error() {
        let mut test_case = request_unsupported_credential_format_case();
        test_case.request.response_mode = ResponseMode::Fragment;

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;

        let holder = holder_service(MockHttpClient::new(), kms, vault).await;

        // Send auth response
        let result = holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await;

        match result {
            Err(Error::Protocol { source }) => {
                assert_eq!(
                    source.redirect_uri().unwrap().to_string(),
                    "http://127.0.0.1:55796/auth#error=vp_formats_not_supported&error_description=vp+format+%3D+%27jwt_vc_json%27+with+%7B%22alg_values_supported%22%3A%5B%22RS256%22%5D%7D+algorithms+is+not+supported"
                );
            }
            _ => panic!("Expected protocol error, got {:?}", result),
        }
    }

    #[rstest]
    #[should_panic]
    #[case::request_unsupported_credential_format_with_state(
        request_unsupported_credential_format_case_with_state()
    )]
    #[should_panic]
    #[case::request_unsupported_credential_alg_with_state(
        request_unsupported_credential_alg_case_with_state()
    )]
    #[tokio::test]
    async fn present_credential_auto_fails_with_state(#[case] test_case: PresentationTestCase) {
        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;

        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |req| {
                let err: ProtocolError =
                    serde_urlencoded::from_bytes(req.body().as_slice()).unwrap();
                assert_eq!(err.state().clone().unwrap(), STATE);

                let mut response = HttpResponse::new(vec![]);
                *response.status_mut() = StatusCode::OK;

                Ok(response)
            },
            1.into(),
        );

        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await
            .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "Please provide the metadata required to generate the ID token")]
    #[case::id_token_metadata_not_declared(siop_id_token_metadata_not_declared_case())]
    #[should_panic(expected = "Key not found for ID: unknown")]
    #[case::invalid_key_metadata(siop_invalid_key_metadata_case())]
    #[tokio::test]
    async fn present_credential_auto_with_siop_fails(#[case] test_case: PresentationTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let mut http_client = MockHttpClient::new();
        test_case.mock_http_auth_response_endpoint(&mut http_client, None);
        let vault = test_case.prepare_vault(&kms).await;

        let holder = holder_service(http_client, kms, vault).await;
        holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn present_credential_with_siop_fails_in_case_of_signer_error() {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let test_case = siop_case(key_metadata.clone());

        let http_client = Arc::new(MockHttpClient::new());
        let key_handle = kms.get(&key_metadata.kid).await.unwrap();

        let mut kms_mock = MockKms::new();
        kms_mock
            .expect_get()
            .returning(move |_| Ok(failed_signer_key(key_handle.clone())));

        let inner = vc::core::HolderService::new(
            kms.clone(),
            InMemVault::new(),
            vc::core::HolderMetadata {
                client_id: "client_id".to_string(),
                pop_lifetime: time::Duration::minutes(5),
            },
            UniversalResolver::default(),
            http_client.clone(),
        );

        let holder = vc::oid4vp::holder::HolderService::new(
            inner,
            http_client,
            kms_mock,
            UniversalResolver::default(),
            None,
            None,
        );

        let key_handle = kms.get(&key_metadata.kid).await.unwrap();
        let credential_mapping = test_case
            .build_credential_mapping((key_metadata.kid, key_handle))
            .await;

        let result = holder
            .present_credentials(
                &test_case.request,
                &credential_mapping,
                &test_case.response_metadata,
            )
            .await;

        assert!(matches!(
            result.err().unwrap(),
            Error::Internal {
                source: InternalError::IdTokenGeneration { .. }
            }
        ));
    }

    #[tokio::test]
    async fn present_credential_with_siop_fails_in_case_of_jwk_error() {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let test_case = siop_case(key_metadata.clone());

        let http_client = Arc::new(MockHttpClient::new());
        let key_handle = kms.get(&key_metadata.kid).await.unwrap();

        let mut kms_mock = MockKms::new();
        kms_mock.expect_get().returning(move |_| Ok(no_jwk_key()));

        let inner = vc::core::HolderService::new(
            kms,
            InMemVault::new(),
            vc::core::HolderMetadata {
                client_id: "client_id".to_string(),
                pop_lifetime: time::Duration::minutes(5),
            },
            UniversalResolver::default(),
            http_client.clone(),
        );

        let holder = crate::vc::oid4vp::holder::HolderService::new(
            inner,
            http_client,
            kms_mock,
            UniversalResolver::default(),
            None,
            None,
        );

        let credential_mapping = test_case
            .build_credential_mapping((key_metadata.kid, key_handle))
            .await;

        let result = holder
            .present_credentials(
                &test_case.request,
                &credential_mapping,
                &test_case.response_metadata,
            )
            .await;

        assert!(matches!(
            result.err().unwrap(),
            Error::Internal {
                source: InternalError::Parse { .. }
            }
        ));
    }

    #[rstest]
    #[case::requested_credential_not_exist_case(requested_credential_not_exist_case())]
    #[should_panic(expected = "matching credentials are not found")]
    #[tokio::test]
    async fn present_credential_auto_fails_when_credentials_are_not_found(
        #[case] test_case: PresentationTestCase,
    ) {
        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |req| {
                let err: ProtocolError =
                    serde_urlencoded::from_bytes(req.body().as_slice()).unwrap();
                assert_eq!(err.error_type(), &ErrorType::AccessDenied);
                assert_eq!(
                    err.description(),
                    &Some("matching credentials are not found".to_owned())
                );

                let mut response = HttpResponse::new(vec![]);
                *response.status_mut() = StatusCode::OK;

                Ok(response)
            },
            1.into(),
        );

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await
            .unwrap();
    }

    #[should_panic(
        expected = "response: status_code=500 Internal Server Error, response_body=Internal Server Error"
    )]
    #[tokio::test]
    async fn present_credential_auto_fails_on_internal_server_error() {
        let test_case = single_presentation::sd_jwt::presentation_test_case();

        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |_| {
                let mut response = HttpResponse::new("Internal Server Error".as_bytes().to_owned());
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                Ok(response)
            },
            1.into(),
        );

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &test_case.response_metadata)
            .await
            .unwrap();
    }

    #[rstest]
    // sd_jwt
    #[case::single_presentation::sd_jwt_single_presentation_success(
        single_presentation::sd_jwt::presentation_test_case()
    )]
    #[case::single_presentation::sd_jwt_single_presentation_with_state_success(
        single_presentation::sd_jwt::presentation_test_case_with_state()
    )]
    #[case::multi_presentation_success(multi_presentation::presentation_test_case())]
    #[case::multi_presentation_with_state_success(
        multi_presentation::presentation_test_case_with_state()
    )]
    #[case::single_presentation::sd_jwt_single_presentation_filter_by_path_success(
        single_presentation::sd_jwt::presentation_test_case_filter_by_path()
    )]
    #[case::single_presentation::sd_jwt_single_presentation_with_filter_by_cred_type_success(
        single_presentation::sd_jwt::presentation_test_case_with_filter_by_cred_type()
    )]
    #[case::single_presentation::sd_jwt_single_presentation_with_filter_by_cred_type_and_email_success(
        single_presentation::sd_jwt::presentation_test_case_with_filter_by_cred_type_and_email()
    )]
    #[case::single_presentation::sd_jwt_single_presentation_with_optional_field_success(
        single_presentation::sd_jwt::presentation_test_case_with_optional_field()
    )]
    #[case::single_presentation::sd_jwt_single_presentation_with_constraints_for_particular_fields_success(
        single_presentation::sd_jwt::presentation_test_case_with_constraints_for_particular_fields(
        )
    )]
    #[case::multi_presentation_filter_by_path_success(
        multi_presentation::presentation_test_case_filter_by_path()
    )]
    #[case::single_presentation::sd_jwt::sd_jwt_single_presentation_with_constraints_with_patterns(
        single_presentation::sd_jwt::presentation_test_case_with_constraints_with_patterns()
    )]
    // json_ld
    #[case::single_presentation::json_ld_single_presentation_success(
        single_presentation::json_ld::presentation_test_case()
    )]
    #[case::single_presentation::json_ld_single_presentation_filter_by_path_success(
        single_presentation::json_ld::presentation_test_case_filter_by_path()
    )]
    #[case::single_presentation::json_ld_single_presentation_with_filter_by_cred_type_success(
        single_presentation::json_ld::presentation_test_case_with_filter_by_cred_type()
    )]
    #[case::single_presentation::json_ld_single_presentation_with_filter_by_cred_type_and_email_success(
        single_presentation::json_ld::presentation_test_case_with_filter_by_cred_type_and_email()
    )]
    #[case::single_presentation::json_ld_single_presentation_with_optional_field_success(
        single_presentation::json_ld::presentation_test_case_with_optional_field()
    )]
    #[case::single_presentation::json_ld_single_presentation_with_constraints_for_particular_fields_success(
        single_presentation::json_ld::presentation_test_case_with_constraints_for_particular_fields(
        )
    )]
    #[case::json_ld::json_ld_single_presentation_with_constraints_with_patterns(
        single_presentation::json_ld::presentation_test_case_with_constraints_with_patterns()
    )]
    #[tokio::test]
    async fn find_credentials_success(#[case] case: PresentationTestCase) {
        let kms = LocalKms::new();
        let vault = case.prepare_vault(&kms).await;
        let holder = holder_service(MockHttpClient::new(), kms, vault).await;

        let credential_mapping = holder
            .find_vcs_for_presentation(&case.request)
            .await
            .unwrap();

        let retrieved_credentials: Vec<Credential> = case
            .request
            .resolved_presentation_query
            .get_presentation_definition()
            .unwrap()
            .input_descriptors()
            .iter()
            .flat_map(|descriptor| {
                let result = credential_mapping.get(&descriptor.id).unwrap();
                match result {
                    CredentialsFindResult::Credentials(creds) => creds,
                    CredentialsFindResult::Reasons(reasons) => {
                        let reasons_str = reasons
                            .iter()
                            .flatten()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(";\n");
                        panic!(
                            "Unexpected VcForPresentationResult type: reasons: {}",
                            reasons_str
                        );
                    }
                }
            })
            .map(|entry| entry.credential.clone())
            .collect();

        let retrieved_credentials_claims: Vec<Claims> = retrieved_credentials
            .iter()
            .filter_map(|credential| match credential {
                Credential::SdJwt(sd_jwt_vc) => {
                    decode_sd_jwt(sd_jwt_vc.to_owned(), SDJWTSerializationFormat::Compact).ok()
                }
                Credential::LdpVc(json_ld_vc) => {
                    serde_json::to_value(json_ld_vc.clone().claims).ok()
                }
                _ => None,
            })
            .map(|c| c.try_into().unwrap())
            .collect();

        assert!(
            !retrieved_credentials_claims.is_empty(),
            "Credentials not found"
        );

        let expected_cred_data = &case.expected_credential_data;

        for expected_claims in expected_cred_data.clone() {
            let claims = retrieved_credentials_claims
                .iter()
                .find(|retrieved_claims| match &case.credential_format {
                    ClaimFormatDesignation::SdJwtVc => {
                        let expected_type = expected_claims["vct"].as_str().unwrap();
                        if let Some(Claim::String(vct)) = retrieved_claims.get("vct") {
                            return expected_type == vct;
                        }
                        true
                    }
                    ClaimFormatDesignation::LdpVc => {
                        let expected_type = expected_claims["type"].as_vec().unwrap();
                        if let Some(Claim::Array(type_)) = &retrieved_claims.get("type") {
                            return expected_type == type_;
                        }
                        true
                    }
                    _ => true,
                });

            if let Some(claim) = claims {
                validate_claims(&case.credential_format, claim, &expected_claims)
            }
        }
    }

    #[rstest]
    // sd_jwt
    #[case::sd_jwt::sd_jwt_presentation_test_case_with_constraints_with_invalid_value_for_pattern(
        single_presentation::sd_jwt::presentation_test_case_with_constraints_with_invalid_value_for_pattern()
    )]
    #[case::sd_jwt::sd_jwt_presentation_test_case_with_constraints_with_invalid_value_for_const(
        single_presentation::sd_jwt::presentation_test_case_with_constraints_with_invalid_value_for_const()
    )]
    #[case::sd_jwt::sd_jwt_presentation_test_case_with_constraints_with_absent_required_claim(
        single_presentation::sd_jwt::presentation_test_case_with_constraints_with_absent_required_claim()
    )]
    // json_ld
    #[case::json_ld::json_ld_presentation_test_case_with_constraints_with_invalid_value_for_pattern_json_ld(
        single_presentation::json_ld::presentation_test_case_with_constraints_with_invalid_value_for_pattern()
    )]
    #[case::json_ld::json_ld_presentation_test_case_with_constraints_with_invalid_value_for_constjson_ld(
        single_presentation::json_ld::presentation_test_case_with_constraints_with_invalid_value_for_const()
    )]
    #[case::json_ld::json_ld_presentation_test_case_with_constraints_with_absent_required_claimjson_ld(
        single_presentation::json_ld::presentation_test_case_with_constraints_with_absent_required_claim()
    )]
    #[tokio::test]
    async fn find_credentials_fails_with_constraints(#[case] case: PresentationTestCase) {
        let kms = LocalKms::new();
        let vault = case.prepare_vault(&kms).await;
        let holder = holder_service(MockHttpClient::new(), kms, vault).await;

        let credential_mapping = holder
            .find_vcs_for_presentation(&case.request)
            .await
            .unwrap();

        let presentation_definition = case
            .request
            .resolved_presentation_query
            .get_presentation_definition()
            .unwrap();

        let input_descriptors = presentation_definition.input_descriptors();

        for id in input_descriptors {
            let result = credential_mapping.get(&id.id).unwrap();
            match result {
                CredentialsFindResult::Credentials(creds) => {
                    panic!(
                        "Unexpected VcForPresentationResult type: creds: {:#?}",
                        creds
                    )
                }
                CredentialsFindResult::Reasons(reasons) => {
                    assert_eq!(reasons.len(), 1);
                    assert_eq!(reasons.first().unwrap().len(), 1);
                }
            }
        }
    }

    #[tokio::test]
    async fn find_credentials_returns_empty_list() {
        let test_case = requested_credential_not_exist_case();
        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms).await;
        let holder = holder_service(MockHttpClient::new(), kms, vault).await;

        let credential_mapping = holder
            .find_vcs_for_presentation(&test_case.request)
            .await
            .unwrap();

        let presentation_definition = test_case
            .request
            .resolved_presentation_query
            .get_presentation_definition()
            .unwrap();
        let input_descriptors = presentation_definition.input_descriptors();

        for id in input_descriptors {
            let result = credential_mapping.get(&id.id).unwrap();
            match result {
                CredentialsFindResult::Credentials(creds) => {
                    panic!(
                        "Unexpected VcForPresentationResult type: credentials: {:#?}",
                        creds
                    )
                }
                CredentialsFindResult::Reasons(reasons) => {
                    assert_eq!(reasons.len(), 1);
                    assert_eq!(reasons[0].len(), 1);
                    assert_eq!(
                        reasons[0][0],
                        FindVCsFailReason::new(
                            vec!["$.vct".to_string()],
                            Some("const".to_string()),
                            Some("https://credentials.example.com/identity_credential".to_string())
                        )
                    );
                }
            }
        }
    }

    #[rstest]
    #[case::single_presentation::sd_jwt(single_presentation::sd_jwt::presentation_test_case())]
    #[case::single_presentation::sd_jwt_with_state(
        single_presentation::sd_jwt::presentation_test_case_with_state()
    )]
    #[case::multi_presentation(multi_presentation::presentation_test_case())]
    #[case::multi_presentation_with_state(multi_presentation::presentation_test_case_with_state())]
    #[tokio::test]
    async fn present_credential_success(#[case] test_case: PresentationTestCase) {
        let mut http_client = MockHttpClient::new();
        test_case.mock_http_auth_response_endpoint(&mut http_client, None);

        let kms = LocalKms::new();
        let key = kms
            .create_and_handle(KeyType::P256, CreateOptions::default())
            .await
            .unwrap();
        let holder = holder_service(http_client, kms, InMemVault::new()).await;
        let credential_mapping = test_case.build_credential_mapping(key).await;

        holder
            .present_credentials(
                &test_case.request,
                &credential_mapping,
                &test_case.response_metadata,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn present_credential_with_siop_success() {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let test_case = siop_case(key_metadata.clone());

        let mut http_client = MockHttpClient::new();
        test_case.mock_http_auth_response_endpoint(&mut http_client, None);

        let key_handle = kms.get(&key_metadata.kid).await.unwrap();
        let holder = holder_service(http_client, kms, InMemVault::new()).await;
        let credential_mapping = test_case
            .build_credential_mapping((key_metadata.kid, key_handle))
            .await;

        holder
            .present_credentials(
                &test_case.request,
                &credential_mapping,
                &test_case.response_metadata,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case::sd_jwt::sd_jwt_present_credential_fails_on_internal_server_error(
        single_presentation::sd_jwt::presentation_test_case()
    )]
    #[case::json_ld::json_ld_present_credential_fails_on_internal_server_error(
        single_presentation::json_ld::presentation_test_case()
    )]
    #[should_panic(
        expected = "response: status_code=500 Internal Server Error, response_body=Internal Server Error"
    )]
    #[tokio::test]
    async fn present_credential_fails_on_internal_server_error(
        #[case] test_case: PresentationTestCase,
    ) {
        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |_| {
                let mut response = HttpResponse::new("Internal Server Error".as_bytes().to_owned());
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                Ok(response)
            },
            1.into(),
        );

        let kms = LocalKms::new();
        let key = kms
            .create_and_handle(KeyType::P256, CreateOptions::default())
            .await
            .unwrap();
        let holder = holder_service(http_client, kms, InMemVault::new()).await;
        let credential_mapping = test_case.build_credential_mapping(key).await;

        holder
            .present_credentials(&test_case.request, &credential_mapping, &Default::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decline_authorization_request_succeeds() {
        let mut http_client = MockHttpClient::new();

        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url("http://127.0.0.1:55796", "/auth"),
            |req| {
                let body = String::from_utf8(req.body().to_owned()).unwrap();

                assert_eq!(
                    body,
                    "error=access_denied&error_description=consent+to+share+the+presentation+is+not+given"
                );

                Ok(HttpResponse::default())
            },
            1.into(),
        );

        let holder = holder_service(http_client, LocalKms::new(), InMemVault::new()).await;

        holder
            .decline_authorization_request(&serde_json::from_str(AUTH_REQUEST).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decline_authorization_request_returns_url_in_same_device_flow() {
        let holder =
            holder_service(MockHttpClient::new(), LocalKms::new(), InMemVault::new()).await;
        let mut auth_req: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(AUTH_REQUEST).unwrap();
        auth_req.insert(
            "response_mode".to_string(),
            serde_json::Value::String("fragment".to_string()),
        );

        let redirect_url = holder
            .decline_authorization_request(
                &serde_json::from_value(serde_json::Value::Object(auth_req)).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            redirect_url.fragment().unwrap(),
            "error=access_denied&error_description=consent+to+share+the+presentation+is+not+given"
        );
    }

    fn siop_case(key_metadata: KeyMetadata) -> PresentationTestCase {
        let mut test_case = single_presentation::sd_jwt::presentation_test_case();
        test_case.request.response_type = ResponseType::VpTokenIdToken;

        test_case.response_metadata.id_token_metadata = Some(IdTokenMetadata {
            key_metadata,
            lifetime: time::Duration::days(1),
        });

        test_case
    }

    fn siop_id_token_metadata_not_declared_case() -> PresentationTestCase {
        let mut test_case = single_presentation::sd_jwt::presentation_test_case();
        test_case.request.response_type = ResponseType::VpTokenIdToken;

        test_case.response_metadata.id_token_metadata = None;

        test_case
    }

    fn siop_invalid_key_metadata_case() -> PresentationTestCase {
        let mut test_case = single_presentation::sd_jwt::presentation_test_case();
        test_case.request.response_type = ResponseType::VpTokenIdToken;

        let key_metadata = KeyMetadata {
            did_url: "did::example::1234".to_string(),
            kid: "unknown".to_string(),
        };
        test_case.response_metadata.id_token_metadata = Some(IdTokenMetadata {
            key_metadata,
            lifetime: time::Duration::days(1),
        });

        test_case
    }

    fn requested_credential_not_exist_case() -> PresentationTestCase {
        let mut test_case = single_presentation::sd_jwt::presentation_test_case();
        test_case.credential_data = vec![
            json!({
                "vct": "https://credentials.example.com/degree_credential",
                "name": "John",
                "degree": "Bachelor"
            })
            .try_into()
            .unwrap(),
        ];
        test_case
    }

    fn request_unsupported_credential_format_case() -> PresentationTestCase {
        let test_case = single_presentation::sd_jwt::presentation_test_case();
        let cred_format: ClaimFormatMap = serde_json::from_value(json!({
            "jwt_vc_json":{
                "alg_values_supported":[
                    "RS256"
                ]
            }
        }))
        .unwrap();

        update_claim_format(test_case, cred_format)
    }

    fn request_unsupported_credential_format_case_with_state() -> PresentationTestCase {
        let test_case = single_presentation::sd_jwt::presentation_test_case_with_state();
        let cred_format: ClaimFormatMap = serde_json::from_value(json!({
            "jwt_vc_json":{
                "alg_values_supported":[
                    "RS256"
                ]
            }
        }))
        .unwrap();

        update_claim_format(test_case, cred_format)
    }

    fn request_unsupported_credential_alg_case() -> PresentationTestCase {
        let test_case = single_presentation::sd_jwt::presentation_test_case();
        let cred_format: ClaimFormatMap = serde_json::from_value(json!({
            "dc+sd-jwt":{
                "sd-jwt_alg_values": ["RS256"],
                "kb-jwt_alg_values": ["RS256"],
            }
        }))
        .unwrap();

        update_claim_format(test_case, cred_format)
    }

    fn request_unsupported_credential_alg_case_with_state() -> PresentationTestCase {
        let test_case = single_presentation::sd_jwt::presentation_test_case_with_state();
        let cred_format: ClaimFormatMap = serde_json::from_value(json!({
            "dc+sd-jwt":{
                "sd-jwt_alg_values": ["RS256"],
                "kb-jwt_alg_values": ["RS256"],
            }
        }))
        .unwrap();

        update_claim_format(test_case, cred_format)
    }

    fn update_claim_format(
        mut test_case: PresentationTestCase,
        cred_format: ClaimFormatMap,
    ) -> PresentationTestCase {
        let mut input_desc = test_case
            .request
            .resolved_presentation_query
            .get_presentation_definition()
            .unwrap()
            .input_descriptors()
            .clone();
        if let Some(i) = input_desc.get_mut(0) {
            *i = i.to_owned().set_format(cred_format)
        }

        let mut pd = test_case
            .request
            .resolved_presentation_query
            .get_presentation_definition()
            .unwrap()
            .clone();
        pd.input_descriptors_mut().clear();
        pd.input_descriptors_mut().append(&mut input_desc);
        test_case.request.resolved_presentation_query =
            ResolvedPresentationQuery::PresentationDefinition(pd);

        test_case
    }
}
