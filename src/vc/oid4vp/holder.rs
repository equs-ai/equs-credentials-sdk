use crate::did::DIDResolver;
use crate::http::HttpClient;
use crate::vc;
use crate::vc::core::PresentationInput;
use crate::vc::oid4vp::internal_error::{
    AuthorizationRequestSnafu, AuthorizationResponseSnafu, JsonSnafu, ParseSnafu,
    PresentationExchangeSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vp::metadata::default_wallet_metadata;
use crate::vc::oid4vp::{AuthorizationResponseMetadata, CredentialMapping, ResolvedAuthRequest};
use crate::vc::presentation_exchange::{PresentationResponse, RequestedPresentation};
use crate::vc::{oid4vp as api, presentation_exchange};
use anyhow::bail;
use async_trait::async_trait;
use futures::future;
use oid4vp::core::authorization_request::parameters::ClientMetadata;
use oid4vp::core::authorization_request::verification::RequestVerification;
use oid4vp::core::authorization_request::AuthorizationRequestObject;
use oid4vp::core::credential_format::CoreCredentialFormat;
use oid4vp::core::metadata::parameters::verifier::VpFormats;
use oid4vp::core::metadata::WalletMetadata;
use oid4vp::core::object::{ParsingErrorContext, UntypedObject};
use oid4vp::core::profile;
use oid4vp::core::profile::Wallet;
use oid4vp::core::response::parameters::{
    PresentationSubmission as PresentationSubmissionParam, VpToken,
};
use oid4vp::core::response::AuthorizationResponse;
use snafu::ResultExt;
use tracing::{info, instrument, Level};
use url::Url;

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

pub struct HolderService<HL, D, HC>
where
    HL: vc::core::Holder,
    D: DIDResolver,
{
    holder: HL,
    did_resolver: D,
    metadata: WalletMetadata,
    http_client: HC,
}

impl<HL, D, HC> HolderService<HL, D, HC>
where
    HL: vc::core::Holder,
    D: DIDResolver,
    HC: HttpClient,
{
    #[instrument(
        level = Level::TRACE,
        skip(holder, did_resolver, http_client),
    )]
    pub fn new(
        holder: HL,
        did_resolver: D,
        metadata: Option<WalletMetadata>,
        http_client: HC,
    ) -> Self {
        let metadata = metadata.unwrap_or(default_wallet_metadata());

        info!("oid4vp-holder service is initialized");

        Self {
            holder,
            metadata,
            did_resolver,
            http_client,
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn submit_presentation(
        &self,
        presentations: Vec<RequestedPresentation>,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<Option<Url>> {
        let presentation_response = presentation_exchange::prepare_presentation_response(
            &presentations,
            &auth_request.presentation_definition,
        )
        .context(PresentationExchangeSnafu)?;
        let auth_resp = Self::create_auth_response(presentation_response)?;

        let redirect_url = self
            .submit_response(
                &auth_request.response_uri,
                &auth_request.response_mode,
                auth_resp,
                |req| self.http_client.async_call(req),
            )
            .await
            .map_err(|e| {
                AuthorizationResponseSnafu {
                    details: format!("Could not submit Authorization Response: {e}"),
                }
                .build()
            })?;

        Ok(redirect_url)
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
    )]
    fn create_auth_response(
        presentation_response: PresentationResponse,
    ) -> Result<AuthorizationResponse> {
        let mut response_params = UntypedObject::default();

        let vp_token =
            serde_json::to_string(&presentation_response.presentations).context(JsonSnafu)?;
        response_params.insert(VpToken(vp_token));

        let pres_sub_json = serde_json::to_value(&presentation_response.presentation_submission)
            .context(JsonSnafu)?;
        response_params.insert(PresentationSubmissionParam(pres_sub_json));

        let auth_resp = AuthorizationResponse::try_from(response_params).map_err(|e| {
            ParseSnafu {
                details: format!("Cannot parse Authorization Response: {e}"),
            }
            .build()
        })?;

        Ok(auth_resp)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn create_presentation_by_input(
        &self,
        presentation_input: &PresentationInput,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<RequestedPresentation> {
        let credentials = self
            .holder
            .find_vcs_for_presentation(presentation_input)
            .await
            .context(VCSnafu)?;

        let first_credential = credentials.first().ok_or_else(|| {
            AuthorizationResponseSnafu {
                details: "Empty credentials list",
            }
            .build()
        })?;

        let presentation = self
            .holder
            .create_presentation(
                auth_request.nonce.0.as_str(),
                auth_request.client_id.as_str(),
                presentation_input,
                first_credential,
            )
            .await
            .context(VCSnafu)?;

        Ok(RequestedPresentation {
            id: presentation_input.id.to_owned(),
            presentation,
        })
    }
}

#[async_trait]
impl<HL, D, HC> api::Holder for HolderService<HL, D, HC>
where
    HL: vc::core::Holder,
    D: DIDResolver,
    HC: HttpClient,
{
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn get_authorization_request(&self, auth_req_uri: &str) -> Result<ResolvedAuthRequest> {
        let url = Url::parse(auth_req_uri).context(UrlParseSnafu)?;
        let aro = self
            .handle_request(&url, |req| self.http_client.async_call(req))
            .await
            .context(AuthorizationRequestSnafu)?;

        let pres_def = aro
            .resolve_presentation_definition(|req| self.http_client.async_call(req))
            .await
            .context(AuthorizationRequestSnafu)?
            .parsed()
            .to_owned();

        Ok(ResolvedAuthRequest {
            client_id: aro.client_id().0.to_owned(),
            presentation_definition: pres_def,
            nonce: aro.nonce().clone(),
            response_mode: aro.response_mode().to_owned(),
            response_uri: aro.return_uri().to_owned(),
        })
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        _: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>> {
        info!("presenting verifiable presentation is started");

        let presentation_inputs =
            presentation_exchange::split_to_inputs(&auth_request.presentation_definition)
                .context(PresentationExchangeSnafu)?;

        let presentations: Vec<RequestedPresentation> =
            future::try_join_all(presentation_inputs.iter().map(|presentation_input| {
                self.create_presentation_by_input(presentation_input, auth_request)
            }))
            .await?;

        let redirect_url = self
            .submit_presentation(presentations, auth_request)
            .await?;

        info!("verifiable presentations are successfully presented");

        Ok(redirect_url)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn find_vcs_for_presentation(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<CredentialMapping> {
        let mut creds_map = CredentialMapping::new();

        let presentation_inputs =
            presentation_exchange::split_to_inputs(&auth_request.presentation_definition)
                .context(PresentationExchangeSnafu)?;
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        creds_map: &CredentialMapping,
        _: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>> {
        info!("presenting verifiable presentations is started");

        let mut presentaions: Vec<RequestedPresentation> = vec![];

        let presentation_inputs =
            presentation_exchange::split_to_inputs(&auth_request.presentation_definition)
                .context(PresentationExchangeSnafu)?;

        // TODO: Improve code:
        //  - Run async code concurrently
        //  - Try to refactor the loop below, possibly by extracting it into a map operation
        //  - Try to reuse [self.create_presentation_by_input]
        for presentation_input in presentation_inputs.iter() {
            if let Some(credentials) = creds_map.get(&presentation_input.id) {
                for credential in credentials.iter() {
                    let presentation = self
                        .holder
                        .create_presentation(
                            auth_request.nonce.0.as_str(),
                            auth_request.client_id.as_str(),
                            presentation_input,
                            credential,
                        )
                        .await
                        .context(VCSnafu)?;

                    presentaions.push(RequestedPresentation {
                        id: presentation_input.id.to_owned(),
                        presentation,
                    });
                }
            } else {
                //TODO Implement cases when credentials not found
            }
        }

        let redirect_url = self.submit_presentation(presentaions, auth_request).await?;

        info!("verifiable presentations are successfully presented");

        Ok(redirect_url)
    }
}

#[async_trait]
impl<HL, D, HC> profile::Profile for HolderService<HL, D, HC>
where
    HL: vc::core::Holder,
    D: DIDResolver,
    HC: HttpClient,
{
    type CredentialFormat = CoreCredentialFormat;

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn validate_request(
        &self,
        wallet_metadata: &WalletMetadata,
        request_object: &AuthorizationRequestObject,
    ) -> anyhow::Result<()> {
        if request_object.get::<ClientMetadata>().is_none() {
            return Ok(());
        }

        let client_metadata =
            ClientMetadata::resolve(request_object, |req| self.http_client.async_call(req))
                .await
                .parsing_error()?;

        if let Some(Ok(vp_formats)) = client_metadata.0.get::<VpFormats>() {
            let unsupported = vp_formats
                .0
                .keys()
                .find(|k| !wallet_metadata.vp_formats_supported().0.contains_key(*k));
            if let Some(format) = unsupported {
                bail!("VP format not supported");
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<HL, D, HC> Wallet for HolderService<HL, D, HC>
where
    HL: vc::core::Holder,
    D: DIDResolver,
    HC: HttpClient,
{
    fn wallet_metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[async_trait]
impl<HL, D, HC> RequestVerification for HolderService<HL, D, HC>
where
    HL: vc::core::Holder,
    D: DIDResolver,
    HC: HttpClient,
{
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        let (header, _) = ssi::jws::decode_unverified(&request_jwt)?;

        let kid = header.key_id.ok_or(
            ParseSnafu {
                details: "Could not parse kid from Request Object JWT".to_owned(),
            }
            .build(),
        )?;
        let ver_map = self
            .did_resolver
            .resolve_verification_method(kid.as_str())
            .await?;
        let verifier_pub_jwk = &ver_map.public_key_jwk.ok_or(
            ParseSnafu {
                details: "Could not parse Verifier's public JWK from Verification Method's Map"
                    .to_owned(),
            }
            .build(),
        )?;

        ssi::jws::decode_verify(&request_jwt, verifier_pub_jwk)?;

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn entity_id(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Alg;
    use crate::http::{HttpClient, MockHttpClient};
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::{CreateOptions, KeyType, Kms};
    use crate::utils::http::test::mock_http_fn;
    use crate::vault::Vault;
    use crate::vc::oid4vp::Holder;
    use crate::vc::oid4vp::{AuthorizationResponseMetadata, HolderBuilder};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};
    use oauth2::http::header::CONTENT_TYPE;
    use oauth2::http::{HeaderMap, HeaderValue, Method, StatusCode};
    use oauth2::HttpResponse;
    use url::Url;

    const REQUEST_OBJECT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVhZ3ZXMmVEV2MyeVZ3N0I5OG92Y0o4amRkbjdUOU1oM3k1VmlreXM2eTRrWCN6RG5hZWFndlcyZURXYzJ5Vnc3Qjk4b3ZjSjhqZGRuN1Q5TWgzeTVWaWt5czZ5NGtYIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vMTI3LjAuMC4xOjU1Nzk2L2F1dGgiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6Im4wTmNFIiwiY2xpZW50X21ldGFkYXRhIjp7InZwX2Zvcm1hdHMiOnsidmMrc2Qtand0Ijp7ImFsZyI6WyJFZERTQSIsIkVTMjU2Il19fX0sInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMWI5ZDZiY2QtYmJmZC00YjJkLTliNWQtYWI4ZGZiYmQ0YmVkIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NksiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Y3QiXSwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJjb25zdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCJ9fSx7InBhdGgiOlsiJC5uYW1lIl19XX19XX0sImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVhZ3ZXMmVEV2MyeVZ3N0I5OG92Y0o4amRkbjdUOU1oM3k1VmlreXM2eTRrWCIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQifQ.RlrD5ibioAvM_S0QAhdPK--9WyLEw258cMduAn26S1puXIxKgJod9gt00FDrK0x-jdPmkuPdpJWKzg3kcimIVQ";
    const REQUEST_URI: &str = "openid4vp://?client_id=did%3Akey%3AzDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX&request_uri=http%3A%2F%2F127.0.0.1%3A55796%2Frequest";
    const CLIENT_ID: &str = "wallet-dev";
    const CRED_JWT: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiSDQyTEp5b1JtWFhybktOUUZDWFcxb3BnRURtZ05hUFlsLUVyV3lxWkNXNCIsIlVOd19fd3hQSzdIbWk3LVZvdjBpaUZvc2Y2bUFCNlM2MzdTd3BqdlRWbDgiLCJlX2NaMVFCSGV4Z3ZBUUdfOF9BdkVNX3U4amJfTi1MOVFTdXdaMkhKVTFFIl0sInZjdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCIsImRhdGUiOiIwOS8wOS8xOTg5Iiwic3ViIjoiZGlkOmtleTp6RG5hZWRTWUZWcVpqc3NyckxjamRCWVBHR0RTMm92U3JvRWl5ZFVQOHNEQk5lN3lDIiwibmJmIjoxNzI0MzcyNTY4LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWVWZUFYdGRneExab0d4VkFNUEZUN0pBZGhpUFZXckNxeVJiNVJzVWFnU0NVZSIsImlhdCI6MTcyNDM3MjU2OCwiZXhwIjoxNzU1OTA4NTY4LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1UxNWZwa3F3bDdxV3RKV2tZUmJmQTlMQ0Z3SFJKX21yQkJhOXEyU0ZPcyIsInkiOiJUaFBhVHZTQW9mdUYtNFpzbjg2RllHRGtLTHZhd2Z3TXlLZmc5bTJJaTlnIn19fQ.s_s2RV6dHjW4JnwlYozGgrTvrjcr7E1BTutHI8OgP9jDjwIH9sM17339QwZrONY_QkcRiCBpIEVK-9OPESNqQg~WyJFR0lvZ0d2UVY5c0liZzlDSW1KU0Z3IiwgIm5hbWUiLCAiSm9obiJd~WyJxZTZoTjMyVFFyY09CYWVWSERpcE1nIiwgInN1cm5hbWUiLCAiRG9lIl0~WyJtUzRuS2FHMjRXdVdpMTlaWHB6VG5RIiwgImFkZHJlc3MiLCAiMjIxQiBCYWtlciBTdHJlZXQiXQ~";
    const VERIFIER_URL: &str = "http://127.0.0.1:55796";

    #[tokio::test]
    async fn e2e() {
        let mut http_client = MockHttpClient::new();

        // Mock request while Holder tries to get Authorization request Object
        mock_get_request_object_call(&mut http_client);
        // Mock request while Holder tries to send Authorization Response
        mock_send_authorization_response_call(&mut http_client);

        let kms = LocalKms::new();
        let kid = kms.create(KeyType::P256, CreateOptions {}).await.unwrap();

        let vault = InMemVault::new();

        let cred_meta = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid,
            format: VCFormat::SdJwtVc,
            alg: Some(Alg::ES256),
            tags: vec![],
        };

        let res = vault
            .store_credential(Credential::SdJwt(CRED_JWT.to_string()), &cred_meta)
            .await;
        assert!(res.is_ok());

        let holder = oid4vp_holder(http_client, vault, kms).await;
        // Handle request object
        let request_obj = holder.get_authorization_request(REQUEST_URI).await.unwrap();
        // Send auth response
        holder
            .present_credentials_auto(&request_obj, &AuthorizationResponseMetadata {})
            .await
            .unwrap();
    }

    fn mock_get_request_object_call(http_client: &mut MockHttpClient) {
        mock_http_fn(
            http_client,
            Method::GET,
            Url::parse(VERIFIER_URL).unwrap().join("/request").unwrap(),
            |req| {
                let resp = HttpResponse {
                    status_code: StatusCode::OK,
                    headers: HeaderMap::from_iter(vec![(
                        CONTENT_TYPE,
                        HeaderValue::from_str("text/plain").unwrap(),
                    )]),
                    body: Vec::from(REQUEST_OBJECT),
                };

                Ok(resp)
            },
            1.into(),
        );
    }

    fn mock_send_authorization_response_call(http_client: &mut MockHttpClient) {
        mock_http_fn(
            http_client,
            Method::POST,
            Url::parse(VERIFIER_URL).unwrap().join("/auth").unwrap(),
            |req| {
                Ok(HttpResponse {
                    status_code: StatusCode::OK,
                    headers: Default::default(),
                    body: vec![],
                })
            },
            1.into(),
        );
    }

    async fn oid4vp_holder(
        http_client: impl HttpClient,
        vault: InMemVault,
        kms: LocalKms,
    ) -> impl Holder {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .https_only(false)
            .build()
            .unwrap();

        HolderBuilder::new(kms, vault, CLIENT_ID.to_owned())
            .with_http_client(http_client)
            .build()
            .await
            .unwrap()
    }
}
