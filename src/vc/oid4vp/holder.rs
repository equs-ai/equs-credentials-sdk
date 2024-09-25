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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret()
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
        ret(),
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
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::{CreateOptions, KeyType, Kms};
    use crate::utils::http::test::mock_http_fn_with_plain_text_resp;
    use crate::vc;
    use crate::vc::oid4vp::tests::fixtures::{
        multi_presentation, single_presentation, REQUEST_URI, VERIFIER_URL,
    };
    use crate::vc::oid4vp::tests::utils::{
        build_url, holder_service, validate_claims, PresentationTestCase,
    };
    use crate::vc::oid4vp::{AuthorizationResponseMetadata, Holder};
    use crate::vc::{Claims, Credential};
    use oauth2::http::Method;
    use rstest::rstest;
    use sd_jwt_rs::utils::decode_sd_jwt;
    use sd_jwt_rs::SDJWTSerializationFormat;

    #[tokio::test]
    async fn get_auth_request_success() {
        let mut http_client = MockHttpClient::new();
        mock_http_fn_with_plain_text_resp(
            &mut http_client,
            Method::GET,
            build_url(VERIFIER_URL, "request"),
            single_presentation::AUTH_REQUEST_JWT,
            1.into(),
        );
        let holder = holder_service(http_client, LocalKms::new(), InMemVault::new()).await;

        // Get request object
        let request_obj = holder.get_authorization_request(REQUEST_URI).await.unwrap();

        assert_eq!(
            serde_json::to_value(&request_obj).unwrap(),
            single_presentation::AUTH_REQUEST
                .parse::<serde_json::Value>()
                .unwrap()
        );
    }

    #[rstest]
    #[case::single_presentation(single_presentation_case(), false)]
    #[case::single_presentation_with_extra_credentials(single_presentation_case(), true)]
    #[case::multiple_presentation(multiple_presentation_case(), false)]
    #[case::multiple_presentation_with_extra_credentials(multiple_presentation_case(), true)]
    #[tokio::test]
    async fn present_credential_auto_correctly(
        #[case] test_case: PresentationTestCase,
        #[case] with_extra_creds: bool,
    ) {
        let mut http_client = MockHttpClient::new();
        test_case.mock_http_auth_response_endpoint(&mut http_client);

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms, with_extra_creds).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &AuthorizationResponseMetadata {})
            .await
            .unwrap();
    }

    #[rstest]
    #[case::single_presentation(single_presentation_case(), false)]
    #[case::single_presentation_with_extra_credentials(single_presentation_case(), true)]
    #[case::multiple_presentation(multiple_presentation_case(), false)]
    #[case::multiple_presentation_with_extra_credentials(multiple_presentation_case(), true)]
    #[tokio::test]
    async fn find_credentials_success(
        #[case] test_case: PresentationTestCase,
        #[case] with_extra_creds: bool,
    ) {
        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms, with_extra_creds).await;
        let holder = holder_service(MockHttpClient::new(), kms, vault).await;

        let credential_mapping = holder
            .find_vcs_for_presentation(&test_case.request)
            .await
            .unwrap();

        let retrieved_credentials: Vec<vc::Credential> = test_case
            .request
            .presentation_definition
            .input_descriptors
            .iter()
            .flat_map(|descriptor| credential_mapping.get(&descriptor.id).unwrap().clone())
            .map(|entry| entry.credential)
            .collect();

        let retrieved_credentials_claims: Vec<Claims> = retrieved_credentials
            .iter()
            .filter_map(|credential| match credential {
                Credential::SdJwt(sd_jwt_vc) => {
                    decode_sd_jwt(sd_jwt_vc.to_owned(), SDJWTSerializationFormat::Compact).ok()
                }
                _ => None,
            })
            .collect();

        let mut cred_data = test_case.credential_data;
        if with_extra_creds {
            cred_data.extend(cred_data.clone())
        }

        for claims in retrieved_credentials_claims {
            let index = cred_data
                .iter()
                .enumerate()
                .find(|(_, (type_, _))| *type_ == claims["vct"])
                .unwrap()
                .0;
            validate_claims(&claims, &cred_data.remove(index));
        }
    }

    #[rstest]
    #[case::single_presentation(single_presentation_case())]
    #[case::multiple_presentation(multiple_presentation_case())]
    #[tokio::test]
    async fn present_credential_correctly(#[case] test_case: PresentationTestCase) {
        let mut http_client = MockHttpClient::new();
        test_case.mock_http_auth_response_endpoint(&mut http_client);

        let kms = LocalKms::new();
        let key = kms
            .create_and_handle(KeyType::P256, CreateOptions {})
            .await
            .unwrap();
        let holder = holder_service(http_client, kms, InMemVault::new()).await;
        let credential_mapping = test_case.build_credential_mapping(key).await;

        holder
            .present_credentials(
                &test_case.request,
                &credential_mapping,
                &AuthorizationResponseMetadata {},
            )
            .await
            .unwrap();
    }

    fn single_presentation_case() -> PresentationTestCase {
        PresentationTestCase {
            request: single_presentation::auth_request(),
            credential_data: single_presentation::credential_data(),
            presentation_submission: single_presentation::presentation_submission(),
        }
    }

    fn single_presentation_several_creds_case() -> PresentationTestCase {
        PresentationTestCase {
            request: single_presentation::auth_request(),
            credential_data: single_presentation::credential_data(),
            presentation_submission: single_presentation::presentation_submission(),
        }
    }

    fn multiple_presentation_case() -> PresentationTestCase {
        PresentationTestCase {
            request: multi_presentation::auth_request(),
            credential_data: multi_presentation::credential_data(),
            presentation_submission: multi_presentation::presentation_submission(),
        }
    }
}
