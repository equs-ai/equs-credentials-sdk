use crate::did::DIDResolver;
use crate::http::HttpClient;
use crate::nonce::Nonce;
use crate::utils::http::MimeType;
use crate::vc::core::PresentationInput;
use crate::vc::oid4vp::internal_error::{
    AuthorizationResponseSnafu, CredentialNotFoundSnafu, HttpClientSnafu, JsonSnafu,
    PresentationExchangeSnafu, VCSnafu,
};
use crate::vc::oid4vp::metadata::default_wallet_metadata;
use crate::vc::oid4vp::{
    AuthorizationResponseMetadata, CredentialMapping, ProtocolError, ResolvedAuthRequest,
};
use crate::vc::presentation_exchange::{PresentationResponse, RequestedPresentation};
use crate::vc::{oid4vp as api, presentation_exchange};
use crate::{utils, vc};
use async_trait::async_trait;
use futures::future;
use oid4vp::core::authorization_request::verification::{did, RequestVerifier};
use oid4vp::core::authorization_request::{AuthorizationRequest, AuthorizationRequestObject};
use oid4vp::core::error::ErrorType;
use oid4vp::core::metadata::WalletMetadata;
use oid4vp::core::object::UntypedObject;
use oid4vp::core::response::parameters::{PresentationSubmission, VpToken};
use oid4vp::core::response::{AuthorizationResponse, UnencodedAuthorizationResponse};
use oid4vp::wallet::Wallet;
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
            .await?;

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
        let vp_token = VpToken::try_from(presentation_response.presentations)
            .context(AuthorizationResponseSnafu)?;

        let pres_sub_json = serde_json::to_value(&presentation_response.presentation_submission)
            .context(JsonSnafu)?;

        let pres_sub =
            PresentationSubmission::try_from(pres_sub_json).context(AuthorizationResponseSnafu)?;

        let auth_resp = AuthorizationResponse::Unencoded(UnencodedAuthorizationResponse(
            UntypedObject::default(),
            vp_token,
            pres_sub,
        ));

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

        if credentials.is_empty() {
            info!("matching credentials are not found, sending an authorization error response to the verifier...");
            let err = ProtocolError::new(
                ErrorType::AccessDenied,
                Some("matching credentials are not found".to_owned()),
            );
            self.submit_auth_error_resp(&auth_request.response_uri, &err)
                .await?;
        }

        let first_credential = credentials.first().ok_or_else(|| {
            CredentialNotFoundSnafu {
                type_: &presentation_input.type_,
                format: &presentation_input.format.name(),
            }
            .build()
        })?;

        let presentation = self
            .holder
            .create_presentation(
                &auth_request.nonce,
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn resolve_auth_resp_endpoint(&self, request_uri: &Url) -> Result<Url> {
        let auth_req =
            AuthorizationRequest::from_url(request_uri, &self.metadata.authorization_endpoint().0)?;

        let url = auth_req
            .resolve_response_uri(|req| self.http_client.async_call(req))
            .await?;

        Ok(url)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn submit_auth_error_resp(&self, response_uri: &Url, body: &ProtocolError) -> Result<()> {
        let body = serde_json::to_vec(body).context(JsonSnafu)?;
        let req = utils::http::generate_post_req(response_uri, MimeType::AppFormUrlEnc, body);

        let _ = self
            .http_client
            .async_call(req)
            .await
            .context(HttpClientSnafu)?;

        info!("authorization error response is sent to verifier");

        Ok(())
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
    async fn get_authorization_request(&self, request_uri: &Url) -> Result<ResolvedAuthRequest> {
        let aro_result = self
            .validate_request(request_uri, |req| self.http_client.async_call(req))
            .await
            .map_err(Error::from);

        let aro = match aro_result {
            Ok(aro) => aro,
            Err(Error::Protocol { source: body }) => {
                let response_uri = self.resolve_auth_resp_endpoint(request_uri).await?;

                info!("authorization request validation is failed, sending an authorization error response to the verifier...");
                self.submit_auth_error_resp(&response_uri, &body).await?;

                return Err(Error::Protocol { source: body });
            }
            Err(e) => return Err(e),
        };

        let pres_def = aro
            .resolve_presentation_definition(|req| self.http_client.async_call(req))
            .await?
            .parsed()
            .to_owned();

        Ok(ResolvedAuthRequest {
            client_id: aro.client_id().0.to_owned(),
            presentation_definition: pres_def,
            nonce: Nonce(aro.nonce().to_owned().into()),
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
                            &auth_request.nonce,
                            &auth_request.client_id,
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn decline_authorization_request(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<()> {
        info!("presentation request is declined, sending an authorization error response to the verifier...");
        let err = ProtocolError::new(
            ErrorType::AccessDenied,
            Some("consent to share the presentation is not given".to_owned()),
        );
        let _ = self
            .submit_auth_error_resp(&auth_request.response_uri, &err)
            .await?;

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
    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[async_trait]
impl<HL, D, HC> RequestVerifier for HolderService<HL, D, HC>
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
    ) -> anyhow::Result<(), oid4vp::core::error::Error> {
        did::verify_with_resolver(
            self.metadata(),
            decoded_request,
            request_jwt,
            None,
            self.did_resolver.as_spruce_resolver(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::{CreateOptions, KeyType, Kms};
    use crate::utils::http::test::{mock_http_fn, mock_http_fn_with_plain_text_resp};
    use crate::vc;
    use crate::vc::oid4vp::protocol_error::ErrorType;
    use crate::vc::oid4vp::tests::fixtures::{
        multi_presentation, single_presentation, REQUEST_URI, VERIFIER_URL,
    };
    use crate::vc::oid4vp::tests::utils::{
        build_url, holder_service, validate_claims, PresentationTestCase,
    };
    use crate::vc::oid4vp::{AuthorizationResponseMetadata, Holder, ProtocolError};
    use crate::vc::presentation_exchange::ClaimFormatMap;
    use crate::vc::{Claims, Credential};
    use oauth2::http::Method;
    use oauth2::HttpResponse;
    use reqwest::StatusCode;
    use rstest::rstest;
    use sd_jwt_rs::utils::decode_sd_jwt;
    use sd_jwt_rs::SDJWTSerializationFormat;
    use serde_json::json;

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
        let request_obj = holder
            .get_authorization_request(&REQUEST_URI.parse().unwrap())
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(&request_obj).unwrap(),
            single_presentation::AUTH_REQUEST
                .parse::<serde_json::Value>()
                .unwrap()
        );
    }

    #[rstest]
    #[case::single_presentation_success(single_presentation::presentation_test_case(), false)]
    #[case::single_presentation_with_extra_credentials_success(
        single_presentation::presentation_test_case(),
        true
    )]
    #[case::multi_presentation_success(multi_presentation::presentation_test_case(), false)]
    #[case::multi_presentation_with_extra_credentials_success(
        multi_presentation::presentation_test_case(),
        true
    )]
    #[tokio::test]
    async fn present_credential_auto_success(
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
    // TODO: Should not submit empty presentation response, implemented as part of the ASDK-98 task
    #[ignore]
    #[should_panic]
    #[case::empty_input_descriptor(empty_input_descriptor_case(), false)]
    #[should_panic(expected = "Unsupported format: jwt_vc_json")]
    #[case::request_unsupported_credential_format(
        request_unsupported_credential_format_case(),
        false
    )]
    // TODO: Validations will be implemented as part of the ASDK-98 task
    #[ignore]
    #[should_panic]
    #[case::request_unsupported_credential_alg(request_unsupported_credential_alg_case(), false)]
    #[tokio::test]
    async fn present_credential_auto_fails(
        #[case] test_case: PresentationTestCase,
        #[case] with_extra_creds: bool,
    ) {
        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms, with_extra_creds).await;
        let holder = holder_service(MockHttpClient::new(), kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &AuthorizationResponseMetadata {})
            .await
            .unwrap();
    }

    #[should_panic(
        expected = "Credential of Type 'https://credentials.example.com/identity_credential' and Format 'vc+sd-jwt' not found"
    )]
    #[tokio::test]
    async fn present_credential_auto_fails_when_credentials_are_not_found() {
        let test_case = requested_credential_not_exist_case();

        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |req| {
                let err: ProtocolError = serde_json::from_slice(req.body.as_slice()).unwrap();
                assert_eq!(err.error_type(), &ErrorType::AccessDenied);
                assert_eq!(
                    err.description(),
                    &Some("matching credentials are not found".to_owned())
                );
                Ok(HttpResponse {
                    status_code: StatusCode::OK,
                    headers: Default::default(),
                    body: vec![],
                })
            },
            1.into(),
        );

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms, false).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &AuthorizationResponseMetadata {})
            .await
            .unwrap();
    }

    #[should_panic(
        expected = "response: status_code=500 Internal Server Error, response_body=Internal Server Error"
    )]
    #[tokio::test]
    async fn present_credential_auto_fails_on_internal_server_error() {
        let test_case = single_presentation::presentation_test_case();

        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |_| {
                Ok(HttpResponse {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    headers: Default::default(),
                    body: "Internal Server Error".as_bytes().to_owned(),
                })
            },
            1.into(),
        );

        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms, false).await;
        let holder = holder_service(http_client, kms, vault).await;

        // Send auth response
        holder
            .present_credentials_auto(&test_case.request, &AuthorizationResponseMetadata {})
            .await
            .unwrap();
    }

    #[rstest]
    #[case::single_presentation_success(single_presentation::presentation_test_case(), false)]
    #[case::single_presentation_with_extra_credentials_success(
        single_presentation::presentation_test_case(),
        true
    )]
    #[case::multi_presentation_success(multi_presentation::presentation_test_case(), false)]
    #[case::multi_presentation_with_extra_credentials_success(
        multi_presentation::presentation_test_case(),
        true
    )]
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

        let retrieved_credentials: Vec<Credential> = test_case
            .request
            .presentation_definition
            .input_descriptors()
            .iter()
            .flat_map(|descriptor| credential_mapping.get(descriptor.id()).unwrap().clone())
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

        assert!(
            !retrieved_credentials_claims.is_empty(),
            "Credentials not found"
        );

        // TODO: Should also validate extra credentials
        for (expected_type, expected_claims) in cred_data {
            let claims = retrieved_credentials_claims
                .iter()
                .find(|retrieved_claims| *expected_type == retrieved_claims["vct"])
                .unwrap();

            validate_claims(claims, &(expected_type, expected_claims));
        }
    }

    #[tokio::test]
    async fn find_credentials_returns_empty_list() {
        let test_case = requested_credential_not_exist_case();
        let kms = LocalKms::new();
        let vault = test_case.prepare_vault(&kms, false).await;
        let holder = holder_service(MockHttpClient::new(), kms, vault).await;

        let credential_mapping = holder
            .find_vcs_for_presentation(&test_case.request)
            .await
            .unwrap();

        let retrieved_credentials: Vec<vc::Credential> = test_case
            .request
            .presentation_definition
            .input_descriptors()
            .iter()
            .flat_map(|descriptor| credential_mapping.get(descriptor.id()).unwrap().clone())
            .map(|entry| entry.credential)
            .collect();

        assert!(retrieved_credentials.is_empty());
    }

    #[rstest]
    #[case::single_presentation(single_presentation::presentation_test_case())]
    #[case::multi_presentation(multi_presentation::presentation_test_case())]
    #[tokio::test]
    async fn present_credential_success(#[case] test_case: PresentationTestCase) {
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

    #[should_panic(expected = "Unsupported format: jwt_vc_json")]
    #[tokio::test]
    async fn present_credential_fails_on_request_unsupported_credential_format() {
        let test_case = request_unsupported_credential_format_case();
        let kms = LocalKms::new();
        let key = kms
            .create_and_handle(KeyType::P256, CreateOptions {})
            .await
            .unwrap();
        let holder = holder_service(MockHttpClient::new(), kms, InMemVault::new()).await;
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

    #[should_panic(
        expected = "response: status_code=500 Internal Server Error, response_body=Internal Server Error"
    )]
    #[tokio::test]
    async fn present_credential_fails_on_internal_server_error() {
        let test_case = single_presentation::presentation_test_case();

        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::POST,
            build_url(VERIFIER_URL, "auth"),
            |_| {
                Ok(HttpResponse {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    headers: Default::default(),
                    body: "Internal Server Error".as_bytes().to_owned(),
                })
            },
            1.into(),
        );

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

    fn requested_credential_not_exist_case() -> PresentationTestCase {
        let mut test_case = single_presentation::presentation_test_case();
        test_case.credential_data = vec![(
            "https://credentials.example.com/degree_credential",
            json!({"name": "John", "degree": "Bachelor"}),
        )];
        test_case
    }

    fn empty_input_descriptor_case() -> PresentationTestCase {
        let mut test_case = single_presentation::presentation_test_case();
        test_case
            .request
            .presentation_definition
            .input_descriptors_mut()
            .clear();
        test_case
    }

    fn request_unsupported_credential_format_case() -> PresentationTestCase {
        let test_case = single_presentation::presentation_test_case();
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
        let test_case = single_presentation::presentation_test_case();
        let cred_format: ClaimFormatMap = serde_json::from_value(json!({
            "vc+sd-jwt":{
                "sd-jwt_alg_values": ["ES256", "EdDSA"],
                "kb-jwt_alg_values": ["ES256", "EdDSA"],
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
            .presentation_definition
            .input_descriptors()
            .clone();
        if let Some(i) = input_desc.get_mut(0) {
            *i = i.to_owned().set_format(cred_format)
        }

        test_case
            .request
            .presentation_definition
            .input_descriptors_mut()
            .clear();

        test_case
            .request
            .presentation_definition
            .input_descriptors_mut()
            .append(&mut input_desc);

        test_case
    }
}
