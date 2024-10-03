use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::PresentationDefinition as PresentationDefinitionParameter;
use oid4vp::core::authorization_request::parameters::{
    Nonce as NonceSpruce, ResponseMode, ResponseType, ResponseUri,
};
use oid4vp::core::authorization_request::AuthorizationRequestObject;
use oid4vp::core::credential_format::CoreCredentialFormat;
use oid4vp::core::metadata::parameters::verifier::VpFormats;
use oid4vp::core::metadata::parameters::wallet::AuthorizationEndpoint;
use oid4vp::core::metadata::WalletMetadata;
use oid4vp::core::object::ParsingErrorContext;
use oid4vp::core::profile::{Profile, Verifier};
use oid4vp::core::verifier::request_signer::RequestSigner;
use oid4vp::core::verifier::Session;
use oid4vp::presentation_exchange::PresentationDefinition;
use serde_json::{Map, Value as Json};
use snafu::ResultExt;
use ssi::jwk::JWK;
use std::marker::PhantomData;
use tracing::{info, instrument, trace, Level};
use url::Url;

use crate::crypto::SigningKey;
use crate::did::DIDResolver;
use crate::kms::{KeyHandle, Kms};
use crate::nonce::{Nonce, NonceGenerator};
use crate::vc;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp as api;
use crate::vc::oid4vp::internal_error::{
    KMSSnafu, NonceGenerationSnafu, ParseSnafu, PresentationExchangeSnafu, VCSnafu,
    VerifierSessionSnafu,
};
use crate::vc::oid4vp::metadata::{
    default_client_metadata, default_vp_formats, default_wallet_metadata,
};
use crate::vc::oid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientMetadata, PresentationSession,
};
use crate::vc::presentation_exchange;
use crate::vc::presentation_exchange::builder::DefaultPresentationBuilder;
use crate::vc::presentation_exchange::PresentationResponse;

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct VerifierMetadata {
    pub client_id: String,
    pub key_metadata: KeyMetadata,
    pub client_metadata: ClientMetadata,
}

pub struct VerifierService<VF, KH, KMS, D, NG>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    NG: NonceGenerator,
{
    verifier: VF,
    metadata: VerifierMetadata,
    kms: KMS,
    nonce_generator: NG,
    did_resolver: D,
    _marker: PhantomData<KH>,
}

impl<VF, KH, KMS, D, NG> VerifierService<VF, KH, KMS, D, NG>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    NG: NonceGenerator,
{
    #[instrument(
        level = Level::TRACE,
        skip(verifier, kms, nonce_generator, did_resolver),
    )]
    pub fn new(
        verifier: VF,
        kms: KMS,
        did_resolver: D,
        nonce_generator: NG,
        client_id: String,
        key_metadata: KeyMetadata,
        client_metadata: Option<ClientMetadata>,
    ) -> Self {
        let metadata = VerifierMetadata {
            client_id,
            key_metadata,
            client_metadata: client_metadata.unwrap_or(default_client_metadata()),
        };

        info!("oid4vp-verifier service is initialized");

        Self {
            metadata,
            did_resolver,
            kms,
            nonce_generator,
            verifier,
            _marker: Default::default(),
        }
    }
}

#[async_trait]
impl<VF, KH, KMS, D, NG> api::Verifier for VerifierService<VF, KH, KMS, D, NG>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    NG: NonceGenerator,
{
    #[instrument(
        level = Level::TRACE,
        skip(self)
        ret(),
    )]
    async fn create_authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        response_uri: Url,
    ) -> Result<(AuthorizationRequest, PresentationSession)> {
        info!("creating authorization request object is started");
        let nonce = self
            .nonce_generator
            .generate()
            .await
            .context(NonceGenerationSnafu)?;

        let request = self
            .authorization_request(
                presentation_definition,
                &nonce,
                default_wallet_metadata(),
                response_uri,
            )
            .await?;

        let session = PresentationSession {
            nonce,
            presentation_definition: presentation_definition.to_owned(),
        };

        info!("authorization request object is created");

        Ok((request, session))
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn verify_presentation(
        &self,
        auth_response: &AuthorizationResponse,
        session: &PresentationSession,
    ) -> Result<Json> {
        let claims = self
            .do_verify_presentation(
                &session.presentation_definition,
                &session.nonce,
                auth_response,
            )
            .await?;

        info!("presentation is verified");

        Ok(claims)
    }
}

impl<VF, KH, KMS, D, NG> VerifierService<VF, KH, KMS, D, NG>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    NG: NonceGenerator,
{
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &Nonce,
        wallet_metadata: WalletMetadata,
        response_uri: Url,
    ) -> Result<AuthorizationRequest> {
        let formats = self
            .metadata
            .client_metadata
            .0
            .get::<VpFormats>()
            .and_then(std::result::Result::ok)
            .unwrap_or_else(default_vp_formats);

        presentation_exchange::validate_formats(formats, presentation_definition)
            .context(PresentationExchangeSnafu)?;

        let presentation_definition_parameter = PresentationDefinitionParameter::try_from(
            presentation_definition.clone(),
        )
        .map_err(|e| {
            ParseSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        let verifier_key = self
            .kms
            .get(&self.metadata.key_metadata.kid)
            .await
            .context(KMSSnafu)?;

        let session = Session::builder(DefaultVerifierProfile, wallet_metadata.clone())
            .with_request_parameter(ResponseMode::DirectPost)
            .with_request_parameter(ResponseUri(response_uri))
            .with_request_parameter(ResponseType::VpToken)
            .with_request_parameter(NonceSpruce(nonce.secret().to_owned()))
            .with_request_parameter(self.metadata.client_metadata.clone())
            .with_request_parameter(presentation_definition_parameter)
            .with_did_client_id_and_resolver(
                self.metadata.key_metadata.did_url.to_owned(),
                SignerWrapper::new(verifier_key)?,
                self.did_resolver.as_spruce_resolver(),
            )
            .await
            .context(VerifierSessionSnafu)?
            .build()
            .await
            .context(VerifierSessionSnafu)?;

        trace!(created_verifier_session = ?session);

        let authorization_endpoint = wallet_metadata
            .get::<AuthorizationEndpoint>()
            .parsing_error()
            .map_err(|e| {
                ParseSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .0;

        Ok(AuthorizationRequest {
            client_id: self.metadata.client_id.to_owned(),
            request_object_jwt: session.request_object_jwt().to_string(),
            authorization_endpoint,
        })
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn do_verify_presentation(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &Nonce,
        authorization_response: &AuthorizationResponse,
    ) -> Result<Json> {
        let mut result: Map<String, Json> = Map::new();
        let presentation_response = PresentationResponse {
            presentations: authorization_response.vp_token.clone(),
            presentation_submission: authorization_response.presentation_submission.clone(),
        };

        let requested_presentations = presentation_exchange::resolve_presentation_response(
            &presentation_response,
            presentation_definition,
        )
        .context(PresentationExchangeSnafu)?;

        for requested_presentation in requested_presentations {
            let claims = self
                .verifier
                .verify_presentation(nonce, &requested_presentation.presentation)
                .await
                .context(VCSnafu)?;
            presentation_exchange::validate_claims(
                &claims,
                &requested_presentation.id,
                presentation_definition,
            )
            .context(PresentationExchangeSnafu)?;

            result.insert(requested_presentation.id, claims);
        }

        Ok(result.into())
    }
}

#[derive(Debug, Clone)]
pub struct DefaultVerifierProfile;

#[async_trait]
impl Profile for DefaultVerifierProfile {
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
        Ok(())
    }
}

impl Verifier for DefaultVerifierProfile {
    type PresentationBuilder = DefaultPresentationBuilder;
}

struct SignerWrapper<S: SigningKey> {
    signer: S,
    key: JWK,
}

impl<S: SigningKey> SignerWrapper<S> {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
    fn new(signer: S) -> Result<SignerWrapper<S>> {
        let key = signer.jwk().ok_or(
            ParseSnafu {
                details: "Could not retrieve JWK",
            }
            .build(),
        )?;

        Ok(SignerWrapper { signer, key })
    }
}

#[async_trait]
impl<S: SigningKey> RequestSigner for SignerWrapper<S> {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    fn alg(&self) -> &str {
        self.signer.alg().into()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    fn jwk(&self) -> &JWK {
        &self.key
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature = self.signer.sign(payload).await?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::http::HttpSnafu;
    use crate::inmem::kms::LocalKms;
    use crate::nonce::Nonce;
    use crate::vc::oid4vp::tests::fixtures::VERIFIER_URL;
    use crate::vc::oid4vp::tests::fixtures::{multi_presentation, single_presentation, NONCE};
    use crate::vc::oid4vp::tests::utils::{
        build_url, validate_claims, verifier_service, VerificationTestCase,
    };
    use crate::vc::oid4vp::{
        auth_request_as_url, AuthorizationResponse, AuthorizationUrlType, PresentationDefinition,
        PresentationSession, Verifier,
    };
    use oid4vp::core::authorization_request::{AuthorizationRequest, AuthorizationRequestObject};
    use oid4vp::core::object::UntypedObject;
    use rstest::rstest;
    use serde_json::json;
    use std::collections::HashMap;
    use url::Url;

    #[tokio::test]
    async fn generate_auth_request_by_reference_success() {
        let presentation_definition = single_presentation::presentation_definition();
        let request_uri = build_url(VERIFIER_URL, "request");

        let (verifier, did) = verifier_service().await;

        let (request, _) = verifier
            .create_authorization_request(&presentation_definition, build_url(VERIFIER_URL, "auth"))
            .await
            .unwrap();

        let by_reference = auth_request_as_url(
            &request,
            AuthorizationUrlType::Reference(request_uri.clone()),
        );

        let hash_query: HashMap<String, String> = by_reference.query_pairs().into_owned().collect();

        assert_eq!(hash_query.get("client_id").unwrap(), &did);
        assert_eq!(hash_query.get("request_uri").unwrap(), request_uri.as_str());
    }

    #[tokio::test]
    async fn generate_auth_request_by_value_success() {
        let presentation_definition = single_presentation::presentation_definition();
        let response_uri: Url = build_url(VERIFIER_URL, "auth");

        let (verifier, did) = verifier_service().await;

        let (request, _) = verifier
            .create_authorization_request(&presentation_definition, response_uri.clone())
            .await
            .unwrap();

        let by_value = auth_request_as_url(&request, AuthorizationUrlType::Value);

        let auth_request = AuthorizationRequest::from_query_params(by_value.query().unwrap());

        let hash_query: HashMap<String, String> = by_value.query_pairs().into_owned().collect();
        let jwt = hash_query.get("request").unwrap();

        let request: AuthorizationRequestObject = ssi::jwt::decode_unverified::<UntypedObject>(jwt)
            .unwrap()
            .try_into()
            .unwrap();

        let actual_presentation_definition = request
            .resolve_presentation_definition(|_| async {
                HttpSnafu {
                    details: "Requesting a presentation definition by reference is not supported in this test.".to_string(),
                }.fail()
            })
            .await
            .unwrap()
            .into_parsed();

        assert_eq!(actual_presentation_definition, presentation_definition);
        assert_eq!(request.client_id().0, did);
        assert_eq!(request.return_uri(), &response_uri);
    }

    // TODO: Validations will be implemented as part of the ASDK-98 task
    #[rstest]
    #[ignore]
    #[case::empty_id(presentation_definition_with_empty_id())]
    #[ignore]
    #[case::empty_descriptors(presentation_definition_with_empty_descriptors())]
    #[tokio::test]
    #[should_panic]
    async fn generate_auth_request_fails_on_invalid_presentation_def(
        #[case] presentation_definition: PresentationDefinition,
    ) {
        let request_uri = build_url(VERIFIER_URL, "request");

        let (verifier, did) = verifier_service().await;

        let (request, _) = verifier
            .create_authorization_request(&presentation_definition, build_url(VERIFIER_URL, "auth"))
            .await
            .unwrap();
    }

    // TODO: Validations will be implemented as part of the ASDK-98 task
    #[ignore]
    #[tokio::test]
    #[should_panic]
    async fn generate_auth_request_fails_on_empty_nonce() {
        let request_uri = build_url(VERIFIER_URL, "request");

        let (verifier, did) = verifier_service().await;

        let (request, _) = verifier
            .create_authorization_request(
                &single_presentation::presentation_definition(),
                build_url(VERIFIER_URL, "auth"),
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case::single_presentation_success(single_presentation::verification_test_case())]
    #[case::multi_presentation_success(multi_presentation::verification_test_case())]
    #[tokio::test]
    async fn verify_auth_response_success(#[case] test_case: VerificationTestCase) {
        let (verifier, client_id) = verifier_service().await;
        let kms = LocalKms::new();
        let session = PresentationSession {
            nonce: Nonce(NONCE.to_owned()),
            presentation_definition: test_case.session.presentation_definition.clone(),
        };

        let response = test_case.auth_response(&session.nonce, &client_id).await;

        let verified_claims = verifier
            .verify_presentation(&response, &test_case.session)
            .await
            .unwrap();

        for (index, credential_data) in test_case.credential_data.into_iter().enumerate() {
            let cred_id = &test_case
                .presentation_submission
                .descriptor_map
                .get(index)
                .unwrap()
                .id;

            let cred_claims = &verified_claims[cred_id];
            validate_claims(cred_claims, &credential_data);
        }
    }

    #[rstest]
    #[should_panic(expected = "Invalid nonce")]
    #[case::invalid_nonce(invalid_nonce_case())]
    #[should_panic(
        expected = "Requested presentation SD_JWT_cred not found in the presentation submission"
    )]
    #[case::presentation_not_provided(presentation_not_provided_case())]
    #[should_panic(
        expected = "Requested presentation Identity-1 not found in the presentation submission"
    )]
    #[case::empty_descriptor_map(empty_descriptor_map_case())]
    // TODO: Filter constraint validations will be implemented as part of the ASDK-98 task
    #[ignore]
    #[case::invalid_presentation_type(invalid_presentation_type_case())]
    #[should_panic(expected = " Requested claim not found by path $.name")]
    #[case::presentation_claim_not_found(presentation_claim_not_found_case())]
    #[tokio::test]
    async fn verify_auth_response_fails(#[case] test_case: VerificationTestCase) {
        let (verifier, client_id) = verifier_service().await;
        let kms = LocalKms::new();
        let nonce = Nonce(NONCE.to_owned());

        let response = test_case.auth_response(&nonce, &client_id).await;

        let verified_claims = verifier
            .verify_presentation(&response, &test_case.session)
            .await
            .unwrap();
    }

    #[rstest]
    #[case::empty_token("[]")]
    #[case::invalid_token(r#"{"test": "invalid"}"#)]
    #[tokio::test]
    #[should_panic(expected = "Incorrect presentation format: expected JWT string")]
    async fn verify_auth_response_fails_on_invalid_vp_token(#[case] vp_token: &str) {
        let (verifier, client_id) = verifier_service().await;
        let kms = LocalKms::new();

        let response = AuthorizationResponse {
            vp_token: serde_json::from_str(vp_token).unwrap(),
            presentation_submission: single_presentation::presentation_submission(),
        };

        let result = verifier
            .verify_presentation(&response, &single_presentation::presentation_session())
            .await
            .unwrap();
    }

    fn presentation_definition_with_empty_id() -> PresentationDefinition {
        let mut presentation_definition = single_presentation::presentation_definition();
        presentation_definition.id = "".to_string();

        presentation_definition
    }

    fn presentation_definition_with_empty_descriptors() -> PresentationDefinition {
        let mut presentation_definition = single_presentation::presentation_definition();
        presentation_definition.input_descriptors = vec![];

        presentation_definition
    }

    fn invalid_nonce_case() -> VerificationTestCase {
        let mut test_case = single_presentation::verification_test_case();
        test_case.session.nonce = Nonce("other-nonce".to_owned());
        test_case
    }

    fn empty_descriptor_map_case() -> VerificationTestCase {
        let mut test_case = single_presentation::verification_test_case();
        test_case.presentation_submission.descriptor_map = vec![];
        test_case
    }

    fn presentation_not_provided_case() -> VerificationTestCase {
        let mut test_case = single_presentation::verification_test_case();
        test_case.session.presentation_definition = multi_presentation::presentation_definition();
        test_case
    }

    fn invalid_presentation_type_case() -> VerificationTestCase {
        let mut test_case = single_presentation::verification_test_case();
        test_case.credential_data = vec![(
            "https://credentials.example.com/degree_credential",
            json!({"name": "John", "degree": "Bachelor"}),
        )];
        test_case
    }

    fn presentation_claim_not_found_case() -> VerificationTestCase {
        let mut test_case = single_presentation::verification_test_case();
        test_case.credential_data = vec![(
            "https://credentials.example.com/identity_credential",
            json!({"degree": "Bachelor"}),
        )];
        test_case
    }
}
