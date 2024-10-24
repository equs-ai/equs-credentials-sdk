use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::Nonce as NonceSpruce;
use oid4vp::core::metadata::WalletMetadata;
use oid4vp::verifier::by_reference::ByReference;
use oid4vp::verifier::request_signer::RequestSigner;
use serde_json::{Map, Value as Json};
use snafu::ResultExt;
use ssi::jwk::JWK;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use tracing::{info, instrument, Level};
use url::Url;

use crate::crypto::SigningKey;
use crate::did::DIDResolver;
use crate::kms::{KeyHandle, Kms};
use crate::nonce::{Nonce, NonceGenerator};
use crate::vc;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp as api;
use crate::vc::oid4vp::internal_error::{
    KMSSnafu, NonceGenerationSnafu, Oid4VpLibSnafu, ParseSnafu, PresentationExchangeSnafu, VCSnafu,
};
use crate::vc::oid4vp::metadata::{default_client_metadata, default_wallet_metadata};
use crate::vc::oid4vp::{
    AuthResponseOptions, AuthorizationResponse, ClientMetadata, PassAuthRequestObject,
    PresentationSession,
};
use crate::vc::presentation_exchange;
use crate::vc::presentation_exchange::{
    validate_against_presentation_definition, PresentationDefinition, PresentationResponse,
};

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

pub type DIDClient<S> = oid4vp::verifier::client::DIDClient<S>;
pub type X509SanClient = oid4vp::verifier::client::X509SanClient;

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
        auth_response_config: &AuthResponseOptions,
        pass_auth_request_object: &PassAuthRequestObject,
        wallet_metadata: Option<&WalletMetadata>,
    ) -> Result<(Url, PresentationSession)> {
        info!("creating authorization request object is started");
        let nonce = self
            .nonce_generator
            .generate()
            .await
            .context(NonceGenerationSnafu)?;

        let (request_url, auth_request_jwt) = self
            .authorization_request(
                presentation_definition,
                nonce.clone(),
                auth_response_config,
                pass_auth_request_object,
                wallet_metadata.unwrap_or(&default_wallet_metadata()),
            )
            .await?;

        let session = PresentationSession {
            nonce,
            auth_request_jwt,
            presentation_definition: presentation_definition.to_owned(),
        };

        info!("authorization request object is created");

        Ok((request_url, session))
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
        nonce: Nonce,
        auth_response_config: &AuthResponseOptions,
        pass_auth_request_object: &PassAuthRequestObject,
        wallet_metadata: &WalletMetadata,
    ) -> Result<(Url, String)> {
        let verifier_key = self
            .kms
            .get(&self.metadata.key_metadata.kid)
            .await
            .context(KMSSnafu)?;

        let did_client = DIDClient::new(
            self.metadata.key_metadata.did_url.clone(),
            SignerWrapper::new(verifier_key)?,
            self.did_resolver.as_spruce_resolver(),
        )
        .await
        .context(Oid4VpLibSnafu)?;

        let verifier = oid4vp::verifier::Verifier::builder()
            .with_client(did_client)
            .with_submission_endpoint(auth_response_config.submission_uri.0.to_owned());

        let pass_req_obj = match pass_auth_request_object.to_owned() {
            PassAuthRequestObject::ByValue => ByReference::False,
            PassAuthRequestObject::ByReference(at) => ByReference::True { at },
        };

        let (auth_request_url, auth_req_jwt) = verifier
            .build()
            .await
            .context(Oid4VpLibSnafu)?
            .build_authorization_request()
            .with_presentation_definition(presentation_definition.to_owned())
            .with_request_parameter(auth_response_config.mode.to_owned())
            .with_request_parameter(auth_response_config.type_.to_owned())
            .with_request_parameter(NonceSpruce::from(nonce.secret()))
            .with_request_parameter(self.metadata.client_metadata.clone())
            .build(wallet_metadata, pass_req_obj)
            .await?;

        Ok((auth_request_url, auth_req_jwt))
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
            result.insert(requested_presentation.id, claims);
        }

        match authorization_response.vp_token {
            Json::Array(_) => {
                let claims = Json::Array(result.values().map(|v| v.to_owned()).collect());
                validate_against_presentation_definition(
                    &claims,
                    presentation_definition,
                    &authorization_response.presentation_submission,
                )
                .context(PresentationExchangeSnafu)?;
            }
            _ => {
                if let Some(claim) = result.values().find(|_| true) {
                    validate_against_presentation_definition(
                        claim,
                        presentation_definition,
                        &authorization_response.presentation_submission,
                    )
                    .context(PresentationExchangeSnafu)?;
                }
            }
        };

        Ok(result.into())
    }
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

impl<S: SigningKey> Debug for SignerWrapper<S> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        std::write!(fmt, "JWK = {:?}", self.key)
    }
}

#[async_trait]
impl<S: SigningKey> RequestSigner for SignerWrapper<S> {
    type Error = anyhow::Error;

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    fn alg(&self) -> anyhow::Result<String, Self::Error> {
        Ok(self.signer.alg().to_string())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    fn jwk(&self) -> anyhow::Result<JWK, Self::Error> {
        Ok(self.key.to_owned())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>, Self::Error> {
        let signature = self.signer.sign(payload).await?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::http::HttpSnafu;
    use crate::inmem::kms::LocalKms;
    use crate::nonce::Nonce;
    use crate::vc::oid4vp::tests::fixtures::multi_presentation::auth_response_options;
    use crate::vc::oid4vp::tests::fixtures::VERIFIER_URL;
    use crate::vc::oid4vp::tests::fixtures::{multi_presentation, single_presentation, NONCE};
    use crate::vc::oid4vp::tests::utils::{
        build_url, validate_claims, verifier_service, VerificationTestCase,
    };
    use crate::vc::oid4vp::{
        AuthorizationResponse, PassAuthRequestObject, PresentationSession, Verifier,
    };
    use crate::vc::presentation_exchange::PresentationDefinition;
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

        let auth_resp_options = auth_response_options(build_url(VERIFIER_URL, "auth"));

        let (uri, _) = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByReference(request_uri.clone()),
                None,
            )
            .await
            .unwrap();

        let hash_query: HashMap<String, String> = uri.query_pairs().into_owned().collect();

        assert_eq!(hash_query.get("client_id").unwrap(), &did);
        assert_eq!(hash_query.get("request_uri").unwrap(), request_uri.as_str());
    }

    #[tokio::test]
    async fn generate_auth_request_by_value_success() {
        let presentation_definition = single_presentation::presentation_definition();
        let response_uri: Url = build_url(VERIFIER_URL, "auth");

        let (verifier, did) = verifier_service().await;

        let auth_resp_options = auth_response_options(response_uri.clone());

        let (request_uri, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByValue,
                None,
            )
            .await
            .unwrap();

        let auth_request = AuthorizationRequest::from_query_params(request_uri.query().unwrap());

        let hash_query: HashMap<String, String> = request_uri.query_pairs().into_owned().collect();
        let auth_req_jwt_from_uri = hash_query.get("request").unwrap();

        let request: AuthorizationRequestObject =
            ssi::jwt::decode_unverified::<UntypedObject>(auth_req_jwt_from_uri)
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

        assert_eq!(session.auth_request_jwt, auth_req_jwt_from_uri.to_owned());
        assert_eq!(
            serde_json::to_value(&actual_presentation_definition).unwrap(),
            serde_json::to_value(&presentation_definition).unwrap()
        );
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

        let auth_resp_options = auth_response_options(build_url(VERIFIER_URL, "auth"));

        let (request, _) = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByReference(request_uri),
                None,
            )
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

        let auth_resp_options = auth_response_options(build_url(VERIFIER_URL, "auth"));

        let (request, _) = verifier
            .create_authorization_request(
                &single_presentation::presentation_definition(),
                &auth_resp_options,
                &PassAuthRequestObject::ByReference(request_uri),
                None,
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
            auth_request_jwt: Default::default(),
        };

        let response = test_case.auth_response(&session.nonce, &client_id).await;

        let verified_claims = verifier
            .verify_presentation(&response, &test_case.session)
            .await
            .unwrap();

        for (index, credential_data) in test_case.credential_data.into_iter().enumerate() {
            let cred_id = &test_case
                .presentation_submission
                .descriptor_map()
                .get(index)
                .unwrap()
                .id();

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
    #[should_panic(expected = "Field elements are not found while it is required")]
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
        presentation_definition = PresentationDefinition::new(
            "".to_string(),
            presentation_definition
                .input_descriptors()
                .first()
                .unwrap()
                .to_owned(),
        );

        presentation_definition
    }

    fn presentation_definition_with_empty_descriptors() -> PresentationDefinition {
        let mut presentation_definition = single_presentation::presentation_definition();
        presentation_definition.input_descriptors_mut().clear();

        presentation_definition
    }

    fn invalid_nonce_case() -> VerificationTestCase {
        let mut test_case = single_presentation::verification_test_case();
        test_case.session.nonce = Nonce("other-nonce".to_owned());
        test_case
    }

    fn empty_descriptor_map_case() -> VerificationTestCase {
        let mut test_case = single_presentation::verification_test_case();
        test_case
            .presentation_submission
            .descriptor_map_mut()
            .clear();
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
