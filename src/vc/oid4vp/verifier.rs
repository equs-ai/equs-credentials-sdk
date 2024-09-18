use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::PresentationDefinition as PresentationDefinitionParameter;
use oid4vp::core::authorization_request::parameters::{ResponseMode, ResponseType, ResponseUri};
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
use crate::vc;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp as api;
use crate::vc::oid4vp::internal_error::{
    KMSSnafu, ParseSnafu, PresentationExchangeSnafu, VCSnafu, VerifierSessionSnafu,
};
use crate::vc::oid4vp::metadata::{
    default_client_metadata, default_vp_formats, default_wallet_metadata,
};
use crate::vc::oid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientMetadata, Nonce, PresentationSession,
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

pub struct VerifierService<VF, KH, KMS, D>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
{
    verifier: VF,
    metadata: VerifierMetadata,
    kms: KMS,
    did_resolver: D,
    _marker: PhantomData<KH>,
}

impl<VF, KH, KMS, D> VerifierService<VF, KH, KMS, D>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
{
    #[instrument(
        level = Level::TRACE,
        skip(verifier, kms, did_resolver),
    )]
    pub fn new(
        verifier: VF,
        kms: KMS,
        did_resolver: D,
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
            verifier,
            _marker: Default::default(),
        }
    }
}

#[async_trait]
impl<VF, KH, KMS, D> api::Verifier for VerifierService<VF, KH, KMS, D>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
{
    #[instrument(
        level = Level::TRACE,
        skip(self)
        ret(level = Level::TRACE)
    )]
    async fn create_authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &Nonce,
        response_uri: Url,
    ) -> Result<(AuthorizationRequest, PresentationSession)> {
        info!("creating authorization request object is started");

        let request = self
            .authorization_request(
                presentation_definition,
                nonce,
                default_wallet_metadata(),
                response_uri,
            )
            .await?;

        let session = PresentationSession {
            nonce: nonce.to_owned(),
            presentation_definition: presentation_definition.to_owned(),
        };

        info!("authorization request object is created");

        Ok((request, session))
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
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

impl<VF, KH, KMS, D> VerifierService<VF, KH, KMS, D>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
{
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
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
            .with_request_parameter(nonce.to_owned())
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
        ret(level = Level::TRACE)
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
                .verify_presentation(&nonce.0, &requested_presentation.presentation)
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
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    fn alg(&self) -> &str {
        self.signer.alg().into()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(level = Level::TRACE)
    )]
    fn jwk(&self) -> &JWK {
        &self.key
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature = self.signer.sign(payload).await?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::inmem::kms::LocalKms;
    use crate::vc::oid4vp::test_utils::{
        create_authorization_response, create_did_and_key_metadata,
        create_test_presentation_definition,
    };
    use crate::vc::oid4vp::{auth_request_as_url, AuthorizationUrlType, Verifier, VerifierBuilder};

    #[tokio::test]
    async fn generate_authorization_request() {
        let presentation_definition = create_test_presentation_definition();
        let nonce = "nOnCe".into();

        let (verifier, _) = verifier().await;

        let (request, _) = verifier
            .create_authorization_request(
                &presentation_definition,
                &nonce,
                "https://verifier/auth".parse().unwrap(),
            )
            .await
            .unwrap();

        let by_value = auth_request_as_url(&request, AuthorizationUrlType::Value);
        let by_reference = auth_request_as_url(
            &request,
            AuthorizationUrlType::Reference("https://verifier/reqobject".parse().unwrap()),
        );

        println!("{}", by_value);
        println!("{}", by_reference);
    }

    #[tokio::test]
    async fn verify_authorization_response() {
        let (verifier, client_id) = verifier().await;

        let presentation_definition = create_test_presentation_definition();
        let claims = json!( {
            "name": "John",
            "surname": "Doe",
            "date": "09/09/1989",
        });
        let nonce = "nOnCe".into();

        let (request, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &nonce,
                "https://verifier/auth".parse().unwrap(),
            )
            .await
            .unwrap();

        let response = create_authorization_response(&client_id, &nonce.0, &claims).await;

        let claims = verifier
            .verify_presentation(&response, &session)
            .await
            .unwrap();

        println!("{}", claims);

        assert_eq!(
            claims["Identity-1"]["vct"],
            json!("https://credentials.example.com/identity_credential")
        );
        assert_eq!(claims["Identity-1"]["name"], json!("John"));
    }

    async fn verifier() -> (impl Verifier, String) {
        let kms = LocalKms::new();

        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let verifier = VerifierBuilder::new(kms, key_metadata, did.clone())
            .build()
            .await
            .unwrap();

        (verifier, did)
    }
}
