use crate::crypto::SigningKey;
use crate::did::DIDResolver;
use crate::kms::{KeyHandle, Kms};
use crate::storage::Storage;
use crate::utils::json::find_json_element;
use crate::vc;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp::presentation_builder::DefaultPresentationBuilder;
use crate::vc::oid4vp::{
    default_client_metadata, default_wallet_metadata, AuthorizationRequest, AuthorizationResponse,
    ClientMetadata,
};
use crate::vc::{oid4vp as api, Presentation};
use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::PresentationDefinition as PresentationDefinitionParameter;
use oid4vp::core::authorization_request::parameters::{
    Nonce, ResponseMode, ResponseType, ResponseUri,
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
use oid4vp::presentation_exchange::{ConstraintsField, PresentationDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use ssi::jwk::JWK;
use std::marker::PhantomData;
use tracing::{info, instrument, trace, Level};
use url::Url;

pub type Error = api::VerifierError;
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub(crate) struct StorageEntry {
    pub nonce: String,
    pub presentation_definition: PresentationDefinition,
}

#[derive(Debug, Clone)]
pub struct VerifierMetadata {
    pub client_id: String,
    pub key_metadata: KeyMetadata,
    pub client_metadata: ClientMetadata,
}

/// Service for managing OIDC4VP verifications.
///
/// This service handles the creation of authorization requests and the verification of presentations.
pub struct VerifierService<VF, KH, KMS, D, ST>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    ST: Storage<String, StorageEntry>,
{
    verifier: VF,
    metadata: VerifierMetadata,
    kms: KMS,
    did_resolver: D,
    storage: ST,
    _marker: PhantomData<KH>,
}

impl<VF, KH, KMS, D, ST> VerifierService<VF, KH, KMS, D, ST>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    ST: Storage<String, StorageEntry>,
{
    /// Creates a new `VerifierService`.
    ///
    /// # Arguments
    ///
    /// * `verifier` - core Verifier
    /// * `kms` - Key Management Service.
    /// * `storage` - Storage for caching requests.
    /// * `client_id` - Verifier ID
    /// * `key_metadata` - Verifier signing key metadata
    ///
    /// # Returns
    ///
    /// A new instance of `VerifierService`.
    #[instrument(
        level = Level::TRACE,
        skip(verifier, kms, did_resolver, storage),
    )]
    pub fn new(
        verifier: VF,
        kms: KMS,
        did_resolver: D,
        storage: ST,
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
            storage,
            _marker: Default::default(),
        }
    }
}

#[async_trait]
impl<VF, KH, KMS, D, ST> api::Verifier for VerifierService<VF, KH, KMS, D, ST>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    ST: Storage<String, StorageEntry>,
{
    /// Creates an authorization request.
    ///
    /// # Arguments
    ///
    /// * `presentation_definition` - The presentation definition.
    /// * `nonce` - A unique nonce.
    /// * `response_uri` - The response URI.
    ///
    /// # Returns
    ///
    /// An `AuthorizationRequest` on success.
    #[instrument(
        level = Level::TRACE,
        skip(self)
        ret(level = Level::TRACE)
    )]
    async fn create_authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        response_uri: Url,
    ) -> Result<AuthorizationRequest> {
        info!("creating authorization request object is started");

        let request = self
            .authorization_request(
                presentation_definition,
                nonce,
                default_wallet_metadata(),
                response_uri,
            )
            .await?;

        let storage_entry = StorageEntry {
            nonce: nonce.to_string(),
            presentation_definition: presentation_definition.clone(),
        };

        self.storage
            .put(presentation_definition.id.to_owned(), storage_entry)
            .await?;

        info!("authorization request object is created");

        Ok(request)
    }

    /// Verifies a presentation.
    ///
    /// # Arguments
    ///
    /// * `auth_response` - The authorization response containing the presentation.
    ///
    /// # Returns
    ///
    /// The verified claims as a JSON object.
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn verify_presentation(&self, auth_response: &AuthorizationResponse) -> Result<Json> {
        let id = &auth_response.presentation_submission.definition_id;
        let storage_entry = self
            .storage
            .get(id)
            .await?
            .ok_or(Error::SubmissionNotFound(id.to_owned()))?;

        let claims = self
            .do_verify_presentation(
                &storage_entry.presentation_definition,
                &storage_entry.nonce,
                auth_response,
            )
            .await?;

        self.storage.delete(id).await?;

        info!("presentation is verified");

        Ok(claims)
    }
}

impl<VF, KH, KMS, D, ST> VerifierService<VF, KH, KMS, D, ST>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    D: DIDResolver,
    ST: Storage<String, StorageEntry>,
{
    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
    )]
    fn validate_field_constraints(claims: &Json, constraints: &[ConstraintsField]) -> Result<()> {
        // TODO: move to presentation_exchange
        for constraint in constraints.iter() {
            for path in constraint.path.iter() {
                if find_json_element(claims, path).is_none() {
                    return Err(Error::InvalidResponse(format!(
                        "Requested claim not found by path {:?}",
                        path
                    )));
                }
            }
        }
        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    fn validate_formats(&self, presentation_definition: &PresentationDefinition) -> Result<()> {
        // TODO: move to presentation_exchange (except for extracting VpFormats from metadata)
        let vp_format_json = match presentation_definition.format.as_ref() {
            Some(format) => format,
            None => return Ok(()), // presentation definition does not contain any format
        };

        let supported_formats = match self.metadata.client_metadata.0.get::<VpFormats>() {
            Some(Ok(formats)) => formats,
            _ => return Ok(()), // supported formats are not found
        };

        let vp_formats: VpFormats = vp_format_json.clone().try_into().map_err(|err| {
            Error::ParsingError(format!(
                "Failed to parse presentation definition format: {}. Error: {}",
                vp_format_json, err
            ))
        })?;

        for vp_format in vp_formats.0.keys() {
            if !supported_formats.0.contains_key(vp_format) {
                return Err(Error::FormatNotSupported(format!(
                    "Format '{}' provided in presentation definition is not supported. Supported formats: {:?}",
                    vp_format, supported_formats.0.keys().collect::<Vec<_>>()
                )));
            }
        }

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        wallet_metadata: WalletMetadata,
        response_uri: Url,
    ) -> Result<AuthorizationRequest> {
        self.validate_formats(presentation_definition)?;

        let presentation_definition_parameter = PresentationDefinitionParameter::try_from(
            presentation_definition.clone(),
        )
        .map_err(|err| {
            Error::ParsingError(format!("Failed to parse presentation definition: {}", err))
        })?;

        let verifier_key = self
            .kms
            .get(&self.metadata.key_metadata.kid)
            .await
            .map_err(|err| {
                Error::RequestCreationFailed(format!(
                    "Failed to get key {}: {}",
                    &self.metadata.key_metadata.kid, err
                ))
            })?;

        let session = Session::builder(DefaultVerifierProfile, wallet_metadata.clone())
            .with_request_parameter(ResponseMode::DirectPost)
            .with_request_parameter(ResponseUri(response_uri))
            .with_request_parameter(ResponseType::VpToken)
            .with_request_parameter(Nonce(nonce.to_string()))
            .with_request_parameter(self.metadata.client_metadata.clone())
            .with_request_parameter(presentation_definition_parameter)
            .with_did_client_id_and_resolver(
                self.metadata.key_metadata.did_url.to_owned(),
                SignerWrapper::new(verifier_key)?,
                self.did_resolver.as_spruce_resolver(),
            )
            .await
            .map_err(|err| Error::KeyResolutionFailed(format!("Failed to build session: {}", err)))?
            .build()
            .await
            .map_err(|err| Error::RequestCreationFailed(err.to_string()))?;

        trace!(created_verifier_session = ?session);

        let authorization_endpoint = wallet_metadata
            .get::<AuthorizationEndpoint>()
            .parsing_error()
            .map_err(|err| {
                Error::ParsingError(format!(
                    "Failed to get authorization endpoint from wallet metadata: {}",
                    err
                ))
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
        nonce: &str,
        authorization_response: &AuthorizationResponse,
    ) -> std::result::Result<Json, Error> {
        let mut result: Map<String, Json> = Map::new();
        let vp_token = &authorization_response.vp_token;
        let presentation_submission = &authorization_response.presentation_submission;

        for input_descriptor in &presentation_definition.input_descriptors {
            let descriptor_map = presentation_submission
                .descriptor_map
                .iter()
                .find(|item| item.id == input_descriptor.id)
                .ok_or_else(|| {
                    Error::InvalidResponse(format!(
                        "Requested presentation {:?} not found",
                        input_descriptor
                            .name
                            .as_deref()
                            .unwrap_or(&input_descriptor.id)
                    ))
                })?;

            let presentation_json =
                find_json_element(vp_token, &descriptor_map.path).ok_or_else(|| {
                    Error::InvalidResponse(format!(
                        "Requested presentation {:?} not found by path {:?}",
                        input_descriptor
                            .name
                            .as_deref()
                            .unwrap_or(&input_descriptor.id),
                        descriptor_map.path
                    ))
                })?;

            let presentation = match descriptor_map.format.as_str() {
                "vc+sd-jwt" => {
                    let sd_jwt = presentation_json.as_str().ok_or_else(|| {
                        Error::FormatNotSupported(
                            "Incorrect presentation format: expected JWT string".to_string(),
                        )
                    })?;
                    Ok(Presentation::SdJwtVp(sd_jwt.to_string()))
                }
                _ => Err(Error::FormatNotSupported(descriptor_map.format.to_owned())),
            }?;

            let claims = self
                .verifier
                .verify_presentation(nonce, &presentation)
                .await
                .map_err(|err| Error::VerificationFailed(err.to_string()))?;

            let constraints_fields = input_descriptor.constraints.fields.as_ref();
            if let Some(constraints) = constraints_fields {
                Self::validate_field_constraints(&claims, constraints)?;
            }

            result.insert(input_descriptor.id.clone(), claims);
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
        let key = signer.jwk().ok_or(Error::InvalidKey(
            "Failed to convert verifier key into JWK".to_string(),
        ))?;

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
        let nonce = "n0NcE";

        let (verifier, _) = verifier().await;

        let request = verifier
            .create_authorization_request(
                &presentation_definition,
                nonce,
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
        let nonce = "n0NcE";

        let request = verifier
            .create_authorization_request(
                &presentation_definition,
                nonce,
                "https://verifier/auth".parse().unwrap(),
            )
            .await
            .unwrap();

        let response = create_authorization_response(&client_id, nonce, &claims).await;

        let claims = verifier.verify_presentation(&response).await.unwrap();

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
