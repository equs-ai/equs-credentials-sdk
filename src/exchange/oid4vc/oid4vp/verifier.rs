use std::marker::PhantomData;
use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::{
    ClientId, Nonce, PresentationDefinition as PresentationDefinitionParameter, ResponseMode,
    ResponseType, ResponseUri,
};
use oid4vp::core::metadata::WalletMetadata;
use oid4vp::core::{
    metadata::parameters::wallet::AuthorizationEndpoint,
    object::ParsingErrorContext,
    verifier::{request_signer::RequestSigner, Session},
};
use oid4vp::presentation_exchange::{ConstraintsField, PresentationDefinition};
use serde_json::{Map, Value as Json};
use ssi::{
    did::Document,
    did_resolve::{DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata},
    jwk::JWK,
};
use url::Url;

use crate::core_::crypto::SigningKey;
use crate::core_::did::ResolveOptions;
use crate::core_::kms::Kms;
use crate::core_::{did::DIDResolver, kms::KeyHandle};
use crate::exchange::oid4vc::oid4vp::error::Error;
use crate::exchange::oid4vc::oid4vp::{
    verifier_profile::DefaultVerifierProfile, AuthorizationRequest, AuthorizationResponse,
    VerifierMetadata,
};
use crate::facade::facade_low_level::{Presentation, Verifier as PresentationVerifier};
use crate::impls::utils::json::find_json_element;

#[async_trait]
pub trait Oid4VpVerifier: Send + Sync {
    async fn authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        wallet_metadata: WalletMetadata,
        response_uri: Url,
    ) -> Result<AuthorizationRequest, Error>;

    async fn verify_presentation(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        authorization_response: &AuthorizationResponse,
    ) -> Result<Json, Error>;
}

pub struct ConcreteOid4VpVerifier<KH, KM, D, PV>
where
    KH: KeyHandle,
    KM: Kms<KH>,
    D: DIDResolver,
    PV: PresentationVerifier,
{
    metadata: VerifierMetadata,
    kms: KM,
    did_resolver: DIDResolverWrapper<D>,
    presentation_verifier: PV,
    _marker: PhantomData<KH>,
}

impl<KH, KM, D, PV> ConcreteOid4VpVerifier<KH, KM, D, PV>
where
    KM: Kms<KH>,
    KH: KeyHandle,
    D: DIDResolver,
    PV: PresentationVerifier,
{
    pub fn new(
        metadata: VerifierMetadata,
        kms: KM,
        did_resolver: D,
        presentation_verifier: PV,
    ) -> Self {
        Self {
            metadata,
            did_resolver: DIDResolverWrapper(did_resolver),
            kms,
            presentation_verifier,
            _marker: Default::default(),
        }
    }

    fn validate_field_constraints(
        claims: &Json,
        constraints: &[ConstraintsField],
    ) -> Result<(), Error> {
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
}

#[async_trait]
impl<KH, KM, D, PV> Oid4VpVerifier for ConcreteOid4VpVerifier<KH, KM, D, PV>
where
    KH: KeyHandle,
    KM: Kms<KH>,
    D: DIDResolver,
    PV: PresentationVerifier,
{
    async fn authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        wallet_metadata: WalletMetadata,
        response_uri: Url,
    ) -> Result<AuthorizationRequest, Error> {
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

        let jwk = verifier_key.jwk().ok_or_else(|| {
            Error::InvalidKey("Failed to convert verifier key into JWK".to_string())
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
                SignerWrapper(verifier_key, jwk),
                &self.did_resolver,
            )
            .await
            .map_err(|err| Error::KeyResolutionFailed(format!("Failed to build session: {}", err)))?
            .build()
            .await
            .map_err(|err| Error::RequestCreationFailed(err.to_string()))?;

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
            client_id: ClientId(self.metadata.client_id.to_owned()),
            request_object_jwt: session.request_object_jwt().to_string(),
            authorization_endpoint,
        })
    }

    async fn verify_presentation(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        authorization_response: &AuthorizationResponse,
    ) -> Result<Json, Error> {
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
                .presentation_verifier
                .verify_presentation(nonce, &presentation)
                .await
                .map_err(|err| Error::VerificationFailed(err.to_string()))?;

            let constraints_fields = input_descriptor
                .constraints.fields.as_ref();

            if let Some(constraints) = constraints_fields {
                Self::validate_field_constraints(&claims, constraints)?;
            }

            result.insert(input_descriptor.id.clone(), claims);
        }

        Ok(result.into())
    }
}

struct SignerWrapper<S: SigningKey + Clone>(S, JWK);

#[async_trait]
impl<S: SigningKey + Clone> RequestSigner for SignerWrapper<S> {
    fn alg(&self) -> &str {
        self.0.alg().into()
    }

    fn jwk(&self) -> &JWK {
        &self.1
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let signature = self.0.sign(payload).await.map_err(|err| err)?;
        Ok(signature)
    }
}

struct DIDResolverWrapper<D: DIDResolver>(D);

#[async_trait]
impl<D: DIDResolver> ssi::did_resolve::DIDResolver for DIDResolverWrapper<D> {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let resolution = self
            .0
            .resolve(
                &did.to_string(),
                ResolveOptions {
                    input: input_metadata.clone(),
                },
            )
            .await;

        (resolution.metadata, resolution.doc, resolution.doc_metadata)
    }
}

#[cfg(test)]
mod tests {
    use crate::exchange::oid4vc::oid4vp::test_utils::{
        crate_authorization_response, create_test_client_metadata,
        create_test_presentation_definition, create_test_verifier_metadata,
    };
    use crate::exchange::oid4vc::oid4vp::verifier::{ConcreteOid4VpVerifier, Oid4VpVerifier};
    use crate::exchange::oid4vc::oid4vp::{default_wallet_metadata, AuthorizationUrlType};
    use crate::facade::facade_low_level::VerifierService;
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::did::UniversalResolver;
    use crate::impls::kms::inmem::LocalKms;
    use serde_json::json;

    #[tokio::test]
    async fn generate_authorization_request() {
        let did_resolver = UniversalResolver::new();
        let mut kms = LocalKms::new();
        let did_key = DIDKey::new();

        let client_metadata = create_test_client_metadata();
        let presentation_definition = create_test_presentation_definition();
        let nonce = "n0NcE";
        let verifier_metadata = create_test_verifier_metadata(&did_resolver, &mut kms).await;
        let presentation_verifier = VerifierService::new(&verifier_metadata.client_id);

        let verifier = ConcreteOid4VpVerifier::new(
            verifier_metadata,
            kms,
            did_resolver,
            presentation_verifier,
        );

        let request = verifier
            .authorization_request(
                &presentation_definition,
                nonce,
                default_wallet_metadata(),
                "https://verifier/auth".parse().unwrap(),
            )
            .await
            .unwrap();

        let by_value = request.as_url(AuthorizationUrlType::Value).unwrap();
        let by_reference = request
            .as_url(AuthorizationUrlType::Reference(
                "https://verifier/reqobject".parse().unwrap(),
            ))
            .unwrap();

        println!("{}", by_value);
        println!("{}", by_reference);
    }

    #[tokio::test]
    async fn verify_authorization_response() {
        let did_resolver = UniversalResolver::new();
        let mut kms = LocalKms::new();
        let did_key = DIDKey::new();

        let presentation_definition = create_test_presentation_definition();
        let claims = json!( {
            "vct": "https://credentials.example.com/identity_credential",
            "name": "John",
            "surname": "Doe",
            "date": "09/09/1989",
        });
        let nonce = "n0NcE";
        let verifier_metadata = create_test_verifier_metadata(&did_resolver, &mut kms).await;
        let response =
            crate_authorization_response(&verifier_metadata.client_id, &nonce, &claims, &mut kms)
                .await;
        let presentation_verifier = VerifierService::new(&verifier_metadata.client_id);

        let verifier = ConcreteOid4VpVerifier::new(
            verifier_metadata.clone(),
            kms,
            did_resolver,
            presentation_verifier,
        );

        let claims = verifier
            .verify_presentation(&presentation_definition, nonce, &response)
            .await
            .unwrap();

        println!("{}", claims);

        assert_eq!(
            claims["Identity-1"]["vct"],
            json!("https://credentials.example.com/identity_credential")
        );
        assert_eq!(claims["Identity-1"]["name"], json!("John"));
    }
}
