use crate::core_::kms::{KeyHandle, Kms};
use crate::core_::storage::Storage;
use crate::exchange;
use crate::exchange::oid4vc::oid4vp::verifier::{ConcreteOid4VpVerifier, Oid4VpVerifier};
use crate::exchange::oid4vc::oid4vp::{
    default_wallet_metadata, AuthorizationRequest, AuthorizationResponse, PresentationDefinition,
    VerifierMetadata,
};
use crate::facade::facade_low_level::VerifierService as PresentationVerifier;
use crate::impls::did::UniversalResolver;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use url::Url;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    VerifierError(#[from] exchange::oid4vc::oid4vp::error::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct StorageEntry {
    pub nonce: String,
    pub presentation_definition: PresentationDefinition,
}

/// Service for managing OIDC4VP verifications.
///
/// This service handles the creation of authorization requests and the verification of presentations.
pub struct VerifierService<'a> {
    verifier: Box<dyn Oid4VpVerifier + 'a>,
    storage: Box<dyn Storage<String, Json> + 'a>,
}

impl<'a> VerifierService<'a> {
    /// Creates a new `VerifierService`.
    ///
    /// # Arguments
    ///
    /// * `metadata` - Metadata required for the verifier.
    /// * `kms` - Key Management Service.
    /// * `storage` - Storage for caching requests.
    ///
    /// # Returns
    ///
    /// A new instance of `VerifierService`.
    pub fn new<KH, KM, ST>(
        metadata: VerifierMetadata,
        kms: KM,
        storage: ST,
    ) -> Self
    where
        KH: KeyHandle + 'a,
        KM: Kms<KH> + 'a,
        ST: Storage<String, Json> + 'a,
    {
        let verifier = ConcreteOid4VpVerifier::new(
            metadata.clone(),
            kms,
            UniversalResolver::new(),
            PresentationVerifier::new(&metadata.client_id),
        );

        VerifierService {
            verifier: Box::new(verifier),
            storage: Box::new(storage),
        }
    }

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
    pub async fn create_authorization_request(
        &mut self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        response_uri: Url,
    ) -> Result<AuthorizationRequest> {
        let request = self
            .verifier
            .authorization_request(
                presentation_definition,
                nonce,
                default_wallet_metadata(),
                response_uri,
            )
            .await
            .map_err(Error::VerifierError)?;

        let storage_entry = StorageEntry {
            nonce: nonce.to_string(),
            presentation_definition: presentation_definition.clone(),
        };

        let storage_entry = serde_json::to_value(&storage_entry).map_err(|err| {
            Error::VerifierError(
                exchange::oid4vc::oid4vp::error::Error::RequestCreationFailed(format!(
                    "Failed to serialize request metadata to JSON: {}",
                    err
                )),
            )
        })?;

        self.storage
            .put(presentation_definition.id.to_owned(), storage_entry)
            .await
            .map_err(|err| {
                Error::VerifierError(
                    exchange::oid4vc::oid4vp::error::Error::RequestCreationFailed(format!(
                        "Failed to save request metadata in storage: {}",
                        err
                    )),
                )
            })?;

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
    pub async fn verify_presentation(
        &mut self,
        auth_response: &AuthorizationResponse,
    ) -> Result<Json> {
        let value = self
            .storage
            .get(&auth_response.presentation_submission.definition_id)
            .await
            .map_err(|err| {
                Error::VerifierError(exchange::oid4vc::oid4vp::error::Error::InvalidResponse(
                    format!("Failed to retrieve request metadata from storage: {}", err),
                ))
            })?;

        let storage_entry: StorageEntry = serde_json::from_value(value.clone()).map_err(|err| {
            Error::VerifierError(exchange::oid4vc::oid4vp::error::Error::InvalidResponse(
                format!("Failed to deserialize request metadata from JSON: {}", err),
            ))
        })?;

        let claims = self
            .verifier
            .verify_presentation(
                &storage_entry.presentation_definition,
                &storage_entry.nonce,
                auth_response,
            )
            .await
            .map_err(Error::VerifierError)?;

        self.storage
            .delete(&auth_response.presentation_submission.definition_id)
            .await
            .map_err(|err| {
                Error::VerifierError(exchange::oid4vc::oid4vp::error::Error::InvalidResponse(
                    format!("Failed to delete request metadata from storage: {}", err),
                ))
            })?;

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use crate::exchange::oid4vc::oid4vp::test_utils::{
        crate_authorization_response, create_test_presentation_definition,
        create_test_verifier_metadata,
    };
    use crate::exchange::oid4vc::oid4vp::AuthorizationUrlType;
    use crate::facade::facade_oid4vp::VerifierService;
    use crate::impls::did::UniversalResolver;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::storage::inmem::InMemStorage;
    use serde_json::{json, Value as Json};
    use url::Url;

    #[tokio::test]
    async fn execute_verifier_flow() {
        let mut kms = LocalKms::new();
        let storage = InMemStorage::<String, Json>::new();
        let did_resolver = UniversalResolver::new();

        let claims = json!( {
            "vct": "https://credentials.example.com/identity_credential",
            "name": "John",
            "surname": "Doe",
            "date": "09/09/1989",
        });
        let verifier_metadata = create_test_verifier_metadata(&did_resolver, &mut kms).await;
        let presentation_definition = create_test_presentation_definition();
        let nonce = "n0NcE";
        let response_uri: Url = "https://verifier.org/auth".parse().unwrap();
        let auth_response =
            crate_authorization_response(&verifier_metadata.client_id, &nonce, &claims, &mut kms).await;

        let mut verifier_service =
            VerifierService::new(verifier_metadata, kms, storage);

        let auth_request = verifier_service.create_authorization_request(
            &presentation_definition,
            nonce,
            response_uri,
        ).await.unwrap();

        let by_value = auth_request.as_url(AuthorizationUrlType::Value).unwrap();
        let by_reference = auth_request
            .as_url(AuthorizationUrlType::Reference(
                "https://verifier/reqobject".parse().unwrap(),
            ))
            .unwrap();

        println!("{}", by_value);
        println!("{}", by_reference);

        let claims = verifier_service.verify_presentation(&auth_response).await.unwrap();

        println!("{}", claims);

        assert_eq!(
            claims["Identity-1"]["vct"],
            json!("https://credentials.example.com/identity_credential")
        );
        assert_eq!(claims["Identity-1"]["name"], json!("John"));
    }
}
