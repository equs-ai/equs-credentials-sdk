use async_trait::async_trait;
use crate::core_::kms::{KeyHandle, Kms};
use crate::core_::storage::Storage;
use crate::exchange;
use crate::exchange::oid4vc::oid4vp::verifier::{ConcreteOid4VpVerifier, Oid4VpVerifier};
use crate::exchange::oid4vc::oid4vp::{
    default_client_metadata, default_wallet_metadata, AuthorizationRequest, AuthorizationResponse,
    KeyMetadata, PresentationDefinition, VerifierMetadata,
};
use crate::facade::facade_low_level::VerifierService as PresentationVerifier;
use crate::impls::did::UniversalResolver;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use url::Url;
use crate::facade::facade_oid4vc::{Error, Result, Verifier};

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
    /// * `client_id` - Verifier ID
    /// * `key_metadata` - Verifier signing key metadata
    /// * `kms` - Key Management Service.
    /// * `storage` - Storage for caching requests.
    ///
    /// # Returns
    ///
    /// A new instance of `VerifierService`.
    pub fn new<KH, KM, ST>(
        client_id: String,
        key_metadata: KeyMetadata,
        kms: KM,
        storage: ST,
    ) -> Self
    where
        KH: KeyHandle + 'a,
        KM: Kms<KH> + 'a,
        ST: Storage<String, Json> + 'a,
    {
        let presentation_verifier = PresentationVerifier::new(&client_id);
        let verifier = ConcreteOid4VpVerifier::new(
            VerifierMetadata {
                client_id,
                key_metadata,
                client_metadata: default_client_metadata(),
            },
            kms,
            UniversalResolver::new(),
            presentation_verifier,
        );

        VerifierService {
            verifier: Box::new(verifier),
            storage: Box::new(storage),
        }
    }
}

#[async_trait]
impl Verifier for VerifierService<'_> {
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
    async fn create_authorization_request(
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
            .map_err(Error::Verifier)?;

        let storage_entry = StorageEntry {
            nonce: nonce.to_string(),
            presentation_definition: presentation_definition.clone(),
        };

        let storage_entry = serde_json::to_value(&storage_entry).map_err(|err| {
            Error::Verifier(
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
                Error::Verifier(
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
    async fn verify_presentation(
        &mut self,
        auth_response: &AuthorizationResponse,
    ) -> Result<Json> {
        let value = self
            .storage
            .get(&auth_response.presentation_submission.definition_id)
            .await
            .map_err(|err| {
                Error::Verifier(exchange::oid4vc::oid4vp::error::Error::InvalidResponse(
                    format!("Failed to retrieve request metadata from storage: {}", err),
                ))
            })?;

        let storage_entry: StorageEntry = serde_json::from_value(value.clone()).map_err(|err| {
            Error::Verifier(exchange::oid4vc::oid4vp::error::Error::InvalidResponse(
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
            .map_err(Error::Verifier)?;

        self.storage
            .delete(&auth_response.presentation_submission.definition_id)
            .await
            .map_err(|err| {
                Error::Verifier(exchange::oid4vc::oid4vp::error::Error::InvalidResponse(
                    format!("Failed to delete request metadata from storage: {}", err),
                ))
            })?;

        Ok(claims)
    }
}
