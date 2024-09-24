pub(crate) mod api;
pub(crate) mod holder;
pub(crate) mod verifier;

mod builder;
mod internal_error;
mod metadata;

pub use builder::Error as BuilderError;
pub use builder::HolderBuilder;
pub use builder::VerifierBuilder;
pub use internal_error::InternalError;

pub use api::*;

#[cfg(test)]
pub mod test_utils {
    use std::str::FromStr;

    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::did::{DIDResolver, DID};
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::kms;
    use crate::kms::{KeyID, Kms};
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata, VPMetadata};
    use crate::vc::formats::API;
    use crate::vc::oid4vp::AuthorizationResponse;
    use oid4vci::openidconnect::Nonce;

    use oid4vp::presentation_exchange::PresentationDefinition;
    use serde_json::{json, Value as Json};
    use ssi::did::DIDURL;

    const TEST_PRESENTATION_DEFINITION: &str = r#"{
        "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        "input_descriptors": [
            {
                "id": "Identity-1",
                "name": "Identity VC",
                "purpose": "We want an identity",
                "format": {
                    "vc+sd-jwt": {
                        "alg": ["EdDSA", "ES256K"]
                    }
                 },
                "constraints": {
                    "fields": [
                        {
                            "path": [
                                "$.vct",
                                "$.name"
                            ]
                        }
                    ]
                }
            }
        ]
    }"#;

    const TEST_PRESENTATION_SUBMISSION: &str = r#"{
        "id": "725199a1-6fbe-4447-be06-a0f9857e32fd",
        "definition_id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        "descriptor_map": [
            {
                "id": "Identity-1",
                "format": "vc+sd-jwt",
                "path": "$"
            }
        ]
    }"#;

    pub fn create_test_presentation_definition() -> PresentationDefinition {
        serde_json::from_str(TEST_PRESENTATION_DEFINITION).unwrap()
    }

    pub async fn create_authorization_response(
        verifier_id: &str,
        nonce: &str,
        claims: &Json,
    ) -> AuthorizationResponse {
        let kms = LocalKms::new();
        let (issuer_kid, issuer_key_handle, issuer_did) = generate_did_key(&kms).await;
        let issuer_did_url = DIDURL::from_str(&issuer_did).unwrap();

        let (holder_kid, holder_key_handle, holder_did) = generate_did_key(&kms).await;
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(claims),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            VCMetadata {
                vct: "https://credentials.example.com/identity_credential".to_owned(),
                lifetime: time::Duration::days(365),
                disclosures: vec!["$.name".to_owned(), "$.surname".to_owned()],
            },
        )
        .await
        .unwrap();

        let vp = SdJwtAPI::create_vp(
            &vc,
            holder_key_handle,
            Nonce::new(nonce.to_string()),
            verifier_id,
            VPMetadata {
                disclosures: json!({
                    "name" : true
                })
                .as_object()
                .unwrap()
                .to_owned(),
            },
        )
        .await
        .unwrap();

        AuthorizationResponse {
            vp_token: json!(vp),
            presentation_submission: serde_json::from_str(TEST_PRESENTATION_SUBMISSION).unwrap(),
        }
    }

    pub async fn generate_did_key(kms: &LocalKms) -> (KeyID, KeyHandle, DID) {
        let (issuer_kid, issuer_key_handle) = kms
            .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
            .await
            .unwrap();
        let issuer_did = DIDKey::new().generate(issuer_key_handle.clone()).unwrap();

        (issuer_kid, issuer_key_handle, issuer_did)
    }

    pub async fn generate_did_key_and_vm(
        kms: &LocalKms,
        did_resolver: &UniversalResolver,
    ) -> (KeyID, KeyHandle, DID, String) {
        let (kid, key_handle, did) = generate_did_key(kms).await;
        let vm_id = did_resolver
            .resolve_verification_method(&did)
            .await
            .unwrap()
            .id;

        (kid, key_handle, did, vm_id)
    }

    // TODO: move to the common test-util module
    pub async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
        let didkey = DIDKey::new();

        let (kid, kh) = kms
            .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
            .await
            .unwrap();

        let did = didkey.generate(kh).unwrap();

        let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

        (did, KeyMetadata { kid, did_url: vm })
    }
}
