use oid4vp::core::authorization_request::{
    AuthorizationRequest as SpruceAuthorizationRequest, RequestIndirection,
};
use oid4vp::core::object::UntypedObject;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use url::Url;

use error::Error;

pub mod error;
pub mod holder;
pub mod presentation_builder;
pub mod verifier;
pub mod verifier_profile;

pub type PresentationSubmission = oid4vp::presentation_exchange::PresentationSubmission;
pub type PresentationDefinition = oid4vp::presentation_exchange::PresentationDefinition;
pub type ClientMetadata = oid4vp::core::authorization_request::parameters::ClientMetadata;
pub type WalletMetadata = oid4vp::core::metadata::WalletMetadata;
pub type KeyMetadata = crate::facade::facade_low_level::KeyMetadata;

const DEFAULT_WALLET_METADATA: &str = r#"{
    "issuer": "https://self-issued.me/v2",
    "authorization_endpoint": "openid4vp://",
    "response_types_supported": [
        "vp_token"
    ],
    "vp_formats_supported":
    {
        "vc+sd-jwt": {
            "alg_values_supported": ["EdDSA", "ES256"]
        }
    },
    "client_id_schemes_supported": [
        "did"
    ],
    "request_object_signing_alg_values_supported": [
        "EdDSA",
        "ES256"
    ]
}"#;

const DEFAULT_CLIENT_METADATA: &str = r#"{
    "vp_formats": {
        "vc+sd-jwt": {
            "alg": [
                "EdDSA",
                "ES256"
            ]
        }
    }
}"#;

pub fn default_wallet_metadata() -> WalletMetadata {
    WalletMetadata::try_from(
        serde_json::from_str::<UntypedObject>(DEFAULT_WALLET_METADATA).unwrap(),
    )
    .unwrap()
}

pub fn default_client_metadata() -> ClientMetadata {
    ClientMetadata::try_from(serde_json::from_str::<Json>(DEFAULT_CLIENT_METADATA).unwrap())
        .unwrap()
}

pub enum AuthorizationUrlType {
    Reference(Url),
    Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    client_id: String,
    pub request_object_jwt: String,
    authorization_endpoint: Url,
}

impl AuthorizationRequest {
    pub fn as_url(&self, type_: AuthorizationUrlType) -> Result<Url, Error> {
        let request_indirection = match type_ {
            AuthorizationUrlType::Value => {
                RequestIndirection::ByValue(self.request_object_jwt.clone())
            }
            AuthorizationUrlType::Reference(at) => RequestIndirection::ByReference(at),
        };

        SpruceAuthorizationRequest {
            client_id: self.client_id.clone(),
            request_indirection,
        }
        .to_url(self.authorization_endpoint.clone())
        .map_err(|err| {
            Error::RequestCreationFailed(format!(
                "Cannot convert Authorization Request into URL: {}",
                err
            ))
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationResponse {
    pub vp_token: Json,
    pub presentation_submission: PresentationSubmission,
}

#[derive(Debug, Clone)]
pub struct VerifierMetadata {
    pub client_id: String,
    pub key_metadata: KeyMetadata,
    pub client_metadata: ClientMetadata,
}

#[cfg(test)]
pub mod test_utils {
    use std::str::FromStr;

    use oid4vci::openidconnect::Nonce;
    use serde_json::{json, Value as Json};
    use ssi::did::DIDURL;

    use crate::core_::did::{DIDResolver, DID};
    use crate::core_::kms;
    use crate::core_::kms::{KeyID, Kms};
    use crate::core_::vc::API;
    use crate::exchange::oid4vc::oid4vp::{
        default_client_metadata, AuthorizationResponse, PresentationDefinition, VerifierMetadata,
    };
    use crate::facade::facade_low_level::KeyMetadata;
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::did::UniversalResolver;
    use crate::impls::kms::inmem::{KeyHandle, LocalKms};
    use crate::impls::vc::sd_jwt_vc::{SdJwtAPI, VCMetadata, VPMetadata};

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

    pub async fn create_test_verifier_metadata(
        did_resolver: &UniversalResolver,
        kms: &mut LocalKms,
    ) -> VerifierMetadata {
        let (verifier_kid, verifier_key_handle, verifier_did, verifier_vm_id) =
            generate_did_key_and_vm(kms, did_resolver).await;

        VerifierMetadata {
            client_id: verifier_did.to_owned(),
            key_metadata: KeyMetadata {
                did_url: verifier_vm_id,
                kid: verifier_kid,
            },
            client_metadata: default_client_metadata(),
        }
    }

    pub fn create_test_presentation_definition() -> PresentationDefinition {
        serde_json::from_str(TEST_PRESENTATION_DEFINITION).unwrap()
    }

    pub async fn crate_authorization_response(
        verifier_id: &str,
        nonce: &str,
        claims: &Json,
        kms: &mut LocalKms,
    ) -> AuthorizationResponse {
        let (issuer_kid, issuer_key_handle, issuer_did) = generate_did_key(kms).await;
        let issuer_did_url = DIDURL::from_str(&issuer_did).unwrap();

        let (holder_kid, holder_key_handle, holder_did) = generate_did_key(kms).await;
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(&claims),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            VCMetadata {
                lifetime: time::Duration::days(365),
                disclosures: vec!["$.name".to_owned(), "$.surname".to_owned()],
            },
        )
        .await
        .unwrap();

        let vp = SdJwtAPI::create_vp(
            &vc,
            (&holder_did_url, holder_key_handle),
            Nonce::new(nonce.to_string()),
            &verifier_id,
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

    pub async fn generate_did_key(kms: &mut LocalKms) -> (KeyID, KeyHandle, DID) {
        let (issuer_kid, issuer_key_handle) = kms
            .create_and_handle(&kms::KeyType::P256, kms::CreateOptions {})
            .await
            .unwrap();
        let issuer_did = DIDKey::new().generate(issuer_key_handle.clone()).unwrap();

        (issuer_kid, issuer_key_handle, issuer_did)
    }

    pub async fn generate_did_key_and_vm(
        kms: &mut LocalKms,
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
}
