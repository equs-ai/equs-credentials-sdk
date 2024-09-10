use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::{Nonce, ResponseMode};
use oid4vp::core::authorization_request::RequestIndirection;
use oid4vp::core::object::UntypedObject;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::fmt::Debug;
use tracing::{instrument, Level};
use url::Url;

use crate::vc::{Claims, Credential};
mod builder;
pub(crate) mod holder;
mod internal_error;
mod presentation_builder;
mod presentation_exchange;
pub(crate) mod verifier;

pub use builder::HolderBuilder;
pub use builder::VerifierBuilder;
use internal_error::InternalError;

// Data type
pub struct AuthorizationResponseMetadata {}
pub type CredentialMapping = HashMap<String, Vec<Credential>>;
pub type PresentationSubmission = oid4vp::presentation_exchange::PresentationSubmission;
pub type PresentationDefinition = oid4vp::presentation_exchange::PresentationDefinition;
pub type ClientMetadata = oid4vp::core::authorization_request::parameters::ClientMetadata;
pub type WalletMetadata = oid4vp::core::metadata::WalletMetadata;

/// A resolved `OID4VP` authorization request.
///
/// `client_id` Verifier's identifier.
/// `presentation_definition` Rules for the required Verifiable Presentation(s).
/// `nonce` Unique value to prevent replay attacks.
/// `response_mode` Method for returning the authorization response.
/// `response_uri` URI to send the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAuthRequest {
    pub client_id: String,
    pub presentation_definition: PresentationDefinition,
    pub nonce: Nonce,
    pub response_mode: ResponseMode,
    pub response_uri: Url,
}

/// An `OID4VP` authorization request.
///
/// It can be represented as a URL using the [auth_request_as_url] helper function.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    client_id: String,
    /// JWT containing Authorization Request parameters.
    pub request_object_jwt: String,
    authorization_endpoint: Url,
}

/// An OID4VP authorization response.
///
/// `vp_token` VP Token containing the Verifiable Presentation(s).
/// `presentation_submission` Details of the submitted presentation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationResponse {
    pub vp_token: serde_json::Value,
    pub presentation_submission: PresentationSubmission,
}

#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(transparent)]
    Internal { source: InternalError },
    //TODO: Add Protocol Error
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        Ok(())
    }
}

/// The `OID4VP` `Holder` API.
///
/// Supports presentation flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// # Features
///
/// * Fetches authorization requests from verifiers.
/// * Discovers credentials required for presentation requests.
/// * Supports both automatic and manual credential presentation.
///
/// # Implementation
///
/// Use [HolderBuilder] to instantiate a service.
/// Existing implementation of the API is not exposed.
#[async_trait]
pub trait Holder: Send + Sync {
    /// Fetches the `OID4VP` authorization request object from the provided URI.
    ///
    /// # Arguments
    ///
    /// * `auth_req_uri` - a request URI provided by the authorization URL.
    ///
    /// # Returns
    ///
    /// A `ResolvedAuthRequest` with the presentation definition and other relevant details on success.
    ///
    /// # Errors
    ///
    /// * [InternalError::UrlParse] - if the request URI is invalid
    /// * [InternalError::AuthorizationRequest] - if the resolution of the authorization request fails.
    async fn get_authorization_request(
        &self,
        auth_req_uri: &str,
    ) -> Result<ResolvedAuthRequest, Error>;

    /// Automatically presents credentials to the Verifier based on the authorization request.
    ///
    /// This method selects the first appropriate credential that matches the requirements of the authorization request.
    /// To present specific credentials, use [Holder::find_vcs_for_presentation] to discover suitable credentials and
    /// [Holder::present_credentials] to manually present them.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request containing the presentation requirements.
    /// * `metadata` - the metadata for the authorization response.
    ///
    /// # Returns
    ///
    /// A redirect URL if the presentation is successful, or `None` on success without redirection.
    ///
    /// # Errors
    ///
    /// * [InternalError::PresentationExchange] - if there is an issue with parsing the presentation metadata.
    /// * [InternalError::VC] - if a required credential is not found.
    /// * [InternalError::AuthorizationResponse] - if the submission of the authorization response fails.
    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, Error>;

    /// Finds verifiable credentials required for the presentation based on the authorization request.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request containing the presentation requirements.
    ///
    /// # Returns
    ///
    ///  A map of credentials that satisfy the authorization request's requirements.
    ///  If no matching credentials are found, an empty map is returned.
    ///
    /// # Errors
    ///
    /// * [InternalError::PresentationExchange] - If there is an issue with parsing the presentation metadata.
    /// * [InternalError::VC] - If an error occurs in the `vc::core` during credential search and extraction
    async fn find_vcs_for_presentation(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<CredentialMapping, Error>;

    /// Manually presents credentials to the Verifier.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request.
    /// * `credential_mapping` - the map of credentials required for the presentation.
    /// * `metadata` -the authorization response metadata.
    ///
    /// # Returns
    ///
    /// A redirect URL if the presentation is successful, or `None` on success without redirection.
    ///
    /// # Errors
    ///
    /// * [InternalError::PresentationExchange] - If there is an issue with parsing the presentation metadata.
    /// * [InternalError::ParseSnafu] - ff there is an issue with parsing the generated authorization response.
    /// * [InternalError::AuthorizationResponse] - if the submission of the authorization response fails.
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        credential_mapping: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, Error>;
}

/// The `OID4VP` `Verifier` API.
///
/// Supports presentation request and verification flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// # Features
///
/// * Create an authorization request.
/// * Verify the presentations.
///
/// # Implementation
///
/// Use [VerifierBuilder] to instantiate a service.
/// Existing implementation of the API is not exposed.
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Creates an `OID4VP` authorization request.
    ///
    /// # Arguments
    ///
    /// * `presentation_definition` - the presentation definition specifying the presentation requirements.
    /// * `nonce` - a string used to prevent replay attacks, representing the nonce for the request.
    /// * `response_uri` - the URL where the Holder will send the response.
    ///
    /// # Returns
    ///
    ///  The OID4VP authorization request on success.
    ///
    /// # Errors
    ///
    /// * [InternalError::VerifierSession] - if an error occurs during the creation of the verifier session.
    /// * [InternalError::KMS] - if there is an error during Issuer key resolution.
    /// * [InternalError::Parse] - if an error occurs during metadata parsing.
    /// * [InternalError::Storage] - if an error occurs during the storing the authorization request metadata.
    async fn create_authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        response_uri: Url,
    ) -> Result<AuthorizationRequest, Error>;

    /// Verifies the presentation provided by the Holder.
    ///
    /// # Arguments
    ///
    /// * `authorization_response` - the authorization response containing the VP token and presentation submission.
    ///
    /// # Returns
    ///
    /// * The verified claims as a JSON object on success.
    ///
    /// # Errors
    ///
    /// * [InternalError::Storage] - if an error occurs while retrieving the authorization request metadata.
    /// * [InternalError::AuthorizationResponse] - if an error occurs while parsing or validating the authorization response.
    /// * [InternalError::FormatNotSupported] - if the provided presentation format is not supported.
    /// * [InternalError::VC] - if the presentation verification fails.
    async fn verify_presentation(
        &self,
        authorization_response: &AuthorizationResponse,
    ) -> Result<Claims, Error>;
}

/// The types of authorization URLs.
///
/// It can be either a request URI from which to retrieve the request object, or the encrypted request object itself.
pub enum AuthorizationUrlType {
    Reference(Url),
    Value,
}

/// Converts an `AuthorizationRequest` into a URL.
///
/// # Arguments
///
/// * `req` - the authorization request.
/// * `type_` - type of authorization URL (by reference or by value).
///
/// # Returns
///
/// * An authorization request URL.
pub fn auth_request_as_url(req: &AuthorizationRequest, type_: AuthorizationUrlType) -> Url {
    let request_indirection = match type_ {
        AuthorizationUrlType::Value => RequestIndirection::ByValue(req.request_object_jwt.clone()),
        AuthorizationUrlType::Reference(at) => RequestIndirection::ByReference(at),
    };
    use oid4vp::core::authorization_request::AuthorizationRequest as SpruceAuthorizationRequest;

    SpruceAuthorizationRequest {
        client_id: req.client_id.clone(),
        request_indirection,
    }
    .to_url(req.authorization_endpoint.clone())
    .unwrap()
}

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

#[instrument(
    level = Level::TRACE,
    ret(level = Level::TRACE)
)]
fn default_client_metadata() -> ClientMetadata {
    ClientMetadata::try_from(
        serde_json::from_str::<serde_json::Value>(DEFAULT_CLIENT_METADATA).unwrap(),
    )
    .unwrap()
}

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

#[instrument(
    level = Level::TRACE,
    ret(level = Level::TRACE)
)]
fn default_wallet_metadata() -> WalletMetadata {
    WalletMetadata::try_from(
        serde_json::from_str::<UntypedObject>(DEFAULT_WALLET_METADATA).unwrap(),
    )
    .unwrap()
}

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
            (&holder_did_url, holder_key_handle),
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

#[cfg(test)]
mod tests {
    use mockito::Server;
    use oid4vp::presentation_exchange::{PresentationDefinition, PresentationSubmission};
    use rstest::rstest;
    use serde_json::{json, Map, Value as Json, Value};
    use ssi::did::DIDURL;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use url::{form_urlencoded, Url};

    use crate::crypto;
    use crate::crypto::Alg;
    use crate::did::universal::UniversalResolver;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::vault::Vault;
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata};
    use crate::vc::formats::API;
    use crate::vc::oid4vp::test_utils::{
        create_did_and_key_metadata, generate_did_key, generate_did_key_and_vm,
    };
    use crate::vc::oid4vp::HolderBuilder;
    use crate::vc::oid4vp::{
        auth_request_as_url, AuthorizationResponseMetadata, AuthorizationUrlType,
    };
    use crate::vc::oid4vp::{AuthorizationResponse, Holder};
    use crate::vc::oid4vp::{Verifier, VerifierBuilder};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};

    type ValidateClaims = dyn FnOnce(Json);

    struct Oid4VpTestCredential {
        pub id: &'static str,
        pub vct: &'static str,
        pub claims: Value,
    }

    struct Oid4VpTestCase {
        pub credentials: Vec<Oid4VpTestCredential>,
        pub presentation_definition: PresentationDefinition,
        pub validate: Box<ValidateClaims>,
    }

    fn single_presentation_case() -> Oid4VpTestCase {
        let identity = Oid4VpTestCredential {
            id: "Identity-1",
            vct: "https://credentials.example.com/identity_credential",
            claims: json!({
                "name": "John",
                "surname": "Doe",
                "address": "221B Baker Street",
                "date": "09/09/1989",
            }),
        };

        let presentation_definition = serde_json::from_value(json!({
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
                                "path": ["$.vct"],
                                "filter": {
                                    "type": "string",
                                    "const": "https://credentials.example.com/identity_credential"
                                }
                            },
                            {
                                "path": ["$.name"]
                            }
                        ]
                    }
                }
            ]
        }))
        .unwrap();

        let validate: Box<ValidateClaims> = Box::new(|claims| {
            assert_eq!(
                claims["Identity-1"]["vct"],
                json!("https://credentials.example.com/identity_credential")
            );
            assert_eq!(claims["Identity-1"]["name"], json!("John"));
        });

        Oid4VpTestCase {
            credentials: vec![identity],
            presentation_definition,
            validate,
        }
    }

    fn multiple_presentation_case() -> Oid4VpTestCase {
        let identity = Oid4VpTestCredential {
            id: "Identity-1",
            vct: "https://credentials.example.com/identity_credential",
            claims: json!({
                "name": "John",
                "surname": "Doe",
                "address": "221B Baker Street",
                "date": "09/09/1989",
            }),
        };

        let degree = Oid4VpTestCredential {
            id: "Degree-1",
            vct: "https://credentials.example.com/degree_credential",
            claims: json!({
                "name": "John",
                "surname": "Doe",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science and Arts"
                },
                "date": "09/09/2002",
            }),
        };

        let presentation_definition = serde_json::from_value(json!({
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
                                "path": ["$.vct"],
                                "filter": {
                                    "type": "string",
                                    "const": "https://credentials.example.com/identity_credential"
                                }
                            },
                            {
                                "path": ["$.name"]
                            }
                        ]
                    }
                },
                {
                    "id": "Degree-1",
                    "name": "Degree VC",
                    "format": {
                        "vc+sd-jwt": {
                            "alg": ["EdDSA", "ES256K"]
                        }
                     },
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {
                                    "type": "string",
                                    "const": "https://credentials.example.com/degree_credential"
                                }
                            },
                            {
                                "path": ["$.name"]
                            }
                        ]
                    }
                }
            ]
        }))
        .unwrap();

        let validate: Box<ValidateClaims> = Box::new(|claims| {
            assert_eq!(
                claims["Identity-1"]["vct"],
                json!("https://credentials.example.com/identity_credential")
            );
            assert_eq!(claims["Identity-1"]["name"], json!("John"));
            assert_eq!(
                claims["Degree-1"]["vct"],
                json!("https://credentials.example.com/degree_credential")
            );
            assert_eq!(
                claims["Degree-1"]["degree"]["type"],
                json!("BachelorDegree")
            );
        });

        Oid4VpTestCase {
            credentials: vec![identity, degree],
            presentation_definition,
            validate,
        }
    }

    #[rstest]
    #[case::single_presentation(single_presentation_case())]
    #[case::multiple_presentation(multiple_presentation_case())]
    #[tokio::test]
    async fn execute_oid4vp_flow(#[case] test_case: Oid4VpTestCase) {
        println!("7. Store Credential");
        let holder_kms = LocalKms::new();
        let (holder_kid, holder_kh, holder_did, holder_vm) =
            generate_did_key_and_vm(&holder_kms, &UniversalResolver::new()).await;
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let holder_vault = InMemVault::new();

        // Create and store VCs
        for credential in &test_case.credentials {
            let (vc, vc_meta) = create_vc(
                credential.vct,
                &holder_did_url,
                holder_kh.clone(),
                credential.claims.clone(),
            )
            .await;
            holder_vault.store_credential(vc, &vc_meta).await.unwrap();
        }

        // Create Holder and Verifier
        let holder = holder(
            holder_kms,
            holder_vault,
            KeyMetadata {
                did_url: holder_vm,
                kid: holder_kid,
            },
        )
        .await;

        let verifier = verifier().await;

        // Generate mocks
        let mut verifier_server = Server::new_async().await;
        let verifier_base_url = verifier_server.url();

        println!("8.1 Verifier: Create Authorization Request");
        // TODO: We should not use a test constant for Presentation Definition here,
        //  we need to build a new one (as every Verifier will build it).
        let nonce = "n0NcE";
        let response_uri: Url = format!("{}/auth", &verifier_base_url).parse().unwrap();
        let auth_request = verifier
            .create_authorization_request(&test_case.presentation_definition, nonce, response_uri)
            .await
            .unwrap();

        let request_uri: Url = format!("{}/req-object", &verifier_base_url)
            .parse()
            .unwrap();
        let by_value = auth_request_as_url(&auth_request, AuthorizationUrlType::Value);
        let by_reference = auth_request_as_url(
            &auth_request,
            AuthorizationUrlType::Reference(
                format!("{}/req-object", &verifier_base_url)
                    .parse()
                    .unwrap(),
            ),
        );

        println!("Request object passed by value: {}", by_value);
        println!("Request object passed by reference: {}", by_reference);

        mock_request_uri_endpoint(&mut verifier_server, &auth_request.request_object_jwt);
        let response_mutex = mock_response_uri_endpoint(&mut verifier_server);

        println!("8.2 Holder: Get Authorization Request");
        let request_object = holder
            .get_authorization_request(by_reference.as_str())
            .await
            .unwrap();

        println!("{:?}", &request_object);

        println!("9. Present Credential Auto");
        holder
            .present_credentials_auto(&request_object, &AuthorizationResponseMetadata {})
            .await
            .unwrap();

        println!("10. Verify Presentation");
        let auth_response = response_mutex.lock().await.clone().unwrap();

        println!("{:?}", auth_response);

        let claims = verifier.verify_presentation(&auth_response).await.unwrap();

        println!("Presentation Claims: {}", claims);

        (test_case.validate)(claims);
    }

    fn mock_request_uri_endpoint(verifier_server: &mut Server, request_object_jwt: &str) {
        verifier_server
            .mock("GET", "/req-object")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body(request_object_jwt)
            .create();
    }

    fn mock_response_uri_endpoint(
        verifier_server: &mut Server,
    ) -> Arc<Mutex<Option<AuthorizationResponse>>> {
        let authorization_response = Arc::new(Mutex::new(None));

        let response_clone = Arc::clone(&authorization_response);

        verifier_server
            .mock("POST", "/auth")
            .with_body_from_request(move |request| {
                let mut json_map = Map::new();
                for (key, value) in form_urlencoded::parse(request.body().unwrap()) {
                    // Try to parse the value as JSON, fall back to treating it as a plain string
                    let json_value: Json =
                        serde_json::from_str(&value).unwrap_or(Json::String(value.to_string()));
                    json_map.insert(key.to_string(), json_value);
                }

                let vp_token = json_map.get("vp_token").unwrap().clone();
                let presentation_submission: PresentationSubmission = serde_json::from_value(
                    json_map.get("presentation_submission").unwrap().clone(),
                )
                .unwrap();

                let mut locked_response = response_clone.try_lock().unwrap();
                *locked_response = Some(AuthorizationResponse {
                    vp_token,
                    presentation_submission,
                });

                vec![]
            })
            .create();

        authorization_response
    }

    async fn verifier() -> impl Verifier {
        let kms = LocalKms::new();

        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        VerifierBuilder::new(kms, key_metadata, did)
            .build()
            .await
            .unwrap()
    }

    async fn holder(kms: LocalKms, vault: InMemVault, key_metadata: KeyMetadata) -> impl Holder {
        HolderBuilder::new(kms, vault, key_metadata, "wallet-dev".to_string())
            .build()
            .await
            .unwrap()
    }

    async fn create_vc(
        vct: &str,
        holder_did_url: &DIDURL,
        holder_kh: impl crypto::Key,
        claims: Json,
    ) -> (Credential, CredentialMetadata) {
        // Generate Issuer DID and Key
        let kms = LocalKms::new();
        let (kid, kh, did) = generate_did_key(&kms).await;
        println!("Issuer DID: {}", did);

        let did_url = DIDURL::from_str(&did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(&claims),
            (&did_url, kh),
            (holder_did_url, holder_kh),
            VCMetadata {
                vct: vct.to_owned(),
                lifetime: time::Duration::days(365),
                disclosures: vec![
                    "$.name".to_owned(),
                    "$.surname".to_owned(),
                    "$.address".to_owned(),
                ],
            },
        )
        .await
        .unwrap();

        println!("Credential: {}", vc);

        let vc_meta = CredentialMetadata {
            type_: vct.to_string(),
            format: VCFormat::SdJwtVc,
            alg: Some(Alg::ES256),
            tags: vec![],
        };

        (Credential::SdJwt(vc), vc_meta)
    }
}
