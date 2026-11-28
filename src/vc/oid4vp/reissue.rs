//! Re-signs a stored Request Object for a Request URI fetched by POST (OpenID4VP 1.0 §5.10).

use std::borrow::Cow;

use openid4vp::core::authorization_request::AuthorizationRequestObject;
use openid4vp::core::authorization_request::parameters::{Audience, WalletNonce};
use openid4vp::core::object::UntypedObject;
use openid4vp::verifier::client::Client as _;
use snafu::{ResultExt, ensure};
use ssi::jwk::JWK;

use crate::did::{JWKResolver, ProofValidationError};
use crate::kms::KeyHandle;
use crate::vc::oid4vp::internal_error::{Oid4VpLibSnafu, RequestObjectReissueSnafu};
use crate::vc::oid4vp::signer::Signer;
use crate::vc::oid4vp::verifier::{
    DecentralizedIdentifierClient, Error, Result, VerifierMetadata, X509Variant,
};
use crate::vc::oid4vp::{AuthorizationRequestChanges, ClientId, ClientIdPrefix};
#[cfg(not(target_arch = "wasm32"))]
use crate::vc::oid4vp::{Certificate, X509Client, ensure_leaf_matches_signing_key};

const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

enum Identity<'a> {
    Did(&'a str),
    #[cfg(not(target_arch = "wasm32"))]
    X509(Vec<Certificate>, X509Variant),
}

/// Backs [`crate::vc::oid4vp::Verifier::reissue_authorization_request`].
pub(super) async fn reissue_authorization_request<KH: KeyHandle + 'static>(
    key: KH,
    metadata: &VerifierMetadata,
    stored_jwt: &str,
    changes: AuthorizationRequestChanges,
) -> Result<String> {
    let identity = identity(metadata, &key)?;
    let signer = Signer::new(key).map_err(|e| refused(format!("unusable signing key: {e}")))?;
    let jwk = openid4vp::signer::Signer::jwk(&signer)
        .map_err(|e| refused(format!("signing key has no public JWK: {e}")))?;

    let (header, payload) = ssi::claims::jws::decode_verify(stored_jwt, &jwk)
        .map_err(|e| refused(format!("stored object does not verify under the key: {e}")))?;
    ensure!(
        header.type_.as_deref() == Some(REQUEST_OBJECT_TYP),
        RequestObjectReissueSnafu {
            details: format!("stored typ is not {REQUEST_OBJECT_TYP}"),
        }
    );
    let mut object: UntypedObject = serde_json::from_slice(&payload)
        .map_err(|e| refused(format!("stored payload is not a JSON object: {e}")))?;

    let changes = effective_changes(changes, &object);
    ensure!(
        changes.wallet_nonce.is_some() || changes.audience.is_some(),
        RequestObjectReissueSnafu {
            details: "nothing to change",
        }
    );
    if let Some(wallet_nonce) = changes.wallet_nonce {
        object.insert(WalletNonce(wallet_nonce));
    }
    if let Some(audience) = changes.audience {
        object.insert(Audience(audience));
    }
    let reissued = AuthorizationRequestObject::try_from(object)
        .map_err(|e| refused(format!("stored payload is not a Request Object: {e}")))?;
    ensure_same_client_id(&metadata.client_id, reissued.client_id())?;

    match identity {
        Identity::Did(did_url) => {
            ensure!(
                header.key_id.as_deref() == Some(did_url),
                RequestObjectReissueSnafu {
                    details: "stored kid differs from the verification method",
                }
            );
            let client = DecentralizedIdentifierClient::new(
                did_url.to_string(),
                signer,
                OwnKeyResolver { jwk },
            )
            .await
            .map_err(|e| refused(format!("cannot build the DID client: {e:#}")))?;
            ensure_same_client_id(client.id(), reissued.client_id())?;
            Ok(client
                .generate_request_object_jwt(&reissued)
                .await
                .context(Oid4VpLibSnafu)?)
        }
        #[cfg(not(target_arch = "wasm32"))]
        Identity::X509(x5c, variant) => {
            ensure!(
                header.x509_certificate_chain.as_deref() == Some(der_chain(&x5c)?.as_slice()),
                RequestObjectReissueSnafu {
                    details: "stored x5c differs from the certificate chain",
                }
            );
            let signer: std::sync::Arc<
                dyn openid4vp::signer::Signer<Error = anyhow::Error> + Send + Sync,
            > = std::sync::Arc::new(signer);
            let client = X509Client::new(x5c, signer, variant)
                .map_err(|e| refused(format!("cannot build the X.509 client: {e:#}")))?;
            ensure_same_client_id(client.id(), reissued.client_id())?;
            Ok(client
                .generate_request_object_jwt(&reissued)
                .await
                .context(Oid4VpLibSnafu)?)
        }
    }
}

fn identity<'a, KH: KeyHandle>(metadata: &'a VerifierMetadata, key: &KH) -> Result<Identity<'a>> {
    let variant = match metadata.client_id.get_prefix() {
        ClientIdPrefix::X509SanDns => X509Variant::SanDns,
        ClientIdPrefix::X509Hash => X509Variant::Hash,
        _ => return Ok(Identity::Did(&metadata.key_metadata.did_url)),
    };
    x509_identity(metadata, key, variant)
}

#[cfg(not(target_arch = "wasm32"))]
fn x509_identity<'a, KH: KeyHandle>(
    metadata: &'a VerifierMetadata,
    key: &KH,
    variant: X509Variant,
) -> Result<Identity<'a>> {
    let pem = metadata
        .x5c_chain
        .as_deref()
        .ok_or_else(|| refused("no certificate chain configured".to_string()))?;
    let x5c = Certificate::load_pem_chain(pem)
        .map_err(|e| refused(format!("cannot parse the certificate chain: {e}")))?;
    let leaf = x5c
        .first()
        .ok_or_else(|| refused("empty certificate chain".to_string()))?;
    ensure_leaf_matches_signing_key(leaf, key)
        .map_err(|e| refused(format!("leaf does not certify the signing key: {e}")))?;
    Ok(Identity::X509(x5c, variant))
}

#[cfg(target_arch = "wasm32")]
fn x509_identity<'a, KH: KeyHandle>(
    _metadata: &'a VerifierMetadata,
    _key: &KH,
    variant: X509Variant,
) -> Result<Identity<'a>> {
    Err(refused(format!(
        "the {} client-id prefix is not supported on wasm32",
        variant.to_prefix()
    )))
}

fn effective_changes(
    changes: AuthorizationRequestChanges,
    stored: &UntypedObject,
) -> AuthorizationRequestChanges {
    let stored_audience = stored
        .get::<Audience>()
        .and_then(|aud| aud.ok())
        .map(|aud| aud.0);
    AuthorizationRequestChanges {
        wallet_nonce: changes.wallet_nonce.filter(|nonce| !nonce.is_empty()),
        audience: changes
            .audience
            .filter(|aud| !aud.is_empty() && Some(aud) != stored_audience.as_ref()),
    }
}

fn refused(details: String) -> Error {
    RequestObjectReissueSnafu { details }.build().into()
}

fn ensure_same_client_id(expected: &ClientId, stored: &ClientId) -> Result<()> {
    ensure!(
        expected == stored,
        RequestObjectReissueSnafu {
            details: format!("expected client_id {expected}, the stored object has {stored}"),
        }
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn der_chain(x5c: &[Certificate]) -> Result<Vec<String>> {
    use base64::Engine;
    use x509_cert::der::Encode;

    x5c.iter()
        .map(|certificate| {
            certificate
                .to_der()
                .map(|der| base64::prelude::BASE64_STANDARD.encode(der))
                .map_err(|e| refused(format!("cannot encode the certificate chain: {e}")))
        })
        .collect()
}

/// Returns the signing key's own JWK, so no DID document is resolved.
struct OwnKeyResolver {
    jwk: JWK,
}

impl JWKResolver for OwnKeyResolver {
    async fn fetch_public_jwk(
        &self,
        _key_id: Option<&str>,
    ) -> core::result::Result<Cow<'_, JWK>, ProofValidationError> {
        Ok(Cow::Borrowed(&self.jwk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::kms::Kms as _;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc;
    use crate::vc::core::api::KeyMetadata;
    use crate::vc::oid4vp::tests::fixtures::VERIFIER_URL;
    use crate::vc::oid4vp::tests::fixtures::multi_presentation::auth_response_options;
    use crate::vc::oid4vp::tests::fixtures::single_presentation;
    use crate::vc::oid4vp::tests::utils::{
        TestVerifierService, build_url, generate_client_metadata, self_signed_certificate_pem,
    };
    use crate::vc::oid4vp::verifier::VerifierService;
    use crate::vc::oid4vp::x509::client_id_from_x509_chain;
    use crate::vc::oid4vp::{
        AuthorizationRequestMetadata, HttpMethodForAuth, InternalError, PassAuthRequestObject,
        Verifier as _, VerifierInfoEntry,
    };
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use openid4vp::core::authorization_request::parameters::VerifierInfoData;
    use openid4vp::utils::NonEmptyVec;
    use rstest::rstest;
    use serde_json::{Map, Value, json};
    use std::collections::HashMap;
    use url::Url;

    const NONCE: &str = "wallet-nonce-+/=&";
    const DNS_NAME: &str = "verifier.example";
    const WALLET: &str = "https://wallet.example";

    struct Fixture {
        kms: LocalKms,
        key_metadata: KeyMetadata,
        client_id: ClientId,
        verifier: TestVerifierService,
        uri: Url,
        stored_jwt: String,
    }

    async fn verifier(
        kms: &LocalKms,
        key_metadata: KeyMetadata,
        client_id: ClientId,
    ) -> TestVerifierService {
        let did = key_metadata.did_url.split('#').next().unwrap().to_string();
        VerifierService::new(
            vc::core::VerifierService::new(&did, UniversalResolver::default()),
            kms.clone(),
            LocalNonceHandler::default(),
            MockHttpClient::new(),
            client_id,
            key_metadata,
            UniversalResolver::default(),
            Some(generate_client_metadata(kms).await),
        )
    }

    async fn x509_verifier(
        kms: &LocalKms,
        key_metadata: KeyMetadata,
        pem: &str,
        variant: X509Variant,
    ) -> TestVerifierService {
        let chain = Certificate::load_pem_chain(pem.as_bytes()).unwrap();
        let client_id = client_id_from_x509_chain(&chain, variant).unwrap();
        verifier(kms, key_metadata, client_id)
            .await
            .with_x509_certificate_chain(pem.as_bytes().to_vec())
    }

    async fn create_request(verifier: &TestVerifierService) -> (Url, String) {
        let entries = NonEmptyVec::new(VerifierInfoEntry {
            format: "urn:etsi:119472-2:rc".to_string(),
            data: VerifierInfoData::String("registration-certificate".to_string()),
            credential_ids: None,
        });
        let (uri, session) = verifier
            .create_authorization_request(
                &single_presentation::sd_jwt::presentation_definition(),
                &AuthorizationRequestMetadata {
                    auth_response_options: auth_response_options(
                        build_url(VERIFIER_URL, "auth"),
                        None,
                    ),
                    transaction_data: None,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: build_url(VERIFIER_URL, "request"),
                        method: Some(HttpMethodForAuth::POST),
                    },
                    expected_origins: None,
                    client_metadata: None,
                    verifier_info: Some(entries.into()),
                },
                None,
            )
            .await
            .unwrap();
        (uri, session.auth_request_jwt.unwrap())
    }

    async fn did_fixture() -> Fixture {
        let kms = LocalKms::new();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;
        let client_id = ClientId::from_did(&did).unwrap();
        let verifier = verifier(&kms, key_metadata.clone(), client_id.clone()).await;
        let (uri, stored_jwt) = create_request(&verifier).await;
        Fixture {
            kms,
            key_metadata,
            client_id,
            verifier,
            uri,
            stored_jwt,
        }
    }

    async fn x509_fixture(variant: X509Variant) -> Fixture {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let key = kms.get(&key_metadata.kid).await.unwrap();
        let pem = self_signed_certificate_pem(&key, DNS_NAME);
        let chain = Certificate::load_pem_chain(pem.as_bytes()).unwrap();
        let client_id = client_id_from_x509_chain(&chain, variant).unwrap();
        let verifier = x509_verifier(&kms, key_metadata.clone(), &pem, variant).await;
        let (uri, stored_jwt) = create_request(&verifier).await;
        Fixture {
            kms,
            key_metadata,
            client_id,
            verifier,
            uri,
            stored_jwt,
        }
    }

    fn claims(jwt: &str) -> Map<String, Value> {
        let (_, payload) = ssi::claims::jws::decode_unverified(jwt).unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    fn header(jwt: &str) -> ssi::claims::jws::Header {
        ssi::claims::jws::decode_unverified(jwt).unwrap().0
    }

    async fn public_jwk(fixture: &Fixture) -> JWK {
        let key = fixture.kms.get(&fixture.key_metadata.kid).await.unwrap();
        openid4vp::signer::Signer::jwk(&Signer::new(key).unwrap()).unwrap()
    }

    fn nonce_only() -> AuthorizationRequestChanges {
        AuthorizationRequestChanges {
            wallet_nonce: Some(NONCE.to_string()),
            audience: None,
        }
    }

    fn audience(aud: &str) -> AuthorizationRequestChanges {
        AuthorizationRequestChanges {
            wallet_nonce: None,
            audience: Some(aud.to_string()),
        }
    }

    async fn is_refused(
        verifier: &TestVerifierService,
        stored_jwt: &str,
        changes: AuthorizationRequestChanges,
    ) -> bool {
        let error = verifier
            .reissue_authorization_request(stored_jwt, changes)
            .await
            .unwrap_err();
        matches!(
            error,
            Error::Internal {
                source: InternalError::RequestObjectReissue { .. }
            }
        )
    }

    async fn sign_with_own_key(
        kms: &LocalKms,
        key_metadata: &KeyMetadata,
        object: UntypedObject,
    ) -> String {
        let key = kms.get(&key_metadata.kid).await.unwrap();
        let signer = Signer::new(key).unwrap();
        let jwk = openid4vp::signer::Signer::jwk(&signer).unwrap();
        let client = DecentralizedIdentifierClient::new(
            key_metadata.did_url.clone(),
            signer,
            OwnKeyResolver { jwk },
        )
        .await
        .unwrap();
        let object = AuthorizationRequestObject::try_from(object).unwrap();
        client.generate_request_object_jwt(&object).await.unwrap()
    }

    async fn sign_raw(fixture: &Fixture, header: Value, payload: &Value) -> String {
        let key = fixture.kms.get(&fixture.key_metadata.kid).await.unwrap();
        let signer = Signer::new(key).unwrap();
        let mut header = header;
        header["alg"] = json!(openid4vp::signer::Signer::alg(&signer).unwrap());
        openid4vp::utils::generate_jwt(header, payload, &signer)
            .await
            .unwrap()
    }

    fn with_claims(stored_jwt: &str, extra: &[(&str, Value)]) -> UntypedObject {
        let mut object = claims(stored_jwt);
        for (key, value) in extra {
            object.insert(key.to_string(), value.clone());
        }
        serde_json::from_value(Value::Object(object)).unwrap()
    }

    async fn resigned(fixture: &Fixture, extra: &[(&str, Value)]) -> String {
        sign_with_own_key(
            &fixture.kms,
            &fixture.key_metadata,
            with_claims(&fixture.stored_jwt, extra),
        )
        .await
    }

    #[tokio::test]
    async fn did_reissue_echoes_the_wallet_nonce_and_keeps_every_other_claim() {
        let fixture = did_fixture().await;

        let reissued = fixture
            .verifier
            .reissue_authorization_request(&fixture.stored_jwt, nonce_only())
            .await
            .unwrap();

        let mut expected = claims(&fixture.stored_jwt);
        expected.insert("wallet_nonce".to_string(), json!(NONCE));
        assert_eq!(claims(&reissued), expected);
        assert!(expected.contains_key("verifier_info"));
        assert_eq!(header(&reissued).key_id, header(&fixture.stored_jwt).key_id);
        ssi::claims::jws::decode_verify(&reissued, &public_jwk(&fixture).await).unwrap();
    }

    #[rstest]
    #[case::hash(X509Variant::Hash)]
    #[case::san_dns(X509Variant::SanDns)]
    #[tokio::test]
    async fn x509_reissue_keeps_the_x5c_header(#[case] variant: X509Variant) {
        let fixture = x509_fixture(variant).await;

        let reissued = fixture
            .verifier
            .reissue_authorization_request(&fixture.stored_jwt, nonce_only())
            .await
            .unwrap();

        assert_eq!(
            header(&reissued).x509_certificate_chain,
            header(&fixture.stored_jwt).x509_certificate_chain
        );
        let mut expected = claims(&fixture.stored_jwt);
        expected.insert("wallet_nonce".to_string(), json!(NONCE));
        assert_eq!(claims(&reissued), expected);
        ssi::claims::jws::decode_verify(&reissued, &public_jwk(&fixture).await).unwrap();
    }

    #[tokio::test]
    async fn audience_replaces_the_stored_aud() {
        let fixture = did_fixture().await;

        let reissued = fixture
            .verifier
            .reissue_authorization_request(&fixture.stored_jwt, audience(WALLET))
            .await
            .unwrap();

        let reissued = claims(&reissued);
        assert_eq!(reissued["aud"], json!(WALLET));
        assert!(!reissued.contains_key("wallet_nonce"));
    }

    #[tokio::test]
    async fn nonce_and_audience_are_set_together() {
        let fixture = did_fixture().await;
        let changes = AuthorizationRequestChanges {
            wallet_nonce: Some(NONCE.to_string()),
            audience: Some(WALLET.to_string()),
        };

        let reissued = fixture
            .verifier
            .reissue_authorization_request(&fixture.stored_jwt, changes)
            .await
            .unwrap();

        let mut expected = claims(&fixture.stored_jwt);
        expected.insert("wallet_nonce".to_string(), json!(NONCE));
        expected.insert("aud".to_string(), json!(WALLET));
        assert_eq!(claims(&reissued), expected);
    }

    #[rstest]
    #[case::unknown_claim("x_custom", json!({ "k": [1, 2] }))]
    #[case::transaction_data(
        "transaction_data",
        json!([BASE64_URL_SAFE_NO_PAD.encode(r#"{"type":"payment","credential_ids":["pid"]}"#)])
    )]
    #[tokio::test]
    async fn stored_claims_survive(#[case] name: &str, #[case] value: Value) {
        let fixture = did_fixture().await;
        let stored = resigned(&fixture, &[(name, value.clone())]).await;

        let reissued = fixture
            .verifier
            .reissue_authorization_request(&stored, nonce_only())
            .await
            .unwrap();

        assert_eq!(claims(&reissued)[name], value);
    }

    #[tokio::test]
    async fn a_did_web_verifier_reissues_without_resolving_its_did_document() {
        let kms = LocalKms::new();
        let (_, generated) = create_did_and_key_metadata(&kms).await;
        let key_metadata = KeyMetadata {
            did_url: "did:web:verifier.invalid#key-1".to_string(),
            kid: generated.kid,
        };
        let template = did_fixture().await;
        let stored = sign_with_own_key(
            &kms,
            &key_metadata,
            with_claims(
                &template.stored_jwt,
                &[(
                    "client_id",
                    json!("decentralized_identifier:did:web:verifier.invalid"),
                )],
            ),
        )
        .await;
        let verifier = verifier(
            &kms,
            key_metadata,
            ClientId::from_did("did:web:verifier.invalid").unwrap(),
        )
        .await;

        let reissued = verifier
            .reissue_authorization_request(&stored, nonce_only())
            .await
            .unwrap();

        assert_eq!(
            header(&reissued).key_id.as_deref(),
            Some("did:web:verifier.invalid#key-1")
        );
        assert_eq!(claims(&reissued)["wallet_nonce"], json!(NONCE));
    }

    #[tokio::test]
    async fn request_uri_method_stays_in_the_uri_and_out_of_the_request_object() {
        let fixture = did_fixture().await;
        let query: HashMap<String, String> = fixture.uri.query_pairs().into_owned().collect();

        let reissued = fixture
            .verifier
            .reissue_authorization_request(&fixture.stored_jwt, nonce_only())
            .await
            .unwrap();

        assert_eq!(
            query.get("request_uri_method").map(String::as_str),
            Some("post")
        );
        assert!(!claims(&fixture.stored_jwt).contains_key("request_uri_method"));
        assert!(!claims(&fixture.stored_jwt).contains_key("wallet_nonce"));
        assert!(!claims(&reissued).contains_key("request_uri_method"));
    }

    #[tokio::test]
    async fn nothing_to_change_is_refused() {
        let fixture = did_fixture().await;
        let changes = AuthorizationRequestChanges::default();

        assert!(is_refused(&fixture.verifier, &fixture.stored_jwt, changes).await);
    }

    #[tokio::test]
    async fn empty_values_count_as_absent() {
        let fixture = did_fixture().await;
        let changes = AuthorizationRequestChanges {
            wallet_nonce: Some(String::new()),
            audience: Some(String::new()),
        };

        assert!(is_refused(&fixture.verifier, &fixture.stored_jwt, changes).await);
    }

    #[tokio::test]
    async fn an_unchanged_audience_is_refused() {
        let fixture = did_fixture().await;
        let stored = resigned(&fixture, &[("aud", json!(WALLET))]).await;

        assert!(is_refused(&fixture.verifier, &stored, audience(WALLET)).await);
    }

    #[tokio::test]
    async fn an_unknown_signing_key_is_a_kms_error() {
        let fixture = did_fixture().await;
        let key_metadata = KeyMetadata {
            did_url: fixture.key_metadata.did_url.clone(),
            kid: "unknown-key".to_string(),
        };
        let verifier = verifier(&fixture.kms, key_metadata, fixture.client_id.clone()).await;

        let error = verifier
            .reissue_authorization_request(&fixture.stored_jwt, nonce_only())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::Internal {
                source: InternalError::KMS { .. }
            }
        ));
    }

    #[tokio::test]
    async fn a_foreign_signing_key_is_refused() {
        let fixture = did_fixture().await;
        let (_, other) = create_did_and_key_metadata(&fixture.kms).await;
        let key_metadata = KeyMetadata {
            did_url: fixture.key_metadata.did_url.clone(),
            kid: other.kid,
        };
        let verifier = verifier(&fixture.kms, key_metadata, fixture.client_id.clone()).await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn another_verification_method_is_refused() {
        let fixture = did_fixture().await;
        let key_metadata = KeyMetadata {
            did_url: format!("{}-other", fixture.key_metadata.did_url),
            kid: fixture.key_metadata.kid.clone(),
        };
        let verifier = verifier(&fixture.kms, key_metadata, fixture.client_id.clone()).await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn another_configured_client_id_is_refused() {
        let fixture = did_fixture().await;
        let (other_did, _) = create_did_and_key_metadata(&fixture.kms).await;
        let verifier = verifier(
            &fixture.kms,
            fixture.key_metadata.clone(),
            ClientId::from_did(&other_did).unwrap(),
        )
        .await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn an_x509_variant_that_derives_another_client_id_is_refused() {
        let fixture = x509_fixture(X509Variant::Hash).await;
        let key = fixture.kms.get(&fixture.key_metadata.kid).await.unwrap();
        let pem = self_signed_certificate_pem(&key, DNS_NAME);
        let verifier = x509_verifier(
            &fixture.kms,
            fixture.key_metadata.clone(),
            &pem,
            X509Variant::SanDns,
        )
        .await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn an_x509_chain_other_than_the_stored_one_is_refused() {
        let fixture = x509_fixture(X509Variant::SanDns).await;
        let key = fixture.kms.get(&fixture.key_metadata.kid).await.unwrap();
        let pem = self_signed_certificate_pem(&key, DNS_NAME);
        let verifier = x509_verifier(
            &fixture.kms,
            fixture.key_metadata.clone(),
            &pem,
            X509Variant::SanDns,
        )
        .await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn an_x509_leaf_that_certifies_another_key_is_refused() {
        let fixture = x509_fixture(X509Variant::Hash).await;
        let (_, other) = create_did_and_key_metadata(&fixture.kms).await;
        let other_key = fixture.kms.get(&other.kid).await.unwrap();
        let pem = self_signed_certificate_pem(&other_key, DNS_NAME);
        let verifier = x509_verifier(
            &fixture.kms,
            fixture.key_metadata.clone(),
            &pem,
            X509Variant::Hash,
        )
        .await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn a_did_verifier_refuses_an_x509_signed_object() {
        let fixture = x509_fixture(X509Variant::Hash).await;
        let (did, _) = create_did_and_key_metadata(&fixture.kms).await;
        let verifier = verifier(
            &fixture.kms,
            fixture.key_metadata.clone(),
            ClientId::from_did(&did).unwrap(),
        )
        .await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn an_x509_verifier_refuses_a_did_signed_object() {
        let fixture = did_fixture().await;
        let key = fixture.kms.get(&fixture.key_metadata.kid).await.unwrap();
        let pem = self_signed_certificate_pem(&key, DNS_NAME);
        let verifier = x509_verifier(
            &fixture.kms,
            fixture.key_metadata.clone(),
            &pem,
            X509Variant::Hash,
        )
        .await;

        assert!(is_refused(&verifier, &fixture.stored_jwt, nonce_only()).await);
    }

    #[tokio::test]
    async fn a_signed_payload_that_is_not_a_request_object_is_refused() {
        let fixture = did_fixture().await;
        let header = json!({ "typ": REQUEST_OBJECT_TYP, "kid": fixture.key_metadata.did_url });
        let stored = sign_raw(&fixture, header, &json!({ "foo": "bar" })).await;

        assert!(is_refused(&fixture.verifier, &stored, nonce_only()).await);
    }

    #[tokio::test]
    async fn a_stored_jwt_of_another_typ_is_refused() {
        let fixture = did_fixture().await;
        let header = json!({ "typ": "JWT", "kid": fixture.key_metadata.did_url });
        let payload = Value::Object(claims(&fixture.stored_jwt));
        let stored = sign_raw(&fixture, header, &payload).await;

        assert!(is_refused(&fixture.verifier, &stored, nonce_only()).await);
    }

    #[tokio::test]
    async fn a_tampered_stored_jwt_is_refused() {
        let fixture = did_fixture().await;
        let mut payload = claims(&fixture.stored_jwt);
        payload.insert("nonce".to_string(), json!("tampered"));
        let mut parts: Vec<String> = fixture.stored_jwt.split('.').map(String::from).collect();
        parts[1] = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());

        assert!(is_refused(&fixture.verifier, &parts.join("."), nonce_only()).await);
    }
}
