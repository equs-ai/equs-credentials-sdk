use crate::crypto::{Alg, Key, Signer, SigningKey, Verifier, VerifyingKey};
use crate::did::didkey::DIDKey;
use crate::did::universal::UniversalResolver;
use crate::did::{DID, DIDResolver};
use crate::inmem::kms::LocalKms;
use crate::jwe::{JweDecrypt, JweDecryptError};
use crate::kms::{KeyHandle, KeyID, KeyType, Kms};
use crate::vc::core::KeyMetadata;
use crate::{crypto, kms};
use async_trait::async_trait;
use kms::CreateOptions;
use mockall::mock;
use serde_json::Value;
use ssi::dids::DIDURLBuf;
use ssi::jwk::JWK;
use std::collections::HashMap;

pub async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    create_did_and_key_metadata_by_key_type(kms, KeyType::P256).await
}

pub async fn create_did_and_key_metadata_by_key_type(
    kms: &LocalKms,
    kt: KeyType,
) -> (DID, KeyMetadata) {
    let (kid, kh) = kms
        .create_and_handle(kt, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh).unwrap();

    let did_url = UniversalResolver::default()
        .resolve_into_any_verification_method(ssi::dids::DID::new(did.as_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap()
        .id;

    (
        did,
        KeyMetadata {
            kid,
            did_url: did_url.to_string(),
        },
    )
}

pub async fn create_did_url_and_key_handle(
    kms: &LocalKms,
    key_type: KeyType,
) -> (DIDURLBuf, impl KeyHandle + use<>) {
    let (_, kh) = kms
        .create_and_handle(key_type, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh.clone()).unwrap();
    let did_url = UniversalResolver::default()
        .resolve_into_any_verification_method(ssi::dids::DID::new(did.as_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap()
        .id;

    (did_url, kh)
}

pub async fn create_did_url_and_key_handle_kid(
    kms: &LocalKms,
    key_type: KeyType,
) -> (DIDURLBuf, KeyID, impl KeyHandle) {
    let (kid, kh) = kms
        .create_and_handle(key_type, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh.clone()).unwrap();
    let vm = UniversalResolver::default()
        .resolve_into_any_verification_method(ssi::dids::DID::new(did.as_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap();

    (vm.id, kid, kh)
}

pub fn no_jwk_key() -> impl KeyHandle {
    #[derive(Clone)]
    struct MockKey {}

    impl Key for MockKey {
        fn pub_key(&self) -> crypto::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn jwk(&self) -> Option<JWK> {
            None
        }
    }

    #[async_trait]
    impl Signer for MockKey {
        fn alg(&self) -> Alg {
            Alg::ES256
        }

        async fn sign(&self, payload: &[u8]) -> crypto::Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl Verifier for MockKey {
        async fn verify(&self, data: &[u8], signature: &[u8]) -> crypto::Result<()> {
            unimplemented!()
        }
    }

    impl SigningKey for MockKey {}
    impl VerifyingKey for MockKey {}
    impl KeyHandle for MockKey {}

    MockKey {}
}

pub struct MockKey {
    key: Box<dyn Key>,
}

impl Key for MockKey {
    fn pub_key(&self) -> crypto::Result<Vec<u8>> {
        self.key.pub_key()
    }

    fn jwk(&self) -> Option<JWK> {
        self.key.jwk()
    }
}

#[async_trait]
impl Signer for MockKey {
    fn alg(&self) -> Alg {
        Alg::ES256
    }

    async fn sign(&self, payload: &[u8]) -> crypto::Result<Vec<u8>> {
        Err(crypto::Error::KeyNotSupported {
            type_: "mock".to_string(),
        })
    }
}

#[async_trait]
impl Verifier for MockKey {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> crypto::Result<()> {
        unimplemented!()
    }
}

impl Clone for MockKey {
    fn clone(&self) -> Self {
        unimplemented!()
    }

    fn clone_from(&mut self, source: &Self) {
        unimplemented!()
    }
}

impl SigningKey for MockKey {}
impl VerifyingKey for MockKey {}
impl KeyHandle for MockKey {}

pub fn failed_signer_key(key: impl Key + 'static) -> MockKey {
    MockKey { key: Box::new(key) }
}

mock! {
    pub JweKms{}

    #[async_trait]
    impl JweDecrypt<MockKey> for JweKms {
        async fn decrypt(&self, jwe: &str, kid: &str) -> Result<Value, JweDecryptError>;
    }

    #[async_trait]
    impl Kms<MockKey> for JweKms {
        async fn create(&self, kt: KeyType, opts: CreateOptions) -> Result<KeyID, kms::Error>;

        async fn get(&self, kid: &KeyID) -> Result<MockKey, kms::Error>;

        async fn get_by_public_key(&self, public_key: &[u8]) -> Result<MockKey, kms::Error>;
    }
}

/// `statuslist+jwt` served at `sub`: an SD-JWT without disclosures, signed by the fixture issuer
/// key under its `did:key` URL.
pub fn status_list_jwt(sub: &str, iat: u64, lst: &str, bits: u8) -> String {
    let issuer = &test_fixtures::keys().issuer;
    test_fixtures::sd_jwt(
        &serde_json::json!({
            "typ": "statuslist+jwt",
            "alg": "ES256",
            "kid": test_fixtures::did_key_url(issuer)
        }),
        &serde_json::json!({
            "status_list": { "lst": lst, "bits": bits },
            "sub": sub,
            "iat": iat,
            "_sd_alg": "sha-256"
        }),
        &[],
        issuer,
    )
}

/// Trusted anchors keyed by Subject Key Identifier, as the verifier holds them.
pub fn anchors(ca_certs: &[&str]) -> HashMap<String, String> {
    ca_certs
        .iter()
        .map(|ca_cert| (skid_of(ca_cert), ca_cert.to_string()))
        .collect()
}

/// Subject Key Identifier of the first certificate in `cert_pem`.
pub fn skid_of(cert_pem: &str) -> String {
    let pem = x509_parser::prelude::Pem::iter_from_buffer(cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    one_core::mapper::x509::subject_key_identifier(&pem.parse_x509().unwrap())
        .unwrap()
        .unwrap()
}
