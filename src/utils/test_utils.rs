use crate::crypto::{Alg, Key, Signer, SigningKey, Verifier, VerifyingKey};
use crate::did::didkey::DIDKey;
use crate::did::{DIDResolver, DID, DIDURL};
use crate::inmem::kms::LocalKms;
use crate::kms::{KeyHandle, KeyID, KeyType, Kms};
use crate::vc::core::KeyMetadata;
use crate::{crypto, kms};
use async_trait::async_trait;
use ssi::jwk::JWK;
use std::str::FromStr;

pub async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    create_did_and_key_metadata_by_key_type(kms, KeyType::P256).await
}

pub async fn create_did_and_key_metadata_by_key_type(
    kms: &LocalKms,
    kt: KeyType,
) -> (DID, KeyMetadata) {
    let didkey = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(kt, kms::CreateOptions {})
        .await
        .unwrap();

    let did = didkey.generate(kh).unwrap();

    let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

    (did, KeyMetadata { kid, did_url: vm })
}

pub async fn create_did_url_and_key_handle(
    kms: &LocalKms,
    key_type: KeyType,
) -> (DIDURL, impl KeyHandle) {
    let didkey = DIDKey::new();

    let (_, kh) = kms
        .create_and_handle(key_type, kms::CreateOptions {})
        .await
        .unwrap();

    let did = didkey.generate(kh.clone()).unwrap();
    let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

    let did_url = DIDURL::from_str(&vm).unwrap();
    (did_url, kh)
}

pub async fn create_did_url_and_key_handle_kid(
    kms: &LocalKms,
    key_type: KeyType,
) -> (DIDURL, KeyID, impl KeyHandle) {
    let didkey = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(key_type, kms::CreateOptions {})
        .await
        .unwrap();

    let did = didkey.generate(kh.clone()).unwrap();
    let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

    let did_url = DIDURL::from_str(&vm).unwrap();
    (did_url, kid, kh)
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

pub fn failed_signer_key(key: impl Key + 'static) -> impl KeyHandle {
    struct MockKey {
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

    MockKey { key: Box::new(key) }
}
