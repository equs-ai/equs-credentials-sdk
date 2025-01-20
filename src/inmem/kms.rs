use async_trait::async_trait;
use snafu::ResultExt;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{instrument, Level};

use crate::crypto::{
    AlgNotSupportedSnafu, DerivationNotSupportedSnafu, DerivationSuite, SigningOptions, Suite,
};
use crate::inmem::crypto::bip32::Bip32;
use crate::inmem::crypto::bls12381::Bls12381;
use crate::inmem::crypto::ed25519::Ed25519;
use crate::inmem::crypto::k256::K256;
use crate::inmem::crypto::p256::P256;
use crate::inmem::storage::InMemStorage;
use crate::kms::{CryptoSnafu, DerivativeKms, KeyID, Kms};
use crate::kms::{Error, NotFoundSnafu, ResolvingSnafu};
use crate::storage::Storage;
use crate::{crypto, kms};

#[derive(Clone)]
pub enum KeyHandle {
    Ed25519(Ed25519),
    P256(P256),
    K256(K256),
    Bls12381(Bls12381),
}

impl KeyHandle {}

#[async_trait]
impl crypto::Signer for KeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn alg(&self) -> crypto::Alg {
        match self {
            KeyHandle::Ed25519(s) => s.alg(),
            KeyHandle::P256(s) => s.alg(),
            KeyHandle::K256(s) => s.alg(),
            KeyHandle::Bls12381(s) => s.alg(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.sign(payload).await,
            KeyHandle::P256(s) => s.sign(payload).await,
            KeyHandle::K256(s) => s.sign(payload).await,
            KeyHandle::Bls12381(s) => s.sign(payload).await,
        }
    }

    async fn sign_multi(
        &self,
        payloads: &[Vec<u8>],
        opts: Option<SigningOptions>,
    ) -> crypto::Result<Vec<u8>> {
        match self {
            KeyHandle::Bls12381(s) => s.sign_multi(payloads, opts).await,
            _ => AlgNotSupportedSnafu {
                alg: self.alg().to_string(),
            }
            .fail(),
        }
    }
}

#[async_trait]
impl crypto::Verifier for KeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.verify(data, signature).await,
            KeyHandle::P256(s) => s.verify(data, signature).await,
            KeyHandle::K256(s) => s.verify(data, signature).await,
            KeyHandle::Bls12381(s) => s.verify(data, signature).await,
        }
    }
}

#[async_trait]
impl crypto::Key for KeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    fn pub_key(&self) -> Result<Vec<u8>, crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.pub_key(),
            KeyHandle::P256(s) => s.pub_key(),
            KeyHandle::K256(s) => s.pub_key(),
            KeyHandle::Bls12381(s) => s.pub_key(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn jwk(&self) -> Option<ssi::jwk::JWK> {
        match self {
            KeyHandle::Ed25519(s) => s.jwk(),
            KeyHandle::P256(s) => s.jwk(),
            KeyHandle::K256(s) => s.jwk(),
            KeyHandle::Bls12381(s) => s.jwk(),
        }
    }
}

#[async_trait]
impl crypto::SigningKey for KeyHandle {}

#[async_trait]
impl crypto::VerifyingKey for KeyHandle {}

#[async_trait]
impl kms::KeyHandle for KeyHandle {}

pub type Bytes = Vec<u8>;

#[derive(Debug, Clone)]
pub struct LocalKms {
    storage: Arc<InMemStorage<KeyID, Bytes>>,
}

const KID_LENGTH: usize = 10;

impl LocalKms {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(InMemStorage::new()),
        }
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn for_store(storage: InMemStorage<KeyID, Bytes>) -> Self {
        Self {
            storage: Arc::new(storage),
        }
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn kid(kt: kms::KeyType, derivation: Option<kms::Derivation>) -> KeyID {
        let id = random_string::generate(KID_LENGTH, random_string::charsets::ALPHA);
        let der = derivation.map(|d| d.to_string()).unwrap_or("".to_string());

        format!("{}:{}:{}", id, kt, der)
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn key_type_and_derivation(kid: &str) -> (kms::KeyType, Option<kms::Derivation>) {
        let [_, kt, der] = kid.split(':').collect::<Vec<&str>>()[..]
            .try_into()
            .unwrap();

        (
            kms::KeyType::from_str(kt).unwrap(),
            kms::Derivation::from_str(der).ok(),
        )
    }

    async fn resolve_payload(&self, kid: &KeyID) -> Result<Bytes, Error> {
        self.storage
            .get(kid)
            .await
            .map_err(|e| {
                ResolvingSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .ok_or(NotFoundSnafu { id: kid }.build())
    }
}

#[async_trait]
impl Kms<KeyHandle> for LocalKms {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn create(&self, kt: kms::KeyType, opts: kms::CreateOptions) -> Result<KeyID, Error> {
        let key = match kt {
            kms::KeyType::Ed25519 => Ed25519::gen(),
            kms::KeyType::P256 => P256::gen(),
            kms::KeyType::K256 => K256::gen(),
            kms::KeyType::Bls12381 => Bls12381::gen(),
        };

        let kid = LocalKms::kid(kt, None);

        let _ = self.storage.put(kid.to_owned(), key).await;

        Ok(kid.to_owned())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
    )]
    async fn get(&self, kid: &KeyID) -> Result<KeyHandle, Error> {
        let payload = self.resolve_payload(kid).await?;
        let (kt, der) = LocalKms::key_type_and_derivation(kid);

        let res = match (kt, der) {
            (_, Some(kms::Derivation::BIP32)) => Bip32::from_seed(payload.as_slice())
                .suite()
                .map(KeyHandle::K256)
                .context(CryptoSnafu)?,
            (kms::KeyType::Ed25519, _) => Ed25519::from_secret(payload.clone())
                .map(KeyHandle::Ed25519)
                .context(CryptoSnafu)?,
            (kms::KeyType::P256, _) => P256::from_secret(payload.clone())
                .map(KeyHandle::P256)
                .context(CryptoSnafu)?,
            (kms::KeyType::K256, _) => K256::from_secret(payload.clone())
                .map(KeyHandle::K256)
                .context(CryptoSnafu)?,
            (kms::KeyType::Bls12381, _) => Bls12381::from_secret(payload.clone())
                .map(KeyHandle::Bls12381)
                .context(CryptoSnafu)?,
        };

        Ok(res)
    }
}

#[async_trait]
impl DerivativeKms<KeyHandle> for LocalKms {
    async fn create_from_seed(&self, seed: &[u8], der: kms::Derivation) -> kms::Result<KeyID> {
        let kt = match der {
            kms::Derivation::BIP32 => kms::KeyType::K256,
        };

        let kid = LocalKms::kid(kt, Some(der));

        let _ = self.storage.put(kid.to_owned(), seed.to_vec()).await;

        Ok(kid.to_owned())
    }

    async fn derive(&self, path: &str, master_kid: &KeyID) -> kms::Result<KeyID> {
        let payload = self.resolve_payload(master_kid).await?;
        let (kt, der) = LocalKms::key_type_and_derivation(master_kid);

        let key = match der {
            Some(kms::Derivation::BIP32) => Bip32::from_seed(payload.as_slice())
                .derive(path)
                .await
                .context(CryptoSnafu)?,
            _ => DerivationNotSupportedSnafu { kid: master_kid }
                .fail()
                .context(CryptoSnafu)?,
        };

        let kid = LocalKms::kid(kt, None);

        let _ = self.storage.put(kid.to_owned(), key).await;

        Ok(kid.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto;
    use crate::crypto::{Signer, Verifier};
    use crate::inmem::kms::LocalKms;
    use crate::kms::test_util::test_kms;
    use crate::kms::{CreateOptions, Derivation, DerivativeKms, Error, KeyType, Kms};
    use bip32::secp256k1::elliptic_curve::rand_core::OsRng;
    use bip32::Mnemonic;

    #[tokio::test]
    async fn e2e() {
        test_kms(LocalKms::new()).await;
    }

    const PAYLOAD: &str = "message";

    #[tokio::test]
    async fn derivation_succeeds() {
        let kms = LocalKms::new();

        let mnemonic = Mnemonic::random(OsRng, Default::default());
        let seed = mnemonic.to_seed("password");

        let master_kid = kms
            .create_from_seed(seed.as_bytes(), Derivation::BIP32)
            .await
            .unwrap();

        let master_kh = kms.get(&master_kid).await.unwrap();

        let signature = master_kh.sign(PAYLOAD.as_bytes()).await.unwrap();
        assert!(master_kh
            .verify(PAYLOAD.as_bytes(), signature.as_slice())
            .await
            .is_ok());

        let paths: [&str; 2] = ["m/0/2147483647'/1/2147483646'", "m/838373'/0'/0'/0'/0'"];

        for path in paths {
            let derived_kid = kms.derive(path, &master_kid).await.unwrap();

            let derived_kh = kms.get(&derived_kid).await.unwrap();

            let signature = derived_kh.sign(PAYLOAD.as_bytes()).await.unwrap();
            assert!(derived_kh
                .verify(PAYLOAD.as_bytes(), signature.as_slice())
                .await
                .is_ok());
        }
    }

    #[tokio::test]
    async fn derivation_not_supported() {
        let kms = LocalKms::new();

        let master_kid = kms.create(KeyType::P256, CreateOptions {}).await.unwrap();

        let res = kms
            .derive("m/0/2147483647'/1/2147483646'", &master_kid)
            .await;

        assert!(matches!(
            res.err(),
            Some(Error::Crypto {
                source: crypto::Error::DerivationNotSupported { .. },
                ..
            })
        ));
    }
}
