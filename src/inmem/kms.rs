use askar_crypto::alg::aes::{A256Kw, AesKey};
use askar_crypto::alg::k256::K256KeyPair;
use askar_crypto::alg::p256::P256KeyPair;
use askar_crypto::kdf::ecdh_1pu::Ecdh1PU;
use askar_crypto::kdf::ecdh_es::EcdhEs;
use askar_crypto::kdf::{FromKeyDerivation, KeyDerivation, KeyExchange};
use askar_crypto::repr::{KeyPublicBytes, KeySecretBytes, ToSecretBytes};
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand::Rng;
use rand::distr::Alphanumeric;
use snafu::{IntoError, ResultExt, ensure};
use ssi::crypto::hashes::sha256::sha256;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{Level, instrument};

use crate::crypto::{AlgNotSupportedSnafu, DerivationNotSupportedSnafu, SigningOptions, Suite};
use crate::inmem::crypto::bip32::Bip32;
use crate::inmem::crypto::bls12381::Bls12381;
use crate::inmem::crypto::ed25519::Ed25519;
use crate::inmem::crypto::k256::K256;
use crate::inmem::crypto::p256::P256;
use crate::inmem::index_storage::IndexStorage;
use crate::inmem::storage::InMemStorage;
use crate::kms::{
    BIP32Params, CreationSnafu, CryptoSnafu, DerivationType, DerivativeKms, ECDH1PUParams,
    ECDHESParams, KeyID, KeyPair, Kms,
};
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl crypto::SigningKey for KeyHandle {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl crypto::VerifyingKey for KeyHandle {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl kms::KeyHandle for KeyHandle {}

pub type Bytes = Vec<u8>;

#[derive(Debug, Clone)]
pub struct LocalKms {
    storage: Arc<InMemStorage<KeyID, Bytes>>,
    indexes: IndexStorage,
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
            indexes: IndexStorage::new(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn for_store(storage: InMemStorage<KeyID, Bytes>) -> Self {
        Self {
            storage: Arc::new(storage),
            indexes: IndexStorage::new(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn kid(key_type: kms::KeyType, derivation_type: Option<DerivationType>) -> KeyID {
        let id = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(KID_LENGTH)
            .map(char::from)
            .collect::<String>();

        format!(
            "{}:{}:{}",
            id,
            key_type,
            derivation_type.map(|v| v.to_string()).unwrap_or_default()
        )
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn key_type_and_derivation(kid: &str) -> kms::Result<(kms::KeyType, Option<DerivationType>)> {
        let vec = kid.split(':').collect::<Vec<&str>>();

        ensure!(vec.len() == 3, NotFoundSnafu { id: kid });

        let key_type =
            kms::KeyType::from_str(vec[1]).map_err(|_| NotFoundSnafu { id: kid }.build())?;
        let derivation_type = kms::DerivationType::from_str(vec[2]).ok();

        Ok((key_type, derivation_type))
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

    fn generate_key_pair<S: Suite>() -> Result<(Vec<u8>, Vec<u8>), Error> {
        let private_key = S::generate();
        let public_key = S::from_secret(private_key.to_owned())
            .and_then(|key| key.pub_key())
            .context(CryptoSnafu)?;

        Ok((public_key, private_key))
    }

    pub async fn map_kid_to_public_key(
        &self,
        kid: &KeyID,
        public_key: &[u8],
        kt: kms::KeyType,
    ) -> Result<(), Error> {
        let public_key_id = Self::public_key_to_id(public_key);
        self.indexes.put_index(public_key_id, kid).await;

        let re_encoded_key = match kt {
            kms::KeyType::K256 => Some(K256::re_encode_public_key(
                public_key,
                !K256::is_compressed_public_key(public_key)?,
            )?),
            kms::KeyType::P256 => Some(P256::re_encode_public_key(
                public_key,
                !P256::is_compressed_public_key(public_key)?,
            )?),
            _ => None,
        };

        if let Some(re_encoded_key) = re_encoded_key {
            let re_encoded_pk_id = Self::public_key_to_id(&re_encoded_key);
            self.indexes.put_index(re_encoded_pk_id, kid).await;
        }

        Ok(())
    }

    async fn get_kid_by_public_key(&self, public_key: &[u8]) -> Result<KeyID, Error> {
        let public_key_id = Self::public_key_to_id(public_key);
        let kid = self
            .indexes
            .get_ids_for_indexes(vec![public_key_id.clone()])
            .await
            .iter()
            .next()
            .ok_or_else(|| NotFoundSnafu { id: public_key_id }.build())?
            .to_string();

        Ok(kid)
    }

    fn public_key_to_id(public_key: &[u8]) -> String {
        let hash = sha256(public_key);

        BASE64_STANDARD.encode(&hash[..16])
    }

    async fn derive_bip32_master(&self, seed: Vec<u8>) -> kms::Result<KeyID> {
        let kid = LocalKms::kid(kms::KeyType::K256, Some(DerivationType::BIP32));

        let _ = self.storage.put(kid.to_owned(), seed).await;

        Ok(kid.to_owned())
    }

    async fn derive_bip32_child(&self, path: String, master_kid: KeyID) -> kms::Result<KeyID> {
        let payload = self.resolve_payload(&master_kid).await?;
        let (kt, dt) = LocalKms::key_type_and_derivation(&master_kid)?;

        if dt != Some(DerivationType::BIP32) {
            return Err(
                CryptoSnafu.into_error(DerivationNotSupportedSnafu { kid: master_kid }.build())
            );
        }

        let key = Bip32::from_seed(payload.as_slice())
            .derive(&path)
            .await
            .context(CryptoSnafu)?;

        let kid = LocalKms::kid(kt, None);

        let _ = self.storage.put(kid.to_owned(), key).await;

        Ok(kid.to_owned())
    }

    async fn derive_ecdh1pu<KP>(&self, mut params: ECDH1PUParams) -> kms::Result<Vec<u8>>
    where
        KP: KeyPublicBytes + KeySecretBytes + KeyExchange,
    {
        if params.receive {
            params.recip_key = self.resolve_private_key(params.recip_key).await?;
        } else {
            params.send_key = self.resolve_private_key(params.send_key).await?;
        }

        let ephem_key = Self::create_askar_key_pair::<KP>(params.ephem_key)?;
        let send_key = Self::create_askar_key_pair::<KP>(params.send_key)?;
        let recip_key = Self::create_askar_key_pair::<KP>(params.recip_key)?;

        let derivation = Ecdh1PU::new(
            &ephem_key,
            &send_key,
            &recip_key,
            &params.alg,
            &params.apu,
            &params.apv,
            &params.cc_tag,
            params.receive,
        );

        Self::derive_aes_256_key(derivation).await
    }

    async fn derive_ecdhes<KP>(&self, params: ECDHESParams) -> kms::Result<Vec<u8>>
    where
        KP: KeyPublicBytes + KeySecretBytes + KeyExchange,
    {
        let ephem_key = Self::create_askar_key_pair::<KP>(params.ephem_key)?;
        let recip_key = Self::create_askar_key_pair::<KP>(params.recip_key)?;

        let derivation = EcdhEs::new(
            &ephem_key,
            &recip_key,
            &params.alg,
            &params.apu,
            &params.apv,
            params.receive,
        );

        Self::derive_aes_256_key(derivation).await
    }

    async fn derive_aes_256_key<D: KeyDerivation>(derivation: D) -> kms::Result<Vec<u8>> {
        AesKey::<A256Kw>::from_key_derivation(derivation)
            .and_then(|key| key.to_secret_bytes())
            .map(|secret_bytes| secret_bytes.to_vec())
            .map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    fn create_askar_key_pair<KP>(key_pair: KeyPair) -> kms::Result<KP>
    where
        KP: KeyPublicBytes + KeySecretBytes + KeyExchange,
    {
        match key_pair {
            KeyPair {
                ref public_key,
                private_key: Some(ref private_key),
            } => KP::from_secret_bytes(private_key).map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            }),
            KeyPair {
                ref public_key,
                private_key: None,
            } => KP::from_public_bytes(public_key).map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            }),
        }
    }

    async fn resolve_private_key(&self, key_pair: KeyPair) -> kms::Result<KeyPair> {
        let kid = self.get_kid_by_public_key(&key_pair.public_key).await?;

        let private_key = self.resolve_payload(&kid).await?;

        Ok(KeyPair {
            private_key: Some(private_key),
            public_key: key_pair.public_key.clone(),
        })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Kms<KeyHandle> for LocalKms {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn create(&self, kt: kms::KeyType, opts: kms::CreateOptions) -> Result<KeyID, Error> {
        let (public_key, private_key) = match kt {
            kms::KeyType::Ed25519 => Self::generate_key_pair::<Ed25519>()?,
            kms::KeyType::P256 => Self::generate_key_pair::<P256>()?,
            kms::KeyType::K256 => Self::generate_key_pair::<K256>()?,
            kms::KeyType::Bls12381 => Self::generate_key_pair::<Bls12381>()?,
        };

        let kid = LocalKms::kid(kt.clone(), None);

        self.storage
            .put(kid.to_owned(), private_key)
            .await
            .map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        self.map_kid_to_public_key(&kid, &public_key, kt).await?;

        Ok(kid)
    }

    #[instrument(level = Level::TRACE, skip(self), err())]
    async fn get(&self, kid: &KeyID) -> Result<KeyHandle, Error> {
        let payload = self.resolve_payload(kid).await?;
        let (kt, dt) = LocalKms::key_type_and_derivation(kid)?;

        let res = match (kt, dt) {
            (_, Some(DerivationType::BIP32)) => Bip32::from_seed(payload.as_slice())
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

    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn get_by_public_key(&self, public_key: &[u8]) -> Result<KeyHandle, Error> {
        let kid = self.get_kid_by_public_key(public_key).await?;

        self.get(&kid).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DerivativeKms<BIP32Params> for LocalKms {
    type Output = KeyID;

    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn derive(&self, params: BIP32Params) -> kms::Result<KeyID> {
        match params {
            BIP32Params::MasterDerive { seed } => self.derive_bip32_master(seed).await,
            BIP32Params::ChildDerive { path, master_kid } => {
                self.derive_bip32_child(path, master_kid).await
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DerivativeKms<ECDH1PUParams> for LocalKms {
    type Output = Vec<u8>;

    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn derive(&self, mut params: ECDH1PUParams) -> kms::Result<Vec<u8>> {
        if params.receive {
            let kid = self
                .get_kid_by_public_key(&params.recip_key.public_key)
                .await?;

            let private_key = self.resolve_payload(&kid).await?;

            params.recip_key = KeyPair {
                private_key: Some(private_key),
                public_key: params.recip_key.public_key.clone(),
            }
        } else {
            let kid = self
                .get_kid_by_public_key(&params.send_key.public_key)
                .await?;

            let private_key = self.resolve_payload(&kid).await?;

            params.send_key = KeyPair {
                private_key: Some(private_key),
                public_key: params.send_key.public_key.clone(),
            }
        }

        match &params.key_type {
            kms::KeyType::P256 => self.derive_ecdh1pu::<P256KeyPair>(params).await,
            kms::KeyType::K256 => self.derive_ecdh1pu::<K256KeyPair>(params).await,
            _ => Err(CryptoSnafu.into_error(
                AlgNotSupportedSnafu {
                    alg: params.key_type.to_string(),
                }
                .build(),
            )),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DerivativeKms<ECDHESParams> for LocalKms {
    type Output = Vec<u8>;

    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn derive(&self, mut params: ECDHESParams) -> kms::Result<Vec<u8>> {
        let kid = self
            .get_kid_by_public_key(&params.recip_key.public_key)
            .await?;

        let private_key = self.resolve_payload(&kid).await?;

        params.recip_key = KeyPair {
            private_key: Some(private_key),
            public_key: params.recip_key.public_key.clone(),
        };

        match &params.key_type {
            kms::KeyType::P256 => self.derive_ecdhes::<P256KeyPair>(params).await,
            kms::KeyType::K256 => self.derive_ecdhes::<K256KeyPair>(params).await,
            _ => Err(CryptoSnafu.into_error(
                AlgNotSupportedSnafu {
                    alg: params.key_type.to_string(),
                }
                .build(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto;
    use crate::crypto::{Signer, Verifier};
    use crate::inmem::kms::LocalKms;
    use crate::kms::test_util::test_kms;
    use crate::kms::{BIP32Params, CreateOptions, DerivativeKms, Error, KeyType, Kms};
    use bip32::Mnemonic;
    use bip32::secp256k1::elliptic_curve::rand_core::OsRng;

    #[tokio::test]
    async fn e2e() {
        test_kms(LocalKms::new()).await;
    }

    const PAYLOAD: &str = "message";

    #[tokio::test]
    async fn derivation_bip32_succeeds() {
        let kms = LocalKms::new();

        let mnemonic = Mnemonic::random(OsRng, Default::default());
        let seed = mnemonic.to_seed("password");

        let master_kid = kms
            .derive(BIP32Params::MasterDerive {
                seed: seed.as_bytes().to_vec(),
            })
            .await
            .unwrap();

        let master_kh = kms.get(&master_kid).await.unwrap();

        let signature = master_kh.sign(PAYLOAD.as_bytes()).await.unwrap();
        assert!(
            master_kh
                .verify(PAYLOAD.as_bytes(), signature.as_slice())
                .await
                .is_ok()
        );

        let paths: [&str; 2] = ["m/0/2147483647'/1/2147483646'", "m/838373'/0'/0'/0'/0'"];

        for path in paths {
            let derived_kid = kms
                .derive(BIP32Params::ChildDerive {
                    path: path.to_string(),
                    master_kid: master_kid.to_owned(),
                })
                .await
                .unwrap();

            let derived_kh = kms.get(&derived_kid).await.unwrap();

            let signature = derived_kh.sign(PAYLOAD.as_bytes()).await.unwrap();
            assert!(
                derived_kh
                    .verify(PAYLOAD.as_bytes(), signature.as_slice())
                    .await
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn derivation_not_supported() {
        let kms = LocalKms::new();

        let master_kid = kms
            .create(KeyType::P256, CreateOptions::default())
            .await
            .unwrap();

        let res = kms
            .derive(BIP32Params::ChildDerive {
                path: "m/0/2147483647'/1/2147483646'".to_string(),
                master_kid,
            })
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
