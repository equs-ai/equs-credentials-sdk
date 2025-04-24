use async_trait::async_trait;
use didcomm::secrets::{
    A256Kw, AesKey, KeyManagementService, KeySecretBytes, KidOrJwk, KnownKeyAlg,
    KnownSignatureType, SecretBytes,
};
use ssi::JWK;
use std::marker::PhantomData;
use std::str::FromStr;

use crate::crypto::{Alg, Key};
use crate::did::universal::UniversalResolver;
use crate::did::JWKResolver;
use crate::kms;
use crate::kms::{DerivativeKms, ECDH1PUParams, ECDHESParams, KeyHandle, KeyPair, KeyType, Kms};
use crate::utils::jwk;

pub trait DIDCommKms<KH: KeyHandle>:
    Kms<KH>
    + DerivativeKms<ECDH1PUParams, Output = Vec<u8>>
    + DerivativeKms<ECDHESParams, Output = Vec<u8>>
{
}

impl<T, KH> DIDCommKms<KH> for T
where
    T: Kms<KH>
        + DerivativeKms<ECDH1PUParams, Output = Vec<u8>>
        + DerivativeKms<ECDHESParams, Output = Vec<u8>>,
    KH: KeyHandle,
{
}

pub struct KmsWrapper<KMS, KH>
where
    KMS: DIDCommKms<KH>,
    KH: KeyHandle,
{
    kms: KMS,
    resolver: UniversalResolver,
    _phantom: PhantomData<KH>,
}

impl<KMS, KH> KmsWrapper<KMS, KH>
where
    KMS: DIDCommKms<KH>,
    KH: KeyHandle,
{
    pub fn new(kms: KMS, resolver: UniversalResolver) -> Self {
        Self {
            kms,
            resolver,
            _phantom: PhantomData,
        }
    }

    async fn resolve_key(&self, x: KidOrJwk) -> didcomm::error::Result<(KeyType, KeyPair)> {
        match x {
            KidOrJwk::Kid(kid) => {
                let jwk = self.resolver.fetch_public_jwk(Some(&kid)).await.unwrap();

                let public_key = jwk.pub_key().map_err(|err| {
                    didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err)
                })?;

                let key_pair = KeyPair {
                    private_key: None,
                    public_key,
                };

                let key_type = jwk::get_key_type(&jwk).ok_or_else(|| {
                    didcomm::error::err_msg(
                        didcomm::error::ErrorKind::Malformed,
                        "Could not resolve JWK key type",
                    )
                })?;

                Ok((key_type, key_pair))
            }
            KidOrJwk::P256Key(jwk) => {
                let jwk = JWK::from_str(&jwk).map_err(|err| {
                    didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err)
                })?;

                let public_key = jwk.pub_key().map_err(|err| {
                    didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err)
                })?;

                let key_pair = if jwk.is_public() {
                    KeyPair {
                        private_key: None,
                        public_key,
                    }
                } else {
                    let private_key = jwk::get_private_key(&jwk).map_err(|err| {
                        didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err)
                    })?;

                    KeyPair {
                        private_key: Some(private_key),
                        public_key,
                    }
                };

                Ok((KeyType::P256, key_pair))
            }
            KidOrJwk::X25519Key(_) => Err(didcomm::error::err_msg(
                didcomm::error::ErrorKind::Unsupported,
                "Unsupported algorithm: X25519",
            )),
        }
    }

    async fn get_by_secret_id(&self, secret_id: &str) -> didcomm::error::Result<KH> {
        let jwk = self
            .resolver
            .fetch_public_jwk(Some(secret_id))
            .await
            .unwrap();

        let public_key = jwk
            .pub_key()
            .map_err(|err| didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err))?;

        self.kms
            .get_by_public_key(&public_key)
            .await
            .map_err(|err| match err {
                kms::Error::NotFound { .. } => didcomm::error::err_msg(
                    didcomm::error::ErrorKind::SecretNotFound,
                    format!("Key not found for ID: {secret_id}"),
                ),
                err => didcomm::error::Error::new(didcomm::error::ErrorKind::IoError, err),
            })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<KMS, KH> KeyManagementService for KmsWrapper<KMS, KH>
where
    KMS: DIDCommKms<KH>,
    KH: KeyHandle,
{
    async fn get_key_alg(&self, secret_id: &str) -> didcomm::error::Result<KnownKeyAlg> {
        self.get_by_secret_id(secret_id)
            .await
            .map(|key_handle| key_handle.alg().into())
    }

    async fn find_secrets<'a>(
        &self,
        secret_ids: &'a [&'a str],
    ) -> didcomm::error::Result<Vec<&'a str>> {
        let mut found_secrets = Vec::with_capacity(secret_ids.len());

        for &kid in secret_ids {
            let key_handle = self.get_by_secret_id(kid).await;

            match key_handle {
                Ok(_) => found_secrets.push(kid),
                Err(err) => {
                    if err.kind() != didcomm::error::ErrorKind::SecretNotFound {
                        return Err(err);
                    }
                }
            }
        }

        Ok(found_secrets)
    }

    async fn create_signature(
        &self,
        secret_id: &str,
        message: &[u8],
        sig_type: Option<KnownSignatureType>,
    ) -> didcomm::error::Result<SecretBytes> {
        let key_handle = self.get_by_secret_id(secret_id).await?;

        key_handle
            .sign(message)
            .await
            .map(Into::into)
            .map_err(|err| didcomm::error::Error::new(didcomm::error::ErrorKind::IoError, err))
    }

    async fn derive_aes_key_using_ecdh_1pu(
        &self,
        ephem_key: KidOrJwk,
        send_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> didcomm::error::Result<AesKey<A256Kw>> {
        let (ephem_key_type, ephem_key) = self.resolve_key(ephem_key).await?;
        let (send_key_type, send_key) = self.resolve_key(send_key).await?;
        let (recip_key_type, recip_key) = self.resolve_key(recip_key).await?;

        if ephem_key_type != send_key_type || ephem_key_type != recip_key_type {
            return Err(didcomm::error::err_msg(
                didcomm::error::ErrorKind::Unsupported,
                "Unsupported derive keys",
            ));
        }

        let params = ECDH1PUParams {
            key_type: ephem_key_type,
            ephem_key,
            send_key,
            recip_key,
            alg,
            apu,
            apv,
            cc_tag,
            receive,
        };

        let key_bytes =
            self.kms.derive(params).await.map_err(|err| {
                didcomm::error::Error::new(didcomm::error::ErrorKind::IoError, err)
            })?;

        AesKey::<A256Kw>::from_secret_bytes(&key_bytes)
            .map_err(|err| didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err))
    }

    async fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> didcomm::error::Result<AesKey<A256Kw>> {
        let (ephem_key_type, ephem_key) = self.resolve_key(ephem_key).await?;
        let (recip_key_type, recip_key) = self.resolve_key(recip_key).await?;

        if ephem_key_type != recip_key_type {
            return Err(didcomm::error::err_msg(
                didcomm::error::ErrorKind::Unsupported,
                "Unsupported derive keys",
            ));
        }

        let params = ECDHESParams {
            key_type: ephem_key_type,
            ephem_key,
            recip_key,
            alg,
            apu,
            apv,
            receive,
        };

        let key_bytes =
            self.kms.derive(params).await.map_err(|err| {
                didcomm::error::Error::new(didcomm::error::ErrorKind::IoError, err)
            })?;

        AesKey::<A256Kw>::from_secret_bytes(&key_bytes)
            .map_err(|err| didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err))
    }
}

impl From<Alg> for KnownKeyAlg {
    fn from(value: Alg) -> Self {
        match value {
            Alg::ES256 => KnownKeyAlg::P256,
            Alg::EdDSA => KnownKeyAlg::Ed25519,
            Alg::ES256K => KnownKeyAlg::K256,
            Alg::BBS => KnownKeyAlg::Unsupported,
        }
    }
}
