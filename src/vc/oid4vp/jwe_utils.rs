use crate::crypto;
use crate::crypto::{Alg, IncorrectKeySnafu};
use crate::kms::KeyHandle;
use one_core_asdk::encryption::EncryptionError;
use one_core_asdk::jwe::PrivateKeyAgreementHandle;
use one_core_asdk::jwe::RemoteJwk;
use one_core_asdk::signer::ecdsa::ECDSASigner;
use one_core_asdk::signer::eddsa::EDDSASigner;
use p256::SecretKey;
use secrecy::SecretSlice;

#[derive(Debug)]
pub struct WrapperForEdDSAHandle {
    pub key: ed25519_compact::SecretKey,
}
#[async_trait::async_trait]
impl PrivateKeyAgreementHandle for WrapperForEdDSAHandle {
    async fn shared_secret(
        &self,
        remote_jwk: &RemoteJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        EDDSASigner::shared_secret_x25519(&self.key.to_vec().into(), remote_jwk)
    }
}

#[derive(Debug)]
pub struct WrapperForES256Handle {
    pub key: SecretKey,
}

#[async_trait::async_trait]
impl PrivateKeyAgreementHandle for WrapperForES256Handle {
    async fn shared_secret(
        &self,
        remote_jwk: &RemoteJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        ECDSASigner::shared_secret_p256(&self.key.to_bytes().to_vec().into(), remote_jwk)
    }
}

pub fn get_private_key_handler(
    private_key: Vec<u8>,
    alg: Alg,
) -> Result<Box<dyn PrivateKeyAgreementHandle>, crypto::Error> {
    match alg {
        Alg::EdDSA => {
            let key = ed25519_compact::SecretKey::from_slice(&private_key).map_err(|e| {
                IncorrectKeySnafu {
                    details: format!("Error while getting secret key for {} key type", alg),
                }
                .build()
            })?;
            Ok(Box::new(WrapperForEdDSAHandle { key }))
        }
        Alg::ES256 => {
            let key = SecretKey::from_slice(private_key.as_slice()).map_err(|e| {
                IncorrectKeySnafu {
                    details: format!("Error while getting secret key for {} key type", alg),
                }
                .build()
            })?;
            Ok(Box::new(WrapperForES256Handle { key }))
        }
        unsupported => Err(crypto::Error::AlgNotSupported {
            alg: unsupported.to_string(),
        }),
    }
}

pub fn add_public_private_keys(kh: impl KeyHandle, alg: Alg) -> Result<Vec<u8>, crypto::Error> {
    match alg {
        Alg::EdDSA => {
            let mut private_key = kh.private_key()?;
            let public_key = kh.pub_key()?;
            for val in public_key {
                private_key.push(val);
            }
            Ok(private_key)
        }
        Alg::ES256 => kh.private_key(),
        unsupported => Err(crypto::Error::AlgNotSupported {
            alg: unsupported.to_string(),
        }),
    }
}
