use crate::crypto::Alg;
use crate::kms::KeyHandle;
use crate::vc::oid4vp::Error::Internal;
use crate::vc::oid4vp::internal_error::AuthorizationResponseDecryptionSnafu;
use one_crypto::encryption::EncryptionError;
use one_crypto::jwe::PrivateKeyAgreementHandle;
use one_crypto::jwe::RemoteJwk;
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::signer::eddsa::EDDSASigner;
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
) -> crate::vc::oid4vp::verifier::Result<Box<dyn PrivateKeyAgreementHandle>> {
    match alg {
        Alg::EdDSA => {
            let key =
                ed25519_compact::SecretKey::from_slice(&private_key).map_err(|e| Internal {
                    source: AuthorizationResponseDecryptionSnafu {
                        details: format!("Error while getting secret key for {} key type", alg),
                    }
                    .build(),
                })?;
            Ok(Box::new(WrapperForEdDSAHandle { key }))
        }
        Alg::ES256 => {
            let key = SecretKey::from_slice(private_key.as_slice()).map_err(|e| Internal {
                source: AuthorizationResponseDecryptionSnafu {
                    details: format!("Error while getting secret key for {} key type", alg),
                }
                .build(),
            })?;
            Ok(Box::new(WrapperForES256Handle { key }))
        }
        _ => Err(Internal {
            source: AuthorizationResponseDecryptionSnafu {
                details: format!("Private key handle for {} key type is not supported", alg),
            }
            .build(),
        }),
    }
}

pub fn add_public_private_keys(
    kh: impl KeyHandle,
    alg: Alg,
) -> crate::vc::oid4vp::verifier::Result<Vec<u8>> {
    match alg {
        Alg::EdDSA => {
            let mut private_key = kh.private_key().map_err(|e| Internal {
                source: AuthorizationResponseDecryptionSnafu {
                    details: format!("Error while getting the private key : {}", e),
                }
                .build(),
            })?;
            let public_key = kh.pub_key().map_err(|e| Internal {
                source: AuthorizationResponseDecryptionSnafu {
                    details: format!("Error while getting the private key : {}", e),
                }
                .build(),
            })?;
            for val in public_key {
                private_key.push(val);
            }
            Ok(private_key)
        }
        Alg::ES256 => kh.private_key().map_err(|e| Internal {
            source: AuthorizationResponseDecryptionSnafu {
                details: format!("Error while getting the private key : {}", e),
            }
            .build(),
        }),
        _ => Err(Internal {
            source: AuthorizationResponseDecryptionSnafu {
                details: format!("Unsupported alg: {}", alg),
            }
            .build(),
        }),
    }
}
