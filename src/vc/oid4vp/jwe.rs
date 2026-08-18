use crate::vc::oid4vp::Error::Internal;
use crate::vc::oid4vp::internal_error::JWESnafu;
use crate::vc::oid4vp::{ClientMetadata, Error};
use one_core_asdk::config::core_config::KeyAlgorithmType::{
    Ecdsa as EcdsaKeyAlgorithm, Eddsa as EddsaKeyAlgorithm,
};
use one_core_asdk::one_crypto::jwe::{Header, build_jwe};
use one_core_asdk::provider::key_algorithm::KeyAlgorithm;
use one_core_asdk::provider::key_algorithm::ecdsa::Ecdsa;
use one_core_asdk::provider::key_algorithm::eddsa::Eddsa;
use one_core_asdk::provider::key_algorithm::model::GeneratedKey;
use one_core_asdk::provider::key_algorithm::provider::KeyAlgorithmProvider;
use one_core_asdk::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core_asdk::provider::key_algorithm::provider::ParsedKey;
use one_core_asdk::standardized_types::jwa::EncryptionAlgorithm;
use one_core_asdk::standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};
use openid4vp::core::metadata::parameters::verifier::EncryptedResponseEncValuesSupported;
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone)]
pub struct JwkConfig {
    pub jwk: Map<String, Value>,
    pub encryption_alg: EncryptionAlgorithm,
    pub kty: String,
    pub kid: String,
    pub alg: Algorithm,
}

pub struct JweEncryptor {
    metadata: ClientMetadata,
    supported_algs: Vec<Algorithm>,
    key_algorithm_provider: KeyAlgorithmProviderImpl,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Algorithm {
    EcdhEs,
    EcdhEsA128kw,
    EcdhEsA192kw,
    Rsa1_5,
    RsaOaep,
    Es256,
    Eddsa,
    //TODO add support for more key types
}

impl TryFrom<String> for Algorithm {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ECDH-ES" => Ok(Algorithm::EcdhEs),
            "ECDH-ES+A128KW" => Ok(Algorithm::EcdhEsA128kw),
            "ECDH-ES+A192KW" => Ok(Algorithm::EcdhEsA192kw),
            "RSA1_5" => Ok(Algorithm::Rsa1_5),
            "RSA-OAEP" => Ok(Algorithm::RsaOaep),
            //ES256 is part of ECDSA. It is ECDSA using P256. ASDK supports it
            "ES256" => Ok(Algorithm::Es256),
            "EdDSA" => Ok(Algorithm::Eddsa),
            _ => Err(Internal {
                source: JWESnafu {
                    details: "Unsupported encryption key algorithm".to_string(),
                }
                .build(),
            }),
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let name = match self {
            Algorithm::EcdhEs => "ECDH-ES",
            Algorithm::EcdhEsA128kw => "ECDH-ES+A128KW",
            Algorithm::EcdhEsA192kw => "ECDH-ES+A192KW",
            Algorithm::Rsa1_5 => "RSA1_5",
            Algorithm::RsaOaep => "RSA-OAEP",
            Algorithm::Es256 => "ES256",
            Algorithm::Eddsa => "EdDSA",
        };
        fmt.write_str(name)
    }
}

impl JweEncryptor {
    pub fn new(metadata: ClientMetadata) -> JweEncryptor {
        let supported_algs = vec![
            Algorithm::EcdhEs,
            Algorithm::Es256, // FIXME: Remove this after proper support of Encryption in ASDK
                              //TODO support more key types and algs
        ];

        let key_algorithm_provider: KeyAlgorithmProviderImpl = KeyAlgorithmProviderImpl::new(
            HashMap::from_iter(vec![
                (EddsaKeyAlgorithm, Arc::new(Eddsa) as Arc<dyn KeyAlgorithm>),
                (EcdsaKeyAlgorithm, Arc::new(Ecdsa) as Arc<dyn KeyAlgorithm>),
            ]),
            Default::default(),
        );
        Self {
            metadata,
            supported_algs,
            key_algorithm_provider,
        }
    }

    fn get_key_algorithm_provider(&self) -> &KeyAlgorithmProviderImpl {
        &self.key_algorithm_provider
    }

    fn supported_keys_contains_alg(&self, jwk: &Map<String, Value>) -> bool {
        if let Some(Value::String(alg)) = jwk.get("alg") {
            self.supported_algs
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .contains(alg)
        } else {
            false
        }
    }

    fn public_key_jwk(&self, config: &JwkConfig) -> Result<PublicJwk, Error> {
        match config.alg {
            Algorithm::Eddsa => Ok(PublicJwk::Okp(PublicJwkEc {
                alg: Some("EdDSA".to_string()),
                r#use: Some(JwkUse::Encryption),
                kid: Some(config.kid.clone()),
                crv: self.get_default_claim("crv", &config.jwk)?,
                x: self.get_default_claim("x", &config.jwk)?,
                y: self.get_default_claim("y", &config.jwk).ok(),
            })),
            Algorithm::Es256 => Ok(PublicJwk::Ec(PublicJwkEc {
                alg: Some("ES256".to_string()),
                r#use: Some(JwkUse::Encryption),
                kid: Some(config.kid.clone()),
                crv: self.get_default_claim("crv", &config.jwk)?,
                x: self.get_default_claim("x", &config.jwk)?,
                y: self.get_default_claim("y", &config.jwk).ok(),
            })),
            Algorithm::EcdhEs => Ok(PublicJwk::Ec(PublicJwkEc {
                alg: Some("ECDH-ES".to_string()),
                r#use: Some(JwkUse::Encryption),
                kid: Some(config.kid.clone()),
                crv: self.get_default_claim("crv", &config.jwk)?,
                x: self.get_default_claim("x", &config.jwk)?,
                y: self.get_default_claim("y", &config.jwk).ok(),
            })),
            _ => Err(Internal {
                source: JWESnafu {
                    details: "Unsupported alg".to_string(),
                }
                .build(),
            }),
        }
    }

    pub async fn get_shared_secret_and_public_key(
        &self,
        input_jwk: &JwkConfig,
    ) -> Result<(SecretSlice<u8>, PublicJwk), Error> {
        let remote_jwk = self.public_key_jwk(input_jwk)?;
        let parsed_key: ParsedKey = self
            .get_key_algorithm_provider()
            .parse_jwk(&remote_jwk)
            .map_err(|_| Internal {
                source: JWESnafu {
                    details: "Unsupported key algorithm".to_string(),
                }
                .build(),
            })?;
        let algorithm = self
            .get_key_algorithm_provider()
            .key_algorithm_from_type(parsed_key.algorithm_type)
            .ok_or(Internal {
                source: JWESnafu {
                    details: "Unsupported key algorithm".to_string(),
                }
                .build(),
            })?;
        let public_key_jwk = parsed_key
            .key
            .key_agreement()
            .ok_or(Internal {
                source: JWESnafu {
                    details: "Unsupported key algorithm".to_string(),
                }
                .build(),
            })?
            .public()
            .as_jwk()
            .map_err(|e| Internal {
                source: JWESnafu {
                    details: format!("Unsupported key algorithm: {}", e),
                }
                .build(),
            })?;
        let local_private_key: GeneratedKey = algorithm.generate_key().map_err(|e| Internal {
            source: JWESnafu {
                details: format!("Unsupported key algorithm: {}", e),
            }
            .build(),
        })?;
        let key_agreement = local_private_key.key.key_agreement().ok_or(Internal {
            source: JWESnafu {
                details: "Unsupported key algorithm".to_string(),
            }
            .build(),
        })?;
        let local_public_key = key_agreement.public().as_jwk().map_err(|e| Internal {
            source: JWESnafu {
                details: format!("Unsupported key algorithm: {}", e),
            }
            .build(),
        })?;

        let remote_jwk = public_key_jwk;
        let shared_secret = key_agreement
            .private()
            .ok_or(Internal {
                source: JWESnafu {
                    details: "Unsupported key algorithm".to_string(),
                }
                .build(),
            })?
            .shared_secret(&remote_jwk)
            .await
            .map_err(|e| Internal {
                source: JWESnafu {
                    details: format!("Unsupported key algorithm: {}", e),
                }
                .build(),
            })?;

        Ok((shared_secret, local_public_key))
    }

    pub async fn encrypt(&self, body: Value) -> Result<String, Error> {
        let jwk_config = self.select_jwk()?;
        let (shared_secret, remote_jwk) =
            self.get_shared_secret_and_public_key(&jwk_config).await?;
        let header = Header {
            key_id: jwk_config.kid.clone(),
            agreement_partyuinfo: None,
            agreement_partyvinfo: None,
        };

        build_jwe(
            body.to_string().as_bytes(),
            header,
            shared_secret,
            remote_jwk,
            jwk_config.encryption_alg,
        )
        .map_err(|e| Internal {
            source: JWESnafu {
                details: format!("Error while encrypting the response: {}", e),
            }
            .build(),
        })
    }

    pub fn select_jwk(&self) -> Result<JwkConfig, Error> {
        let jwks = self
            .metadata
            .jwks()
            .and_then(|item| item.ok())
            .ok_or(Internal {
                source: JWESnafu {
                    details: "JWKs not provided properly".to_string(),
                }
                .build(),
            })?;
        let jwk = jwks
            .keys
            .into_iter()
            .find(|jwk| self.supported_keys_contains_alg(jwk))
            .ok_or(Internal {
                source: JWESnafu {
                    details: "Couldnt find suitable jwk".to_string(),
                }
                .build(),
            })?;
        let encs = self
            .metadata
            .encrypted_response_enc_values_supported()
            .map_err(|e| Internal {
                source: JWESnafu {
                    details: format!(
                        "Error while getting enc values supported from ClientMetadata: {}",
                        e
                    ),
                }
                .build(),
            })?;
        let encryption_alg = self.select_enc(encs);

        Ok(JwkConfig {
            jwk: jwk.clone(),
            encryption_alg,
            kty: self.get_default_claim("kty", &jwk)?,
            kid: self.get_default_claim("kid", &jwk)?,
            alg: self.get_default_claim("alg", &jwk)?.try_into()?,
        })
    }

    fn get_default_claim(
        &self,
        claim_name: &str,
        jwk: &Map<String, Value>,
    ) -> Result<String, Error> {
        let Some(Value::String(claim)) = jwk.get(claim_name) else {
            return Err(Internal {
                source: JWESnafu {
                    details: format!("{claim_name} was not given properly in jwk"),
                }
                .build(),
            });
        };
        Ok(claim.to_owned())
    }

    pub fn select_enc(
        &self,
        encs: Option<EncryptedResponseEncValuesSupported>,
    ) -> EncryptionAlgorithm {
        let Some(encs) = encs else {
            return EncryptionAlgorithm::A128GCM;
        };

        encs.0
            .iter()
            .find_map(|enc| match enc.as_str() {
                "A128GCM" => Some(EncryptionAlgorithm::A128GCM),
                "A256GCM" => Some(EncryptionAlgorithm::A256GCM),
                "A128CBC-HS256" => Some(EncryptionAlgorithm::A128CBCHS256),
                _ => None,
            })
            .unwrap_or(EncryptionAlgorithm::A128GCM)
    }
}

#[cfg(test)]
mod tests {
    use crate::vc::oid4vp::jwe::JweEncryptor;
    use crate::vc::oid4vp::tests::utils::wrap_p256_private_key;
    use one_core_asdk::one_crypto::jwe::decrypt_jwe_payload;
    use serde_json::{Value, json};

    #[tokio::test]
    async fn test_encoding() {
        let metadata = super::test_utils::get_metadata(pregenerated_pub_jwk());
        let encoder = JweEncryptor::new(metadata);
        let body = json!({
            "some_key": "some_value",
        });
        let verifier_private_jwk = r#"{
              "kty": "EC",
              "crv": "P-256",
              "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
              "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
              "d": "rs9veoNnfQCH7kfsAis_nAHtpcEghiAzKry8R-de0eA"
            }"#;

        // Used as part of ClientMetadata
        let verifier_public_jwk = r#"{
              "kty": "EC",
              "crv": "P-256",
              "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
              "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY"
            }"#;
        let jwe = encoder.encrypt(body.clone()).await.unwrap();

        let kh = wrap_p256_private_key(verifier_private_jwk);

        let res = decrypt_jwe_payload(&jwe, &kh).await.unwrap();
        assert_eq!(res, body.to_string().as_bytes().to_vec());
    }

    fn pregenerated_pub_jwk() -> serde_json::Map<String, Value> {
        if let Value::Object(map) = json!({
          "kid": "ecdsa-kid",
          "kty": "EC",
          "crv": "P-256",
          "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
          "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
          "alg": "ECDH-ES"
        }) {
            map
        } else {
            unreachable!()
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use crate::jwe::JweDecrypt;
    use crate::kms::{CreateOptions, KeyHandle, KeyType, Kms};
    use crate::vc::oid4vp::ClientMetadata;
    use crate::vc::oid4vp::jwe::JweEncryptor;
    use serde_json::{Value, json};

    pub async fn test_kms_encrypt_decrypt<KH: KeyHandle>(kms: impl Kms<KH> + JweDecrypt<KH>) {
        let kid = kms
            .create(KeyType::P256, CreateOptions::default())
            .await
            .unwrap();
        let kh = kms.get(&kid).await.unwrap();
        let mut pub_jwk = kh.jwk().unwrap().to_public();
        pub_jwk.key_id = Some(kid.clone());
        let pub_jwk = if let Value::Object(mut map) = serde_json::to_value(&pub_jwk).unwrap() {
            map.insert("alg".to_string(), Value::String("ECDH-ES".to_string()));
            map
        } else {
            unreachable!("");
        };
        let given_payload = json!({"key": "value"});

        let metadata = get_metadata(pub_jwk);
        let encryptor = JweEncryptor::new(metadata);
        let jwe = encryptor.encrypt(given_payload.clone()).await.unwrap();

        let decrypted_payload = kms.decrypt(&jwe, &kid).await.unwrap();
        assert_eq!(decrypted_payload, given_payload);
    }

    pub(crate) fn get_metadata(jwk: serde_json::Map<String, Value>) -> ClientMetadata {
        let mut metadata = serde_json::from_value::<ClientMetadata>(json!({
          "jwks": {
            "keys": [
            ]
          },
          "encrypted_response_enc_values_supported": [
            "A256GCM"
          ]
        }))
        .unwrap();

        let mut jws = metadata.jwks().unwrap().unwrap();
        jws.keys.push(jwk);
        metadata.0.insert(jws);

        metadata
    }
}
