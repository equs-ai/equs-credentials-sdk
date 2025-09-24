use crate::vc::oid4vp::Error::Internal;
use crate::vc::oid4vp::internal_error::JWESnafu;
use crate::vc::oid4vp::{ClientMetadata, Error};
use one_core::config::core_config::KeyAlgorithmType::{
    Ecdsa as EcdsaKeyAlgorithm, Eddsa as EddsaKeyAlgorithm,
};
use one_core::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::model::GeneratedKey;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use one_crypto::jwe::{EncryptionAlgorithm, Header, RemoteJwk, build_jwe};
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
    supported_keys: Vec<Algorithm>,
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
        let supported_keys = vec![
            Algorithm::Eddsa,
            Algorithm::Es256,
            //TODO support more key types and algs
        ];

        let key_algorithm_provider: KeyAlgorithmProviderImpl =
            KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![
                (EddsaKeyAlgorithm, Arc::new(Eddsa) as Arc<dyn KeyAlgorithm>),
                (EcdsaKeyAlgorithm, Arc::new(Ecdsa) as Arc<dyn KeyAlgorithm>),
            ]));
        Self {
            metadata,
            supported_keys,
            key_algorithm_provider,
        }
    }

    fn get_supported_key_types(&self) -> &Vec<Algorithm> {
        &self.supported_keys
    }

    fn get_key_algorithm_provider(&self) -> &KeyAlgorithmProviderImpl {
        &self.key_algorithm_provider
    }
    fn supported_keys_contains_alg(&self, jwk: &Map<String, Value>) -> bool {
        if let Some(Value::String(alg)) = jwk.get("alg") {
            self.get_supported_key_types()
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .contains(alg)
        } else {
            false
        }
    }

    fn public_key_jwk(&self, config: &JwkConfig) -> Result<PublicKeyJwk, Error> {
        match config.alg {
            Algorithm::Eddsa => Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                r#use: Some("enc".to_string()),
                kid: Some(config.kid.clone()),
                crv: self.get_default_claim("crv", &config.jwk)?,
                x: self.get_default_claim("x", &config.jwk)?,
                y: self.get_default_claim("y", &config.jwk).ok(),
            })),
            Algorithm::Es256 => Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                r#use: Some("enc".to_string()),
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
    ) -> Result<(SecretSlice<u8>, RemoteJwk), Error> {
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
        let shared_secret = key_agreement
            .private()
            .ok_or(Internal {
                source: JWESnafu {
                    details: "Unsupported key algorithm".to_string(),
                }
                .build(),
            })?
            .shared_secret(&public_key_jwk)
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
            //TODO one-core puts nonce here. Why?
            agreement_partyuinfo: "some_nonce".to_string(),
            agreement_partyvinfo: "some_nonce".to_string(),
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
        //TODO Default is specified as `A128GCM` in the specification(https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-new-parameters)
        // due to limits of dependencies Agent-SDK uses `A128CBC-HS256` as default value
        if let Some(encs) = encs {
            for enc in encs.0 {
                match enc.as_str() {
                    "A256GCM" => return EncryptionAlgorithm::A256GCM,
                    "A128CBC-HS256" => return EncryptionAlgorithm::A128CBCHS256,
                    _ => {}
                };
            }
            EncryptionAlgorithm::A128CBCHS256
        } else {
            EncryptionAlgorithm::A128CBCHS256
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::vc::oid4vp::jwe_encryptor::JweEncryptor;
    use crate::vc::oid4vp::tests::utils::wrap_p256_private_key;
    use crate::vc::oid4vp::{ClientMetadata, ResolvedAuthRequest};
    use one_crypto::jwe::decrypt_jwe_payload;
    use serde_json::{from_str, json};

    #[tokio::test]
    async fn test_encoding() {
        let metadata = get_metadata();
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

    fn get_metadata() -> ClientMetadata {
        let result: ResolvedAuthRequest = from_str(
            r#"
            {
              "response_uri": "https://some-link.com",
              "client_id": "decentralized_identifier:did:key:zDnaeveTW9mmpzfLKHgmoYox1te7kxhdoboadQf5hM2rtiZjh",
              "response_type": "vp_token",
              "response_mode": "dc_api.jwt",
              "nonce": "xyz123ltcaccescbwc777",
              "dcql_query": {
                "credentials": [
                  {
                    "id": "my_credential",
                    "format": "dc+sd-jwt",
                    "meta": {
                      "vct_values": [
                        "https://credentials.example.com/identity_credential"
                      ]
                    },
                    "claims": [
                      {
                        "path": [
                          "last_name"
                        ]
                      },
                      {
                        "path": [
                          "first_name"
                        ]
                      },
                      {
                        "path": [
                          "address",
                          "postal_code"
                        ]
                      }
                    ]
                  }
                ]
              },
              "client_metadata": {
                "jwks": {
                  "keys": [
                    {
                      "kid": "ecdsa-kid",
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
                      "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
                      "alg": "ES256"
                    }
                  ]
                },
                "encrypted_response_enc_values_supported": [
                  "A256GCM"
                ]
              }
            }
           "#,
        )
        .unwrap();

        result.client_metadata
    }
}
