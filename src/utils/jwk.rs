use crate::crypto::{AlgNotSupportedSnafu, KeyNotSupportedSnafu};
use crate::{crypto, kms};
use ssi::crypto::{ed25519, k256, p256};
use ssi::jwk::{serialize_p256, serialize_secp256k1, Params};
use ssi::JWK;
use tracing::{instrument, Level};

impl crypto::Key for JWK {
    #[instrument(level = Level::TRACE, skip_all, err())]
    fn pub_key(&self) -> crypto::Result<Vec<u8>> {
        match &self.params {
            Params::EC(params) => {
                let curve = params.curve.as_ref().ok_or_else(|| {
                    KeyNotSupportedSnafu {
                        type_: format!("{:?}", self),
                    }
                    .build()
                })?;

                match curve.as_str() {
                    "secp256k1" => serialize_secp256k1(params).map_err(|err| {
                        KeyNotSupportedSnafu {
                            type_: err.to_string(),
                        }
                        .build()
                    }),
                    "P-256" => serialize_p256(params).map_err(|err| {
                        KeyNotSupportedSnafu {
                            type_: err.to_string(),
                        }
                        .build()
                    }),
                    other => AlgNotSupportedSnafu {
                        alg: other.to_string(),
                    }
                    .fail(),
                }
            }
            Params::OKP(params) => match params.curve.as_str() {
                "Ed25519" => Ok(params.public_key.0.clone()),
                other => AlgNotSupportedSnafu {
                    alg: other.to_string(),
                }
                .fail(),
            },
            _ => KeyNotSupportedSnafu {
                type_: format!("{:?}", self),
            }
            .fail(),
        }
    }

    fn jwk(&self) -> Option<crypto::JWK> {
        Some(self.to_owned())
    }
}

#[instrument(level = Level::TRACE, skip_all, err())]
pub fn get_private_key(jwk: &JWK) -> Result<Vec<u8>, ssi::jwk::Error> {
    match &jwk.params {
        Params::EC(params) => {
            let curve = params
                .curve
                .as_ref()
                .ok_or_else(|| ssi::jwk::Error::MissingCurve)?;

            match curve.as_str() {
                "secp256k1" => {
                    TryInto::<k256::SecretKey>::try_into(params).map(|key| key.to_bytes().to_vec())
                }
                "P-256" => {
                    TryInto::<p256::SecretKey>::try_into(params).map(|key| key.to_bytes().to_vec())
                }
                _ => Err(ssi::jwk::Error::UnsupportedKeyType),
            }
        }
        Params::OKP(params) => match params.curve.as_str() {
            "Ed25519" => {
                TryInto::<ed25519::SigningKey>::try_into(params).map(|key| key.as_bytes().to_vec())
            }
            _ => Err(ssi::jwk::Error::UnsupportedKeyType),
        },
        _ => Err(ssi::jwk::Error::UnsupportedKeyType),
    }
}

#[instrument(level = Level::TRACE, skip_all, ret())]
pub fn get_key_type(jwk: &JWK) -> Option<kms::KeyType> {
    match &jwk.params {
        Params::EC(params) => {
            let curve = params.curve.as_ref()?;

            match curve.as_str() {
                "secp256k1" => Some(kms::KeyType::K256),
                "P-256" => Some(kms::KeyType::P256),
                _ => None,
            }
        }
        Params::OKP(params) => match params.curve.as_str() {
            "Ed25519" => Some(kms::KeyType::Ed25519),
            _ => None,
        },
        _ => None,
    }
}

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn from_spruce_jwk(spruce_jwk: &JWK) -> Option<jsonwebtoken::jwk::Jwk> {
    let Ok(serialized) = serde_json::to_value(spruce_jwk) else {
        return None;
    };

    let Ok(jsonwebtoken_jwk) = serde_json::from_value(serialized) else {
        return None;
    };

    Some(jsonwebtoken_jwk)
}

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn from_spruce_jwk_opt(spruce_jwk: Option<ssi::jwk::JWK>) -> Option<jsonwebtoken::jwk::Jwk> {
    spruce_jwk.and_then(|j| from_spruce_jwk(&j))
}

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn from_jsonwebtoken_jwk(jsonwebtoken_jwk: &jsonwebtoken::jwk::Jwk) -> Option<ssi::jwk::JWK> {
    let Ok(serialized) = serde_json::to_value(jsonwebtoken_jwk) else {
        return None;
    };

    let Ok(spruce_jwk) = serde_json::from_value(serialized) else {
        return None;
    };

    Some(spruce_jwk)
}

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn from_jsonwebtoken_jwk_opt(
    jsonwebtoken_jwk: Option<jsonwebtoken::jwk::Jwk>,
) -> Option<ssi::jwk::JWK> {
    jsonwebtoken_jwk.and_then(|j| from_jsonwebtoken_jwk(&j))
}

#[cfg(test)]
mod tests {
    use crate::utils::jwk::{from_jsonwebtoken_jwk, from_spruce_jwk};

    #[test]
    fn jwk_conversions_work_correctly() {
        let spruce_jwk = ssi::jwk::JWK::generate_ed25519().unwrap();

        let jsonwebtoken_jwk = from_spruce_jwk(&spruce_jwk);
        assert!(jsonwebtoken_jwk.is_some());

        let reconverted = from_jsonwebtoken_jwk(&jsonwebtoken_jwk.unwrap());
        assert!(reconverted.is_some());
        assert!(spruce_jwk.equals_public(&reconverted.unwrap()));
    }
}
