use crate::crypto::{AlgNotSupportedSnafu, KeyNotSupportedSnafu};
use crate::{crypto, kms};
#[cfg(not(target_arch = "wasm32"))]
use one_core_asdk::standardized_types::jwk::PublicJwk;
use ssi::JWK;
use ssi::crypto::{ed25519, k256, p256};
use ssi::jwk::{Params, serialize_p256, serialize_secp256k1};
use tracing::{Level, instrument};

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

#[cfg(not(target_arch = "wasm32"))]
#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn from_one_core_public_key_jwk_jsonwebtoken_jwk(
    one_core_jwt: PublicJwk,
) -> Option<jsonwebtoken::jwk::Jwk> {
    let json = serde_json::to_value(one_core_jwt).ok()?;

    serde_json::from_value(json).ok()
}

#[cfg(test)]
mod tests {
    use crate::crypto::Key;
    use crate::kms;
    use crate::utils::jwk::{
        from_jsonwebtoken_jwk, from_jsonwebtoken_jwk_opt, from_spruce_jwk, from_spruce_jwk_opt,
        get_key_type, get_private_key,
    };
    use rstest::rstest;
    use ssi::JWK;
    use ssi::jwk::Params;

    #[test]
    fn jwk_conversions_work_correctly() {
        let spruce_jwk = JWK::generate_ed25519().unwrap();

        let jsonwebtoken_jwk = from_spruce_jwk(&spruce_jwk);
        assert!(jsonwebtoken_jwk.is_some());

        let reconverted = from_jsonwebtoken_jwk(&jsonwebtoken_jwk.unwrap());
        assert!(reconverted.is_some());
        assert!(spruce_jwk.equals_public(&reconverted.unwrap()));
    }

    fn ec_with_unsupported_curve() -> JWK {
        // Start from a real P-256 JWK and rewrite the curve label so the
        // value is well-formed but the curve is one our impl rejects.
        let mut jwk = JWK::generate_p256();
        if let Params::EC(ref mut p) = jwk.params {
            p.curve = Some("P-384".to_string());
        }
        jwk
    }

    fn ec_without_curve() -> JWK {
        let mut jwk = JWK::generate_p256();
        if let Params::EC(ref mut p) = jwk.params {
            p.curve = None;
        }
        jwk
    }

    fn symmetric_jwk() -> JWK {
        JWK::from(Params::Symmetric(ssi::jwk::SymmetricParams {
            key_value: Some(ssi::jwk::Base64urlUInt(vec![0u8; 16])),
        }))
    }

    #[test]
    fn key_pub_key_returns_expected_bytes_for_ed25519() {
        // Ed25519 is the only curve where we can assert the exact public-key
        // bytes (they live unmodified in the OKP params).
        let jwk = JWK::generate_ed25519().unwrap();
        let Params::OKP(ref params) = jwk.params else {
            panic!("expected OKP params");
        };
        let expected = params.public_key.0.clone();

        let bytes = jwk.pub_key().unwrap();

        assert_eq!(bytes, expected);
        assert!(!bytes.is_empty());
    }

    #[rstest]
    #[case::p256(JWK::generate_p256())]
    #[case::secp256k1(JWK::generate_secp256k1())]
    fn key_pub_key_returns_non_empty_bytes_for_ec_curves(#[case] jwk: JWK) {
        let bytes = jwk.pub_key().unwrap();

        assert!(!bytes.is_empty());
    }

    #[test]
    #[should_panic(expected = "Unsupported key type")]
    fn key_pub_key_errors_when_ec_curve_is_missing() {
        let jwk = ec_without_curve();

        jwk.pub_key().unwrap();
    }

    #[test]
    #[should_panic(expected = "Unsupported algorithm: P-384")]
    fn key_pub_key_errors_for_unsupported_curve() {
        let jwk = ec_with_unsupported_curve();

        jwk.pub_key().unwrap();
    }

    #[rstest]
    #[case::ed25519(JWK::generate_ed25519().unwrap())]
    #[case::p256(JWK::generate_p256())]
    #[case::secp256k1(JWK::generate_secp256k1())]
    fn get_private_key_returns_32_bytes_for_supported_curves(#[case] jwk: JWK) {
        let bytes = get_private_key(&jwk).unwrap();

        // Ed25519 secret, P-256 scalar, and secp256k1 scalar are all 32 bytes.
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    #[should_panic(expected = "UnsupportedKeyType")]
    fn get_private_key_rejects_unsupported_curve() {
        let jwk = ec_with_unsupported_curve();

        get_private_key(&jwk).unwrap();
    }

    #[rstest]
    #[case::ed25519(JWK::generate_ed25519().unwrap(), Some(kms::KeyType::Ed25519))]
    #[case::p256(JWK::generate_p256(), Some(kms::KeyType::P256))]
    #[case::secp256k1(JWK::generate_secp256k1(), Some(kms::KeyType::K256))]
    #[case::unsupported_curve(ec_with_unsupported_curve(), None)]
    #[case::symmetric(symmetric_jwk(), None)]
    fn get_key_type_maps_jwk_to_key_type(#[case] jwk: JWK, #[case] expected: Option<kms::KeyType>) {
        assert_eq!(get_key_type(&jwk), expected);
    }

    #[test]
    fn from_spruce_jwk_opt_returns_none_for_none_input() {
        let converted = from_spruce_jwk_opt(None);

        assert!(converted.is_none());
    }

    #[test]
    fn from_spruce_jwk_opt_converts_when_some() {
        let jwk = JWK::generate_ed25519().unwrap();

        let converted = from_spruce_jwk_opt(Some(jwk));

        assert!(converted.is_some());
    }

    #[test]
    fn from_jsonwebtoken_jwk_opt_returns_none_for_none_input() {
        let converted = from_jsonwebtoken_jwk_opt(None);

        assert!(converted.is_none());
    }

    #[test]
    fn from_jsonwebtoken_jwk_opt_converts_when_some() {
        let spruce_jwk = JWK::generate_ed25519().unwrap();
        let jsonwebtoken_jwk = from_spruce_jwk(&spruce_jwk).unwrap();

        let roundtrip = from_jsonwebtoken_jwk_opt(Some(jsonwebtoken_jwk));

        assert!(roundtrip.is_some());
        assert!(spruce_jwk.equals_public(&roundtrip.unwrap()));
    }
}
