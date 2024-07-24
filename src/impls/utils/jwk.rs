pub fn from_spruce_jwk(spruce_jwk: &ssi::jwk::JWK) -> Option<jsonwebtoken::jwk::Jwk> {
    let Ok(serialized) = serde_json::to_value(spruce_jwk) else { return None };

    let Ok(jsonwebtoken_jwk) = serde_json::from_value(serialized) else { return None };

    Some(jsonwebtoken_jwk)
}

pub fn from_spruce_jwk_opt(spruce_jwk: Option<ssi::jwk::JWK>) -> Option<jsonwebtoken::jwk::Jwk> {
    spruce_jwk.map(|j| from_spruce_jwk(&j)).flatten()
}

pub fn from_jsonwebtoken_jwk(jsonwebtoken_jwk: &jsonwebtoken::jwk::Jwk) -> Option<ssi::jwk::JWK> {
    let Ok(serialized) = serde_json::to_value(jsonwebtoken_jwk) else { return None };

    let Ok(spruce_jwk) = serde_json::from_value(serialized) else { return None };

    Some(spruce_jwk)
}

pub fn from_jsonwebtoken_jwk_opt(jsonwebtoken_jwk: Option<jsonwebtoken::jwk::Jwk>) -> Option<ssi::jwk::JWK> {
    jsonwebtoken_jwk.map(|j| from_jsonwebtoken_jwk(&j)).flatten()
}

#[cfg(test)]
mod tests {
    use crate::impls::utils::jwk::{from_jsonwebtoken_jwk, from_spruce_jwk};

    #[test]
    fn e2e() {
        let spruce_jwk = ssi::jwk::JWK::generate_ed25519().unwrap();

        let jsonwebtoken_jwk = from_spruce_jwk(&spruce_jwk);
        assert!(jsonwebtoken_jwk.is_some());

        let reconverted = from_jsonwebtoken_jwk(&jsonwebtoken_jwk.unwrap());
        assert!(reconverted.is_some());
        assert!(spruce_jwk.equals_public(&reconverted.unwrap()));
    }
}