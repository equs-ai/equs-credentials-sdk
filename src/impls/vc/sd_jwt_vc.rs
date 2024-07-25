use std::collections::HashMap;

use futures::executor;
use sd_jwt_rs::{ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer, SDJWTSerializationFormat};
use serde_json::Value;
use time::OffsetDateTime;

use crate::core_::crypto::{Key, Signer};
use crate::core_::did::DIDURL;
use crate::core_::vc;
use crate::core_::vc::{API, Error, Nonce, VerifyOptions};
use crate::core_::vc::sd_jwt_vc::{Claims, Credential, Disclosure, Presentation, SD_JWT_VC};
use crate::impls;
use crate::impls::utils::b64;
use crate::impls::utils::serde::Helpers;

pub struct SignerWrapper {
    signer: Box<dyn Signer>,
}

impl SignerWrapper {}

impl sd_jwt_rs::signer::SDJWTSigner for SignerWrapper {
    fn algorithm(&self) -> &str {
        let alg = self.signer.alg();
        alg.into()
    }

    fn sign(&self, message: &[u8]) -> sd_jwt_rs::error::Result<String> {
        let future = self.signer.sign(message);
        let sgn = executor::block_on(future);
        sgn.map(|s| b64::encode(s))
            .map_err(|e| sd_jwt_rs::error::Error::SigningError(e.to_string()))
    }
}

// Metadata

#[derive(Debug, Default)]
pub struct VCMetadata {
    pub lifetime: Option<time::Duration>,
    pub disclosures: Vec<Disclosure>,
}

#[derive(Debug, Default)]
pub struct VPMetadata {
    pub disclosures: Vec<Disclosure>,
}

impl vc::HasClaims<Claims> for Credential {
    fn parse_claims(&self) -> Result<Claims, Error> {
        let (_, payload, _) = ssi::jws::split_jws(&self.as_str())?;

        let decoded = b64::decode(payload)?;
        let str = String::from_utf8(decoded).map_err(|e| Error::Parsing(e.to_string()))?;

        let claims: Claims = serde_json::from_str(&str)?;

        Ok(claims)
    }
}

impl vc::HasCredential<Credential> for Presentation {
    fn get_credential(&self) -> Result<Credential, Error> {
        todo!()
    }
}

pub struct SdJwtAPI {}

impl SdJwtAPI {
    fn validate_claims(claims: Claims) -> Result<(), Error> {
        if !claims.contains_key("vct") {
            return Err(Error::IncorrectClaim(String::from("missing vct")));
        }

        Ok(())
    }

    fn prepare_claims(claims: Claims,
                      iss_url: &DIDURL, hld_url: &DIDURL,
                      metadata: &VCMetadata) -> Value {
        let mut prepared = serde_json::Map::from(claims);

        prepared.put_str("iss", iss_url);
        prepared.put_str("sub", hld_url);

        let now = OffsetDateTime::now_utc();
        prepared.put_dt("iat", now);
        prepared.put_dt("nbf", now);
        if let Some(exp) = metadata.lifetime.map(|lt| now + lt) {
            prepared.put_dt("exp", exp);
        };

        Value::Object(prepared)
    }

    fn extra_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("typ".to_string(), SD_JWT_VC.to_string());

        headers
    }
}

impl API<Claims, Credential, Presentation, VCMetadata, VPMetadata> for SdJwtAPI {
    async fn create_vc<S, K>(claims: Claims,
                             issuer_data: (&DIDURL, S),
                             holder_data: (&DIDURL, K),
                             metadata: VCMetadata) -> Result<Credential, Error>
    where
        S: Signer + 'static,
        K: Key,
    {
        let (iss_did, signer) = issuer_data;
        let (hld_did, hld_key) = holder_data;

        let sgn_wrapper = SignerWrapper { signer: Box::new(signer) };

        let claims = SdJwtAPI::prepare_claims(claims, iss_did, hld_did, &metadata);
        let headers = SdJwtAPI::extra_headers();

        let Some(jwk) = impls::utils::jwk::from_spruce_jwk_opt(hld_key.jwk()) else {
            return Err(Error::KeyNotSupported);
        };

        let mut issuer = SDJWTIssuer::new(Box::new(sgn_wrapper));
        let res = issuer.issue_sd_jwt(
            claims,
            ClaimsForSelectiveDisclosureStrategy::Custom(metadata.disclosures),
            Some(jwk),
            false,
            SDJWTSerializationFormat::Compact,
            Some(headers),
        );

        res.map_err(|err| Error::Signing(err.to_string()))
    }

    async fn create_vp<S>(credential: &Credential, signer: S,
                          nonce: Nonce, verifier_id: &str,
                          holder_did_url: &DIDURL, metadata: VPMetadata) -> Result<Presentation, Error>
    where
        S: Signer,
    {
        todo!()
    }

    async fn verify_vp(presentation: &Presentation, opts: VerifyOptions) -> Result<(), Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;
    use ssi::did::DIDURL;

    use crate::core_::crypto::Key;
    use crate::core_::kms;
    use crate::core_::kms::Kms;
    use crate::core_::vc::{API, HasClaims};
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::vc::sd_jwt_vc::{SdJwtAPI, VCMetadata};

    #[tokio::test]
    async fn e2e() {
        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();

        for kt in vec![kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Create a key
            let (_, i_kh) = kms.create_and_handle(&kt, kms::CreateOptions {}).await.unwrap();
            let (_, h_kh) = kms.create_and_handle(&kt, kms::CreateOptions {}).await.unwrap();

            let claims = json!( {
                "vct": "https://issuer.net/cred_schema",
                "name": "John Doe",
                "dob": "09/09/1989",
            });

            let iss_did = didkey.generate(i_kh.clone()).unwrap();
            let iss_did_url = DIDURL::from_str(&iss_did).unwrap();
            println!("Iss DID: {}", iss_did);

            let hld_did = didkey.generate(h_kh.clone()).unwrap();
            let hld_did_url = DIDURL::from_str(&hld_did).unwrap();
            println!("Hld DID: {}", hld_did);

            let cl = claims.as_object().unwrap().clone();
            println!("Claims: {:?}", cl);

            let iss_jwk = i_kh.clone().jwk().unwrap();
            println!("Iss JWK:\n{}", serde_json::to_string_pretty(&iss_jwk).unwrap());
            let hld_jwk = i_kh.clone().jwk().unwrap();
            println!("Hld JWK:\n{}", serde_json::to_string_pretty(&hld_jwk).unwrap());

            let vc_res = SdJwtAPI::create_vc(
                cl,
                (&iss_did_url, i_kh.clone()),
                (&hld_did_url, h_kh.clone()),
                VCMetadata {
                    lifetime: Some(time::Duration::days(365)),
                    disclosures: vec!["$.name"],
                },
            ).await;
            assert!(vc_res.is_ok());

            let vc = vc_res.unwrap();
            println!("VC:\n{}", vc);

            let claims = vc.parse_claims().unwrap();
            println!("Claims:\n{}", serde_json::to_string_pretty(&claims).unwrap());

            assert!(!claims.contains_key("name"));
            assert_eq!(claims.get("dob").unwrap(), "09/09/1989");
            assert_eq!(claims.get("sub").unwrap(), &hld_did_url.to_string());
            assert_eq!(claims.get("iss").unwrap(), &iss_did_url.to_string());
        }
    }
}
