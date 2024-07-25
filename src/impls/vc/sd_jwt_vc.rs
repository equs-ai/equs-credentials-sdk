use std::collections::HashMap;

use futures::executor;
use jsonwebtoken::{DecodingKey, Header};
use sd_jwt_rs::{ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat, SDJWTVerifier};
use serde_json::{Map, Value};
use ssi::did::VerificationMethodMap;
use ssi::jwk::JWK;
use time::OffsetDateTime;

use crate::core_::{did, vc};
use crate::core_::crypto::{Key, Signer};
use crate::core_::did::{DIDResolver, DIDURL};
use crate::core_::vc::{API, Error, Nonce, VerifyOptions};
use crate::core_::vc::sd_jwt_vc::{Claims, Credential, Disclosure, Presentation, SD_JWT_VC};
use crate::impls::did::UniversalResolver;
use crate::impls::utils;
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
        // TODO: support async signers in `sd-jwt-rust`
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
    pub disclosures: Map<String, Value>,
}

impl vc::HasClaims<Claims> for Credential {
    fn parse_claims(&self) -> Result<Claims, Error> {
        let stripped = SdJwtAPI::strip_disclosures(&self);
        let claims = ssi::jwt::decode_unverified(stripped)?;
        Ok(claims)
    }
}

impl vc::HasCredential<Credential> for Presentation {
    fn get_credential(&self) -> Result<Credential, Error> {
        // NOTE: returns basic VC w/o disclosures
        let stripped = SdJwtAPI::strip_disclosures(&self);
        Ok(stripped.to_owned())
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

    fn resolve_key(iss: &str, _: &Header) -> Result<DecodingKey, Error> {
        let resolver = UniversalResolver::new();

        // TODO: support async `KeyResolver` in `sd-jwt-rust`
        let future = resolver.resolve_verification(iss);
        let ver_method: Result<VerificationMethodMap, did::Error> = executor::block_on(future);

        let ver_method = ver_method?;

        let jwk = ver_method.get_jwk()?;
        let Some(jwk) = utils::jwk::from_spruce_jwk(&jwk) else {
            return Err(Error::KeyNotSupported);
        };

        DecodingKey::from_jwk(&jwk).map_err(|e| Error::Parsing(e.to_string()))
    }

    fn unsafe_resolve_iss_key(iss: &str, header: &Header) -> DecodingKey {
        // TODO: support error handling for `KeyResolver` in `sd-jwt-rust`
        let Ok(key) = Self::resolve_key(iss, header) else {
            panic!("error during resolving issuer key")
        };

        key
    }

    pub fn strip_disclosures(vc: &Credential) -> &str {
        let mut parts = vc.split('~');
        let stripped = match parts.next() {
            Some(part) => part,
            _ => unreachable!(),
        };
        stripped
    }

    pub fn verify_signature(vc: &Credential, jwk: &JWK) -> Result<(), Error> {
        let stripped = Self::strip_disclosures(vc);

        let _ = ssi::jws::decode_verify(stripped, jwk)?;

        Ok(())
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

        let Some(jwk) = utils::jwk::from_spruce_jwk_opt(hld_key.jwk()) else {
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
        S: Signer + 'static,
    {
        let sgn_wrapper = SignerWrapper { signer: Box::new(signer) };

        let mut holder = SDJWTHolder::new(credential.to_owned(), SDJWTSerializationFormat::Compact)
            .map_err(|e| Error::Parsing(e.to_string()))?;

        let presentation = holder.create_presentation(
            metadata.disclosures,
            Some(nonce.secret().to_owned()),
            Some(verifier_id.to_string()),
            Some(&sgn_wrapper),
        );

        Ok(presentation.unwrap())
    }

    async fn verify_vp(presentation: &Presentation, nonce: Nonce, verifier_id: &str, opts: VerifyOptions) -> Result<(), Error> {
        let verifier = SDJWTVerifier::new(
            presentation.to_owned(),
            Box::new(SdJwtAPI::unsafe_resolve_iss_key),
            Some(verifier_id.to_string()),
            Some(nonce.secret().to_string()),
            SDJWTSerializationFormat::Compact,
        ).map_err(|e| Error::Verifying(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oid4vci::openidconnect::Nonce;
    use serde_json::json;
    use ssi::did::DIDURL;

    use crate::core_::{kms, vc};
    use crate::core_::crypto::Key;
    use crate::core_::kms::Kms;
    use crate::core_::vc::{API, HasClaims, HasCredential};
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::vc::sd_jwt_vc::{SdJwtAPI, VCMetadata, VPMetadata};

    #[tokio::test]
    async fn e2e() {
        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();

        for kt in vec![kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Initialization
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
            let hld_jwk = h_kh.clone().jwk().unwrap();
            println!("Hld JWK:\n{}", serde_json::to_string_pretty(&hld_jwk).unwrap());

            // VC
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

            let sgn_res = SdJwtAPI::verify_signature(&vc, &iss_jwk);
            assert!(sgn_res.is_ok());

            // VP
            let nonce = Nonce::new_random();
            let vp_res = SdJwtAPI::create_vp(
                &vc,
                h_kh.clone(),
                nonce.clone(),
                "verifier-id",
                &hld_did_url,
                VPMetadata {
                    disclosures: json!({
                        "name" : false
                    }).as_object().unwrap().to_owned()
                },
            ).await;
            assert!(vp_res.is_ok());

            let vp = vp_res.unwrap();
            println!("VP:\n{}", vp);

            let vc_from_vp = vp.get_credential().unwrap();
            let sgn_res = SdJwtAPI::verify_signature(&vc_from_vp, &iss_jwk);
            assert!(sgn_res.is_ok());

            // Verification
            let ver_res = SdJwtAPI::verify_vp(
                &vp,
                nonce.clone(),
                "verifier-id",
                vc::VerifyOptions {},
            ).await;
            assert!(ver_res.is_ok());
        }
    }
}
