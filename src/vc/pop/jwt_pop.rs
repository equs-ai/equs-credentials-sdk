use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;
use oid4vci::proof_of_possession::{
    ProofOfPossession, ProofOfPossessionController, ProofOfPossessionParams,
    ProofOfPossessionVerificationParams,
};
use snafu::ResultExt;
use ssi::jwk::JWK;

use crate::crypto;
use crate::crypto::SigningKey;
use crate::did::universal::UniversalResolver;
use crate::did::{DIDResolver, DIDURL};
use crate::vc::pop;
use crate::vc::pop::{
    ConversionSnafu, Error, GenerateOptions, ParsingSnafu, VerificationSnafu, VerifyOptions,
};

pub struct SignerWrapper<S: SigningKey> {
    key: S,
}

#[async_trait]
impl<S: SigningKey> oid4vci::proof_of_possession::Signer for SignerWrapper<S> {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ssi::jws::Error> {
        self.key
            .sign(data)
            .await
            .map_err(|e| ssi::jws::Error::InvalidSignature)
    }
}

pub struct JwtProofOfPossession {}

#[async_trait]
impl pop::ProofOfPossession<String> for JwtProofOfPossession {
    async fn generate<S>(
        did_url: &DIDURL,
        key: S,
        nonce: Nonce,
        opts: GenerateOptions,
    ) -> Result<String, Error>
    where
        S: SigningKey,
    {
        let params = &ProofOfPossessionParams {
            audience: opts.cred_iss_id.clone(),
            issuer: opts.client_id.clone(),
            nonce: Some(nonce),
            controller: ProofOfPossessionController {
                vm: Some(did_url.to_owned()),
                // TODO: error handling
                jwk: key.jwk().unwrap(),
            },
        };
        let exp = opts.lifetime.unwrap_or(time::Duration::minutes(10));

        let pop = ProofOfPossession::generate(params, exp);

        let sgn = SignerWrapper { key };

        pop.to_jwt_with_signer(sgn).await.context(ConversionSnafu)
    }

    async fn verify(
        proof: String,
        nonce: Nonce,
        opts: VerifyOptions,
    ) -> Result<(DIDURL, Box<dyn crypto::Key>), Error> {
        let resolver = UniversalResolver::new();

        let pop = ProofOfPossession::from_jwt(proof.as_str(), resolver.as_spruce_resolver())
            .await
            .context(ParsingSnafu)?;

        let verification = pop
            .verify(&ProofOfPossessionVerificationParams {
                audience: opts.cred_iss_id.clone(),
                // TODO: do we need to check client-id if Holder was already authorized?
                issuer: opts.client_id.clone(),
                nonce: nonce.clone(),
                controller_did: None,
                controller_jwk: None,
                nbf_tolerance: None,
                exp_tolerance: None,
            })
            .await
            .context(VerificationSnafu)?;

        // TODO: refactor
        let did_url = pop.controller.vm.unwrap();
        let hld_key = pop.controller.jwk;

        Ok((did_url, Box::new(hld_key)))
    }
}

impl crypto::Key for JWK {
    fn pub_key(&self) -> Result<Vec<u8>, crypto::Error> {
        unimplemented!()
    }

    fn jwk(&self) -> Option<JWK> {
        Some(self.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oid4vci::openidconnect;
    use serde_json::{Map, Value};
    use ssi::did::DIDURL;

    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::Kms;
    use crate::vc::pop::jwt_pop::JwtProofOfPossession;
    use crate::vc::pop::{GenerateOptions, ProofOfPossession, VerifyOptions};

    #[tokio::test]
    async fn e2e() {
        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        for kt in [kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Create a key
            let (_, h_kh) = kms
                .create_and_handle(kt, kms::CreateOptions {})
                .await
                .unwrap();

            let hld_did = didkey.generate(h_kh.clone()).unwrap();
            let hld_did_url = DIDURL::from_str(&hld_did).unwrap();

            println!("Holder DID: {}", hld_did);

            let jwk = h_kh.clone().jwk().unwrap();
            println!("JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

            let nonce = openidconnect::Nonce::new_random();

            let proof = JwtProofOfPossession::generate(
                &hld_did_url,
                h_kh.clone(),
                nonce.clone(),
                GenerateOptions {
                    cred_iss_id: "did:web:issuer.com".to_string(),
                    client_id: Some("client-id".to_string()),
                    lifetime: None,
                },
            )
            .await;
            assert!(proof.is_ok());

            let proof = proof.unwrap();
            println!("Proof JWT:\n{}", proof);

            let decoded: Map<String, Value> =
                ssi::jwt::decode_verify(proof.as_str(), &jwk).unwrap();
            println!(
                "Decoded: {}",
                serde_json::to_string_pretty(&decoded).unwrap()
            );

            assert_eq!(decoded.get("aud").unwrap(), "did:web:issuer.com");
            assert_eq!(decoded.get("iss").unwrap(), "client-id");
            assert!(decoded.contains_key("nonce"));

            let verified = JwtProofOfPossession::verify(
                proof,
                nonce.clone(),
                VerifyOptions {
                    cred_iss_id: "did:web:issuer.com".to_string(),
                    client_id: Some("client-id".to_string()),
                },
            )
            .await;
            assert!(verified.is_ok());

            let (did_url, key) = verified.unwrap();
            assert_eq!(did_url, hld_did_url);
            assert_eq!(jwk.to_public(), key.jwk().unwrap());
        }
    }
}
