use async_trait::async_trait;
use oid4vci::proof_of_possession::{
    ProofOfPossession, ProofOfPossessionController, ProofOfPossessionParams,
    ProofOfPossessionVerificationParams,
};
use snafu::ResultExt;
use ssi::claims::jws;
use ssi::dids::DIDURLBuf;
use tracing::{debug, instrument, trace, Level};

use crate::crypto;
use crate::crypto::{Alg, SigningKey};
use crate::did::universal::UniversalResolver;
use crate::did::DIDURL;
use crate::nonce::Nonce;
use crate::vc::pop;
use crate::vc::pop::{
    ConversionSnafu, CryptoSnafu, Error, GenerateOptions, JWSSnafu, KeyTypeNotSupportedSnafu,
    ParsingSnafu, VerificationSnafu, VerifyOptions,
};

pub struct JwtProofOfPossession {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl pop::ProofOfPossession<String> for JwtProofOfPossession {
    #[instrument(level = Level::TRACE, skip(key), err(), ret())]
    async fn generate<S>(
        did_url: &DIDURL,
        key: S,
        nonce: &Nonce,
        opts: GenerateOptions,
    ) -> Result<String, Error>
    where
        S: SigningKey,
    {
        let params = &ProofOfPossessionParams {
            audience: opts.audience.clone(),
            issuer: opts.issuer.clone(),
            nonce: Some(oid4vci::types::Nonce::new(nonce.secret().to_owned())),
            controller: ProofOfPossessionController {
                vm: Some(did_url.to_owned()),
                jwk: key.jwk().ok_or(
                    KeyTypeNotSupportedSnafu {
                        type_: "JWK incompatible",
                    }
                    .build(),
                )?,
            },
        };
        let exp = opts.lifetime.unwrap_or(time::Duration::minutes(5));

        let pop = ProofOfPossession::generate(params, exp);

        let signing_input = pop.to_jwt_signing_input().context(ConversionSnafu)?;
        let signed = key.sign(&signing_input).await.context(CryptoSnafu)?;

        let jws = pop.to_jwt_with_signature(signed).context(ConversionSnafu)?;

        Ok(jws)
    }

    #[instrument(level = Level::TRACE, err())]
    async fn verify(
        proof: String,
        nonce: &Nonce,
        opts: VerifyOptions,
    ) -> Result<(DIDURLBuf, Box<dyn crypto::Key>), Error> {
        let resolver = UniversalResolver::default();

        let pop = ProofOfPossession::from_jwt(proof.as_str(), resolver)
            .await
            .context(ParsingSnafu)?;

        let verification = pop
            .verify(&ProofOfPossessionVerificationParams {
                audience: opts.audience.clone(),
                // TODO: do we need to check client-id if Holder was already authorized?
                issuer: opts.issuer.clone(),
                nonce: oid4vci::types::Nonce::new(nonce.secret().to_owned()),
                nbf_tolerance: opts.clock_tolerance,
                exp_tolerance: opts.clock_tolerance,
                controller_did: None,
                controller_jwk: None,
            })
            .await
            .context(VerificationSnafu)?;

        debug!("proof of possession is verified");

        let did_url = pop.controller.vm.ok_or(Error::VerificationMethodNotFound)?;
        let hld_key = pop.controller.jwk;

        trace!(resolved_did_url = ?did_url);

        Ok((did_url, Box::new(hld_key)))
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    fn alg(proof: &String) -> Result<Alg, Error> {
        let (header, _) = jws::decode_unverified(proof).context(JWSSnafu)?;

        let alg = header.algorithm;
        (&alg).try_into().context(CryptoSnafu)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{Map, Value};

    use crate::crypto::Key;
    use crate::did::DIDURL;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::kms::KeyType;
    use crate::nonce::{Nonce, NonceGenerator};
    use crate::utils::test_utils::{create_did_url_and_key_handle, failed_signer_key, no_jwk_key};
    use crate::vc::pop::jwt_pop::JwtProofOfPossession;
    use crate::vc::pop::{Error, GenerateOptions, ProofOfPossession, VerifyOptions};

    #[rstest]
    #[case::p256(KeyType::P256)]
    #[case::ed25519(KeyType::Ed25519)]
    #[tokio::test]
    async fn jwt_pop_generation_and_verification_work_correctly_for_all_supported_keys(
        #[case] kt: KeyType,
    ) {
        let kms = LocalKms::new();
        let (did_url, kh) = create_did_url_and_key_handle(&kms, kt.clone()).await;
        let jwk = kh.clone().jwk().unwrap();

        let nonce = random_nonce().await;
        let proof =
            JwtProofOfPossession::generate(&did_url, kh.clone(), &nonce, sample_generate_opts())
                .await
                .unwrap();

        let decoded: Map<String, Value> =
            ssi::claims::jwt::decode_verify(proof.as_str(), &jwk).unwrap();
        assert_eq!(decoded.get("aud").unwrap(), "did:web:issuer.com");
        assert_eq!(decoded.get("iss").unwrap(), "client-id");
        assert!(decoded.contains_key("nonce"));

        let (v_did_url, key) = JwtProofOfPossession::verify(proof, &nonce, sample_verify_opts())
            .await
            .unwrap();

        assert_eq!(v_did_url.did(), did_url.did());
        assert_eq!(key.jwk().unwrap(), jwk);
    }

    #[tokio::test]
    async fn jwt_pop_generation_fails_on_invalid_jwk() {
        let kh = no_jwk_key();
        let did_url = DIDURL::new("did:example:123").unwrap();

        let res = JwtProofOfPossession::generate(
            did_url,
            kh,
            &random_nonce().await,
            sample_generate_opts(),
        )
        .await;

        assert!(matches!(res.err(), Some(Error::KeyTypeNotSupported { .. })));
    }

    #[tokio::test]
    async fn jwt_pop_generation_fails_on_invalid_signer() {
        let kms = LocalKms::new();
        let (did_url, kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let failed_kh = failed_signer_key(kh);

        let res = JwtProofOfPossession::generate(
            &did_url,
            failed_kh,
            &random_nonce().await,
            sample_generate_opts(),
        )
        .await;

        assert!(matches!(res.err(), Some(Error::Crypto { .. })));
    }

    #[tokio::test]
    async fn jwt_pop_verification_fails_on_invalid_payload() {
        let res = JwtProofOfPossession::verify(
            "invalid-jwt".to_string(),
            &random_nonce().await,
            sample_verify_opts(),
        )
        .await;

        assert!(matches!(res.err(), Some(Error::Parsing { .. })));
    }

    #[tokio::test]
    async fn jwt_pop_verification_fails_on_invalid_nonce() {
        let kms = LocalKms::new();
        let (did_url, kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let nonce1 = random_nonce().await;
        let proof = JwtProofOfPossession::generate(&did_url, kh, &nonce1, sample_generate_opts())
            .await
            .unwrap();

        let nonce2 = random_nonce().await;
        let res = JwtProofOfPossession::verify(proof, &nonce2, sample_verify_opts()).await;

        assert!(matches!(res.err(), Some(Error::Verification { .. })));
    }

    async fn random_nonce() -> Nonce {
        LocalNonceGenerator::default().generate().await.unwrap()
    }

    fn sample_generate_opts() -> GenerateOptions {
        GenerateOptions {
            audience: "did:web:issuer.com".to_string(),
            issuer: Some("client-id".to_string()),
            lifetime: None,
        }
    }

    fn sample_verify_opts() -> VerifyOptions {
        VerifyOptions {
            audience: "did:web:issuer.com".to_string(),
            issuer: Some("client-id".to_string()),
            ..Default::default()
        }
    }
}
