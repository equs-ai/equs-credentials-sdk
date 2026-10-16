//! Minimal [SignCredential] implementation independent of `IssuerService`.
//!
//! `CredentialSigner` carries only what the signing step actually needs — a KMS for
//! key access and a DID resolver for LDP proof assembly — and is the
//! local-signer counterpart to [crate::vc::core::AssembleCredential] (the
//! external-signer path).
//!
//! `IssuerService` embeds a `CredentialSigner` field and delegates its own
//! [SignCredential] impl to it; the public `Issuer::issue_credential` flow is
//! unchanged.

use crate::did::universal::UniversalResolver;
use crate::kms;
use crate::vc::Credential;
use crate::vc::core::api::InvalidDIDUrlSnafu;
use crate::vc::core::{KMSSnafu, Result, SignCredential, UnsignedCredential, VCSnafu};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use async_trait::async_trait;
use snafu::ResultExt;
use ssi::dids::DIDURLBuf;
use std::marker::PhantomData;
use std::str::FromStr;
use tracing::{Level, instrument};

pub struct CredentialSigner<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    pub(crate) kms: KMS,
    pub(crate) did_resolver: UniversalResolver,
    _marker: PhantomData<KH>,
}

impl<KH, KMS> CredentialSigner<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(kms, resolver))]
    pub fn new(kms: KMS, resolver: UniversalResolver) -> Self {
        Self {
            kms,
            did_resolver: resolver,
            _marker: PhantomData,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<KH, KMS> SignCredential for CredentialSigner<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    async fn sign_credential(&self, unsigned_credential: UnsignedCredential) -> Result<Credential> {
        match unsigned_credential {
            UnsignedCredential::SdJwt(unsigned) => {
                let kh = self
                    .kms
                    .get(&unsigned.issuer_key_id)
                    .await
                    .context(KMSSnafu)?;
                let cred = SdJwtAPI::sign_credential(unsigned, kh)
                    .await
                    .context(VCSnafu)?;
                Ok(Credential::SdJwt(cred))
            }
            UnsignedCredential::Ldp(unsigned) => {
                let kh = self
                    .kms
                    .get(&unsigned.issuer_key_id)
                    .await
                    .context(KMSSnafu)?;
                let iss_did = DIDURLBuf::from_str(&unsigned.issuer_did_url).map_err(|e| {
                    InvalidDIDUrlSnafu {
                        input: format!("{}: {}", unsigned.issuer_did_url, e),
                    }
                    .build()
                })?;

                let vc = JsonLdAPI::sign_credential(
                    unsigned.unsigned_vc,
                    (&iss_did, kh),
                    unsigned.mandatory_claims,
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;
                Ok(Credential::LdpVc(vc))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::did::universal::UniversalResolver;
    use crate::inmem::kms::LocalKms;
    use crate::kms::KeyType;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::core::tests::fixtures::sample_issuer_metadata;
    use crate::vc::core::tests::utils::{CredTestCase, random_nonce};
    use crate::vc::core::{
        CredentialSigner, IssuerService, PrepareCredential, SignCredential, UnsignedCredential,
    };
    use rstest::rstest;

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn credential_signer_signs_unsigned_from_prepare(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = Some(random_nonce().await);
        let proof = case.generate_pop(&kms, nonce.clone(), KeyType::P256).await;

        let issuer = IssuerService::new(
            kms.clone(),
            sample_issuer_metadata(key_metadata, &case),
            UniversalResolver::default(),
        );
        let signer = CredentialSigner::new(kms, UniversalResolver::default());

        let request = case.create_cred_request(proof);
        let unsigned = issuer
            .prepare_credential(&request, &case.claims, nonce, None)
            .await
            .unwrap();

        let credential = signer.sign_credential(unsigned).await.unwrap();
        case.assert_credential(&credential).await;
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn unsigned_credential_serde_roundtrip(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = Some(random_nonce().await);
        let proof = case.generate_pop(&kms, nonce.clone(), KeyType::P256).await;

        let issuer = IssuerService::new(
            kms.clone(),
            sample_issuer_metadata(key_metadata, &case),
            UniversalResolver::default(),
        );
        let signer = CredentialSigner::new(kms, UniversalResolver::default());

        let request = case.create_cred_request(proof);
        let unsigned = issuer
            .prepare_credential(&request, &case.claims, nonce, None)
            .await
            .unwrap();

        let json = serde_json::to_string(&unsigned).unwrap();
        let restored: UnsignedCredential = serde_json::from_str(&json).unwrap();

        // The restored unsigned must still be signable end-to-end via the externally-tagged
        // wire format used by all wrappers.
        let credential = signer.sign_credential(restored).await.unwrap();
        case.assert_credential(&credential).await;
    }
}
