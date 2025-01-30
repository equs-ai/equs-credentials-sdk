use async_trait::async_trait;
use snafu::ResultExt;
use ssi::dids::DIDURLBuf;
use std::collections::HashMap;
use std::marker::PhantomData;
use tracing::{debug, info, instrument, trace, Level};

use crate::crypto::Alg;
use crate::nonce::Nonce;
use crate::vault::{CredentialEntry, CredentialFilter};
use crate::vc::core::{
    CredentialOffer, CredentialRequest, CredentialRequestData, Holder, HolderMetadata, KeyMetadata,
    PresentationInput, Proof,
};
use crate::vc::core::{
    CredentialOfferContent, FormatNotSupportedSnafu, InvalidDIDUrlSnafu, KMSSnafu,
    ProofFormatRequiredSnafu, ProofSnafu, RequestedCredentialNotFoundSnafu, Result, VCSnafu,
    VaultSnafu,
};
use crate::vc::formats::json_ld_vc;
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VPMetadata};
use crate::vc::formats::{VerifyOptions, API};
use crate::vc::pop::jwt_pop::JwtProofOfPossession;
use crate::vc::pop::ProofOfPossession;
use crate::vc::{pop, Credential, CredentialMetadata, HasVCFormat, Presentation};
use crate::{kms, vault};

pub struct HolderService<KH, KMS, V>
where
    KMS: kms::Kms<KH>,
    KH: kms::KeyHandle,
    V: vault::Vault,
{
    kms: KMS,
    vault: V,
    metadata: HolderMetadata,
    _marker: PhantomData<KH>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[async_trait]
impl<KH, KMS, V> Holder for HolderService<KH, KMS, V>
where
    KMS: kms::Kms<KH>,
    KH: kms::KeyHandle,
    V: vault::Vault,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn request_credential(
        &self,
        credential_offer: &CredentialOffer,
        nonce: &Nonce,
        key_metadata: &KeyMetadata,
    ) -> Result<CredentialRequest> {
        trace!(?credential_offer, ?nonce);

        let supported_proofs = match &credential_offer.content {
            CredentialOfferContent::CredDef(cred_def) => &cred_def.supported_proofs,
            CredentialOfferContent::SupportedProofs(proofs) => proofs,
        };

        let (did_url, key) = self.resolve_key_metadata(key_metadata).await?;
        let pop_fmt = self.resolve_proof_format(supported_proofs.to_owned(), &key)?;

        let proof = match pop_fmt {
            pop::Format::Jwt => JwtProofOfPossession::generate(
                &did_url,
                key,
                nonce,
                pop::GenerateOptions {
                    audience: credential_offer.issuer_id.clone(),
                    issuer: None,
                    lifetime: None,
                },
            )
            .await
            .context(ProofSnafu)?,
            _ => {
                return FormatNotSupportedSnafu {
                    format: pop_fmt.to_string(),
                }
                .fail()
            }
        };
        trace!(resolved_proof = %proof);

        let credential_request = CredentialRequest {
            cred_def_id: credential_offer.cred_def_id.clone(),
            cred_offer_id: credential_offer.cred_offer_id.clone(),
            proof: Proof {
                format: pop_fmt.to_string(),
                proof: proof.to_string(),
            },
            protocol_data: Some(CredentialRequestData::default()),
        };

        Ok(credential_request)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn store_credential(
        &self,
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<String> {
        trace!(?credential, credential_metadata = ?metadata);

        let id = self
            .vault
            .store_credential(credential.to_owned(), metadata)
            .await
            .context(VaultSnafu)?;

        info!("credential {id} stored to the vault");

        Ok(id)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_credential(&self, credential: &Credential) -> Result<()> {
        trace!(?credential);

        match credential {
            Credential::SdJwt(cred) => SdJwtAPI::verify_vc(cred, VerifyOptions::default())
                .await
                .context(VCSnafu),
            Credential::LdpVc(cred) => JsonLdAPI::verify_vc(cred, VerifyOptions::default())
                .await
                .context(VCSnafu),
            _ => FormatNotSupportedSnafu {
                format: credential.format().to_string(),
            }
            .fail()?,
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn create_presentation_auto(
        &self,
        nonce: &Nonce,
        verifier_id: &str,
        presentation_input: &PresentationInput,
    ) -> Result<Presentation> {
        let credentials = self.find_vcs_for_presentation(presentation_input).await?;
        let selected = credentials
            .first()
            .ok_or(RequestedCredentialNotFoundSnafu.build())?;

        let presentation = self
            .create_presentation(nonce, verifier_id, presentation_input, selected)
            .await?;

        Ok(presentation)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn find_vcs_for_presentation(
        &self,
        presentation_input: &PresentationInput,
    ) -> Result<Vec<CredentialEntry>> {
        trace!(?presentation_input);

        let filters = self.resolve_filters(presentation_input);

        info!("search for credentials in the vault");
        let credentials = self
            .vault
            .find_credentials(filters)
            .await
            .context(VaultSnafu)?;

        Ok(credentials.into_iter().collect())
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn create_presentation(
        &self,
        nonce: &Nonce,
        verifier_id: &str,
        presentation_input: &PresentationInput,
        cred_entry: &CredentialEntry,
    ) -> Result<Presentation> {
        info!("access to the key {}", cred_entry.kid);
        let key = self.kms.get(&cred_entry.kid).await.context(KMSSnafu)?;

        let presentation = match &cred_entry.credential {
            Credential::SdJwt(vc) => {
                let disclosures =
                    SdJwtAPI::resolve_disclosures(presentation_input).context(VCSnafu)?;
                let vp =
                    SdJwtAPI::create_vp(vc, key, nonce, verifier_id, VPMetadata { disclosures })
                        .await
                        .context(VCSnafu)?;

                Presentation::SdJwtVp(vp)
            }
            Credential::LdpVc(vc) => {
                let vp = JsonLdAPI::create_vp(
                    vc,
                    key,
                    nonce,
                    verifier_id,
                    json_ld_vc::VPMetadata::from_presentation_input(vc, presentation_input)
                        .context(VCSnafu)?,
                )
                .await
                .context(VCSnafu)?;

                Presentation::LdpVp(vp)
            }
            _ => FormatNotSupportedSnafu {
                format: cred_entry.credential.format().to_string(),
            }
            .fail()?,
        };

        Ok(presentation)
    }
}

impl<KH, KMS, V> HolderService<KH, KMS, V>
where
    KMS: kms::Kms<KH>,
    KH: kms::KeyHandle,
    V: vault::Vault,
{
    #[instrument(level = Level::TRACE, skip(kms, vault))]
    pub fn new(kms: KMS, vault: V, metadata: HolderMetadata) -> Self {
        debug!(holder_metadata = ?metadata);

        Self {
            kms,
            vault,
            metadata,
            _marker: Default::default(),
        }
    }

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn resolve_proof_format(
        &self,
        supported_proofs: Option<HashMap<pop::Format, Vec<Alg>>>,
        key: &KH,
    ) -> Result<pop::Format> {
        let alg = key.alg();

        trace!(?alg);

        let fmt = match supported_proofs {
            Some(proofs) => {
                let (fmt, _) = proofs
                    .iter()
                    .find(|(fmt, algs)| algs.contains(&alg))
                    .ok_or(ProofFormatRequiredSnafu.build())?;

                fmt.to_owned()
            }
            None => pop::Format::Jwt,
        };

        debug!(resolved_format = ?fmt);

        Ok(fmt)
    }

    #[instrument(level = Level::TRACE, skip(self), err())]
    async fn resolve_key_metadata(&self, key_metadata: &KeyMetadata) -> Result<(DIDURLBuf, KH)> {
        let did_url = DIDURLBuf::from_string(key_metadata.did_url.to_owned())
            .map_err(|_| {
                InvalidDIDUrlSnafu {
                    input: &key_metadata.did_url,
                }
                .build()
            })?
            .to_owned();

        info!("access to the key {}", key_metadata.kid);
        let kh = self.kms.get(&key_metadata.kid).await.context(KMSSnafu)?;

        debug!(resolved_did = ?did_url);

        Ok((did_url, kh))
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    fn resolve_filters(&self, input: &PresentationInput) -> Vec<CredentialFilter> {
        trace!(presentation_input = ?input);

        let mut filters = vec![];

        if let Some(format) = &input.format {
            filters.push(CredentialFilter::Format(format.to_owned()));
        }

        for restriction in &input.restrictions {
            if restriction.optional {
                continue;
            }

            match &restriction.value {
                Some(value) => {
                    let result: Vec<CredentialFilter> = restriction
                        .fields
                        .iter()
                        .map(|field| CredentialFilter::Tag(field.to_string(), value.to_string()))
                        .collect();
                    filters.extend(result)
                }
                None => filters.push(CredentialFilter::TagKeys(restriction.fields.clone())),
            }
        }

        filters
    }
}

#[cfg(test)]
mod tests {
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::KeyType;
    use crate::utils::test_utils::{
        create_did_and_key_metadata, create_did_and_key_metadata_by_key_type,
    };
    use crate::vault::{CredentialEntry, FormatNotSupportedSnafu, MockVault, Vault};
    use crate::vc::core::tests::fixtures::{
        sample_cred_def_offer, CREDENTIAL_ID, CRED_DEF_ID, VERIFIER_ID,
    };
    use crate::vc::core::tests::utils::{random_nonce, CredTestCase};
    use crate::vc::core::{Error, Holder, HolderMetadata, HolderService, KeyMetadata};
    use crate::vc::{CredentialMetadata, HasVCFormat};
    use rstest::rstest;

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_requests_credential_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service(kms, vault);

        let offer = sample_cred_def_offer(&case);

        let nonce = random_nonce().await;

        let request = holder
            .request_credential(&offer, &nonce, &key_metadata)
            .await
            .unwrap();

        assert_eq!(request.cred_def_id, CRED_DEF_ID);
        case.assert_proof_of_possession(request.proof, &nonce, &key_metadata.did_url)
            .await;
    }

    #[tokio::test]
    async fn credential_request_fails_in_case_of_kms_error() {
        let kms = LocalKms::new();
        let vault = InMemVault::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let key_metadata = KeyMetadata {
            kid: "invalid_key_id".to_string(),
            ..key_metadata
        };

        let holder = holder_service(kms, vault);
        let offer = sample_cred_def_offer(&CredTestCase::sd_jwt());
        let nonce = random_nonce().await;

        let result = holder
            .request_credential(&offer, &nonce, &key_metadata)
            .await;

        assert!(matches!(result.err().unwrap(), Error::KMS { .. }));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_request_credential_fails_on_invalid_metadata(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service(kms, vault);

        let offer = sample_cred_def_offer(&case);
        let nonce = random_nonce().await;

        let res = holder
            .request_credential(
                &offer,
                &nonce,
                &KeyMetadata {
                    did_url: "".to_string(),
                    ..key_metadata
                },
            )
            .await;

        assert!(matches!(res.err(), Some(Error::InvalidDIDUrl { .. })));

        let res = holder
            .request_credential(
                &offer,
                &nonce,
                &KeyMetadata {
                    kid: "not-found".to_string(),
                    ..key_metadata
                },
            )
            .await;

        assert!(matches!(res.err(), Some(Error::KMS { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_request_credential_fails_on_unsupported_proof(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();
        // Ed25519 is not supported by sample cred def
        let (_, key_metadata) =
            create_did_and_key_metadata_by_key_type(&kms, KeyType::Ed25519).await;

        let holder = holder_service(kms, vault);

        let offer = sample_cred_def_offer(&case);
        let nonce = random_nonce().await;

        let res = holder
            .request_credential(&offer, &nonce, &key_metadata)
            .await;

        assert!(matches!(res.err(), Some(Error::ProofFormatRequired)));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_verifies_credential_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let entry = case.generate_vc(&kms).await;

        let holder = holder_service(kms, vault);

        holder.verify_credential(&entry.credential).await.unwrap();
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_verify_credential_fails_on_invalid_cred(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let holder = holder_service(kms, vault);

        let res = holder.verify_credential(&case.invalid_cred()).await;

        assert!(matches!(res.err(), Some(Error::VC { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_stores_credential_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let entry = case.generate_vc(&kms).await;
        let cred_metadata = CredentialMetadata {
            type_: case.type_.to_string(),
            format: case.format.clone(),
            kid: entry.kid.clone(),
            alg: None,
            tags: vec![],
        };

        let holder = holder_service(kms, vault.clone());

        let id = holder
            .store_credential(&entry.credential, &cred_metadata)
            .await
            .unwrap();

        let stored = vault.get_credential(&id).await.unwrap();

        assert_eq!(
            stored.unwrap().credential.format(),
            entry.credential.format()
        );
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_store_credential_fails_when_vault_fails(#[case] case: CredTestCase) {
        let mut vault = MockVault::new();
        vault.expect_store_credential().return_once(|_, _| {
            FormatNotSupportedSnafu {
                format: "test".to_string(),
            }
            .fail()
        });

        let kms = LocalKms::new();

        let entry = case.generate_vc(&kms).await;
        let cred_metadata = CredentialMetadata {
            type_: case.type_.to_string(),
            format: case.format.clone(),
            kid: entry.kid.clone(),
            alg: None,
            tags: vec![],
        };

        let holder = holder_service(kms, vault);

        let res = holder
            .store_credential(&entry.credential, &cred_metadata)
            .await;

        assert!(matches!(res.err(), Some(Error::Vault { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_find_vcs_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let mut entry1 = case.generate_vc(&kms).await;
        let mut entry2 = case.generate_vc(&kms).await;

        let ids = vault.store_entries(vec![&entry1, &entry2]).await.unwrap();

        let holder = holder_service(kms, vault);

        let input = case.create_presentation_input();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        assert_eq!(creds.len(), 2);

        let serde_json::Value::Array(json_creds) = serde_json::to_value(&creds).unwrap() else {
            panic!("failed to serialize credentials as json array");
        };

        entry1.id = ids[0].clone();
        entry2.id = ids[1].clone();
        assert!(json_creds.contains(&serde_json::to_value(entry1).unwrap()));
        assert!(json_creds.contains(&serde_json::to_value(entry2).unwrap()));

        let input = CredTestCase {
            type_: "non-existing".to_string(),
            ..case
        }
        .create_presentation_input();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        assert!(creds.is_empty())
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_find_credential_fails_when_vault_fails(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let mut vault = MockVault::new();
        vault.expect_find_credentials().return_once(|_| {
            FormatNotSupportedSnafu {
                format: "test".to_string(),
            }
            .fail()
        });

        let holder = holder_service(kms, vault);

        let res = holder
            .find_vcs_for_presentation(&case.create_presentation_input())
            .await;

        assert!(matches!(res.err(), Some(Error::Vault { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_creates_presentation_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let entry = case.generate_vc(&kms).await;

        let holder = holder_service(kms, vault.clone());

        let nonce = random_nonce().await;

        let presentation = holder
            .create_presentation(
                &nonce,
                VERIFIER_ID,
                &case.create_presentation_input(),
                &entry,
            )
            .await
            .unwrap();

        case.assert_presentation(&presentation, &entry.credential)
            .await;
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_create_presentation_fails_on_invalid_kid(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let entry = case.generate_vc(&kms).await;

        let holder = holder_service(kms, vault.clone());

        let nonce = random_nonce().await;

        let res = holder
            .create_presentation(
                &nonce,
                VERIFIER_ID,
                &case.create_presentation_input(),
                &CredentialEntry {
                    kid: "invalid".to_string(),
                    ..entry
                },
            )
            .await;

        assert!(matches!(res.err(), Some(Error::KMS { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_create_presentation_fails_on_invalid_credential(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service(kms, vault);

        let nonce = random_nonce().await;

        let res = holder
            .create_presentation(
                &nonce,
                VERIFIER_ID,
                &case.create_presentation_input(),
                &CredentialEntry {
                    credential: case.invalid_cred(),
                    kid: key_metadata.kid,
                    id: CREDENTIAL_ID.to_string(),
                },
            )
            .await;

        assert!(matches!(res.err(), Some(Error::VC { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_creates_presentation_auto_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let entry = case.generate_vc(&kms).await;
        vault.store_entries(vec![&entry]).await.unwrap();

        let holder = holder_service(kms, vault);

        let nonce = random_nonce().await;

        let presentation = holder
            .create_presentation_auto(&nonce, VERIFIER_ID, &case.create_presentation_input())
            .await
            .unwrap();

        case.assert_presentation(&presentation, &entry.credential)
            .await;
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_create_presentation_auto_fails_when_vault_fails(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let mut vault = MockVault::new();
        vault.expect_find_credentials().return_once(|_| {
            FormatNotSupportedSnafu {
                format: "test".to_string(),
            }
            .fail()
        });

        let entry = case.generate_vc(&kms).await;

        let holder = holder_service(kms, vault);

        let nonce = random_nonce().await;

        let res = holder
            .create_presentation_auto(&nonce, VERIFIER_ID, &case.create_presentation_input())
            .await;

        assert!(matches!(res.err(), Some(Error::Vault { .. })));
    }

    fn holder_service(kms: LocalKms, vault: impl Vault) -> impl Holder {
        HolderService::new(
            kms,
            vault,
            HolderMetadata {
                client_id: "wallet-dev".to_string(),
            },
        )
    }
}
