use async_trait::async_trait;
use snafu::ResultExt;
use ssi::dids::DIDURLBuf;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;
use tracing::{Level, debug, info, instrument, trace};

use crate::crypto::Alg;
use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::nonce::Nonce;
use crate::vault::CredentialEntry;
use crate::vc::core::api::ClaimsDidNotPassFilteringSnafu;
use crate::vc::core::{
    CredentialOffer, CredentialRequest, CredentialRequestData, Holder, HolderBinder,
    HolderMetadata, KeyMetadata, PresentationInput, Proof,
};
use crate::vc::core::{
    CredentialOfferContent, FormatNotSupportedSnafu, InvalidDIDUrlSnafu, KMSSnafu,
    ProofFormatRequiredSnafu, ProofSnafu, RequestedCredentialNotFoundSnafu, Result, VCSnafu,
    VaultSnafu,
};
use crate::vc::formats::json_ld_vc;
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VPMetadata};
use crate::vc::formats::{API, VerifyOptions};
use crate::vc::oid4vp::{CredentialsFindResult, FindVCsFailReason};
use crate::vc::pop::ProofOfPossession;
use crate::vc::pop::jwt_pop::JwtProofOfPossession;
use crate::vc::presentation_exchange::{is_valid_vc_type, validate_credential};
use crate::vc::{Credential, CredentialMetadata, HasVCFormat, Presentation, pop};
use crate::{kms, vault};

#[derive(Clone)]
pub struct HolderService<KH, KMS, V, HC>
where
    KMS: kms::Kms<KH>,
    KH: kms::KeyHandle,
    V: vault::Vault,
    HC: HttpClient,
{
    kms: KMS,
    vault: V,
    _marker: PhantomData<KH>,
    metadata: HolderMetadata,
    did_resolver: UniversalResolver,
    http_client: Arc<HC>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<KH, KMS, V, HC> Holder for HolderService<KH, KMS, V, HC>
where
    KMS: kms::Kms<KH>,
    KH: kms::KeyHandle,
    V: vault::Vault,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn request_credential(
        &self,
        credential_offer: &CredentialOffer,
        nonce: Option<Nonce>,
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
                    lifetime: self.metadata.pop.lifetime,
                    not_before: self.metadata.pop.not_before,
                },
            )
            .await
            .context(ProofSnafu)?,
            _ => {
                return FormatNotSupportedSnafu {
                    format: pop_fmt.to_string(),
                }
                .fail();
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
            Credential::SdJwt(cred) => SdJwtAPI::verify_vc(
                cred,
                VerifyOptions {
                    selective_claims: Default::default(),
                },
                self.did_resolver.clone(),
            )
            .await
            .context(VCSnafu),
            Credential::LdpVc(cred) => JsonLdAPI::verify_vc(
                cred,
                VerifyOptions {
                    selective_claims: Default::default(),
                },
                self.did_resolver.clone(),
            )
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
        holder_binder: Option<HolderBinder>,
        presentation_input: &PresentationInput,
    ) -> Result<Presentation> {
        let credentials = self.find_vcs_for_presentation(presentation_input).await?;

        if let CredentialsFindResult::Credentials(credentials) = credentials
            && let Some(credential) = credentials.first()
        {
            return self
                .create_presentation(holder_binder, presentation_input, credential)
                .await;
        }

        RequestedCredentialNotFoundSnafu {
            details: "No credential found",
        }
        .fail()
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn find_vcs_for_presentation(
        &self,
        presentation_input: &PresentationInput,
    ) -> Result<CredentialsFindResult> {
        trace!(?presentation_input);

        let fields = presentation_input
            .restrictions
            .iter()
            .flat_map(|pr| pr.fields.clone())
            .collect::<Vec<_>>();

        info!("search for credentials in the vault");
        let credentials: Vec<CredentialEntry> = if !fields.is_empty() {
            self.vault
                .find_credentials(fields, None)
                .await
                .context(VaultSnafu)?
        } else {
            self.vault.get_credentials(None).await.context(VaultSnafu)?
        };

        let mut reasons: HashSet<FindVCsFailReason> = HashSet::new();
        let mut credentials_result = vec![];
        let mut cached_status_list = HashMap::new();
        for entry in credentials {
            if let Ok(true) | Err(_) = entry.credential.is_expired() {
                continue;
            }

            if let Ok(false) | Err(_) = entry
                .credential
                .is_valid(
                    self.http_client.deref(),
                    self.did_resolver.to_owned(),
                    Some(&mut cached_status_list),
                )
                .await
            {
                continue;
            }

            let is_valid_vc_type = is_valid_vc_type(&entry.credential, presentation_input)
                .map_err(|e| {
                    ClaimsDidNotPassFilteringSnafu {
                        details: e.to_string(),
                    }
                    .build()
                })?;

            if !is_valid_vc_type {
                reasons.insert(FindVCsFailReason::TypesNotMatched);
                continue;
            }

            let result =
                validate_credential(&entry.credential, presentation_input).map_err(|e| {
                    ClaimsDidNotPassFilteringSnafu {
                        details: e.to_string(),
                    }
                    .build()
                })?;
            if let Some(inner_reasons) = result {
                reasons.insert(FindVCsFailReason::Paths(inner_reasons));
            } else {
                credentials_result.push(entry);
            }
        }

        if !credentials_result.is_empty() {
            return Ok(CredentialsFindResult::Credentials(credentials_result));
        }

        if reasons.is_empty() {
            return Ok(CredentialsFindResult::Reason(
                FindVCsFailReason::CredentialsNotFound,
            ));
        }

        let mut claim_paths = reasons
            .into_iter()
            .filter_map(|reason| {
                if let FindVCsFailReason::Paths(paths) = reason {
                    Some(paths)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if claim_paths.is_empty() {
            return Ok(CredentialsFindResult::Reason(
                FindVCsFailReason::TypesNotMatched,
            ));
        }

        claim_paths.sort_by_key(|a| a.len());

        Ok(CredentialsFindResult::Reason(FindVCsFailReason::Paths(
            claim_paths[0].to_owned(),
        )))
    }
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn create_presentation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation_input: &PresentationInput,
        cred_entry: &CredentialEntry,
    ) -> Result<Presentation> {
        info!("access to the key {}", cred_entry.kid);
        let key = self.kms.get(&cred_entry.kid).await.context(KMSSnafu)?;

        let presentation = match &cred_entry.credential {
            Credential::SdJwt(vc) => {
                let disclosures =
                    SdJwtAPI::resolve_disclosures(presentation_input).context(VCSnafu)?;
                let vp = SdJwtAPI::create_vp(
                    vc,
                    key,
                    VPMetadata {
                        disclosures,
                        holder_binder,
                    },
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;

                Presentation::SdJwtVp(vp)
            }
            Credential::LdpVc(vc) => {
                let metadata = json_ld_vc::VPMetadata::from_presentation_input(
                    vc,
                    presentation_input,
                    holder_binder,
                )
                .context(VCSnafu)?;
                let vp = JsonLdAPI::create_vp(vc, key, metadata, self.did_resolver.clone())
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
impl<KH, KMS, V, HC> HolderService<KH, KMS, V, HC>
where
    KMS: kms::Kms<KH>,
    KH: kms::KeyHandle,
    V: vault::Vault,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(kms, vault, did_resolver, http_client))]
    pub fn new(
        kms: KMS,
        vault: V,
        metadata: HolderMetadata,
        did_resolver: UniversalResolver,
        http_client: Arc<HC>,
    ) -> Self {
        debug!(holder_metadata = ?metadata);

        Self {
            kms,
            vault,
            metadata,
            _marker: Default::default(),
            did_resolver,
            http_client,
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
}

#[cfg(test)]
mod tests {
    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::did::{DID, DIDBuf, DIDResolver};
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::inmem::vault::InMemVault;
    use crate::kms::{KeyType, Kms};
    use crate::reqwest::builder::ReqwestClientBuilder;
    use crate::utils::test_utils::{
        create_did_and_key_metadata, create_did_and_key_metadata_by_key_type,
    };
    use crate::vault::{CredentialEntry, FormatNotSupportedSnafu, MockVault, Vault};
    use crate::vc::core::status_issuer::StatusIssuerService;
    use crate::vc::core::tests::fixtures::{
        CRED_DEF_ID, CREDENTIAL_ID, VERIFIER_ID, sample_cred_def_offer,
    };
    use crate::vc::core::tests::utils::{CredTestCase, random_nonce};
    use crate::vc::core::{
        CredentialDefinitionData, Error, Holder, HolderBinder, HolderMetadata, HolderService,
        KeyMetadata, ProofOfPossessionMetadata, StatusIssuer, StatusIssuerMetadata,
        StatusListDefinition,
    };
    use crate::vc::oid4vp::{CredentialsFindResult, FindVCsFailReason};
    use crate::vc::presentation_exchange::StatusSize;
    use crate::vc::status_formats::StatusListFormat;
    use crate::vc::status_formats::status_list_token_jwt::{VCStatus, VCStatuses};
    use crate::vc::{CredentialMetadata, HasVCFormat, Presentation, VCStatusesData};
    use crate::{kms, vc};
    use rstest::rstest;
    use serde_json::json;
    use std::str::FromStr;
    use std::sync::Arc;
    use time::Duration;
    use url::Url;

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

        let nonce = Some(random_nonce().await);

        let request = holder
            .request_credential(&offer, nonce.clone(), &key_metadata)
            .await
            .unwrap();

        assert_eq!(request.cred_def_id, CRED_DEF_ID);
        case.assert_proof_of_possession(request.proof, nonce, &key_metadata.did_url)
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
        let nonce = Some(random_nonce().await);

        let result = holder
            .request_credential(&offer, nonce, &key_metadata)
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
        let nonce = Some(random_nonce().await);

        let res = holder
            .request_credential(
                &offer,
                nonce.clone(),
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
                nonce,
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
        let nonce = Some(random_nonce().await);

        let res = holder
            .request_credential(&offer, nonce, &key_metadata)
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

        let (entry, _) = case.generate_vc(&kms, None).await;

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

        let (entry, _) = case.generate_vc(&kms, None).await;
        let cred_metadata = CredentialMetadata {
            type_: case.type_.to_string(),
            format: case.format.clone(),
            kid: entry.kid.clone(),
            alg: None,
            fields: vec![],
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

        let (entry, _) = case.generate_vc(&kms, None).await;
        let cred_metadata = CredentialMetadata {
            type_: case.type_.to_string(),
            format: case.format.clone(),
            kid: entry.kid.clone(),
            alg: None,
            fields: vec![],
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

        let (mut entry1, did_url1) = case.generate_vc(&kms, None).await;
        let (mut entry2, did_url2) = case.generate_vc(&kms, None).await;

        let ids = vault
            .store_entries(vec![
                (&entry1, did_url1.as_str()),
                (&entry2, did_url2.as_str()),
            ])
            .await
            .unwrap();

        let holder = holder_service(kms, vault);

        let input = case.create_presentation_input();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        let CredentialsFindResult::Credentials(creds) = creds else {
            panic!(
                "Wrong return type from holder.find_vcs_for_presentation. Should be non empty credentials"
            )
        };

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

        let CredentialsFindResult::Reason(FindVCsFailReason::TypesNotMatched) = creds else {
            panic!(
                "Wrong return type from holder.find_vcs_for_presentation. Should be mismatched credentials",
            )
        };
    }

    #[rstest]
    #[case::non_revoked_sd_jwt(CredTestCase::sd_jwt(), false)]
    #[case::revoked_sd_jwt(CredTestCase::sd_jwt(), true)]
    #[case::non_revoked_ldp_vc(CredTestCase::ldp_vc(), false)]
    #[should_panic(expected = "Format ldp_vc does not support status_list")]
    #[case::revoked_ldp_vc(CredTestCase::ldp_vc(), true)] // NOT SUPPORTED YET
    #[tokio::test]
    async fn holder_find_vcs_filter_revoked_creds(
        #[case] mut case: CredTestCase,
        #[case] revoke: bool,
    ) {
        let server = httpmock::MockServer::start_async().await;

        let host = server.host();
        let port = server.port();
        let server_list_path = "/status_list";

        let status_list_url =
            Url::parse(&format!("http://{host}:{port}{server_list_path}")).unwrap();

        let staus_issuer = build_status_issuer(status_list_url.clone()).await;

        let status_list = issue_status_list_with_revoked_indexes(&staus_issuer, vec![1]).await;

        server
            .mock_async(|when, then| {
                when.method("GET").path(server_list_path);
                then.status(200)
                    .header("content-type", "application/statuslist+jwt")
                    .body(status_list.clone());
            })
            .await;

        if revoke {
            case = case.add_revoked_status(status_list_url);
        }

        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let (entry1, did_url1) = case.generate_vc(&kms, None).await;

        let ids = vault
            .store_entries(vec![(&entry1, did_url1.as_str())])
            .await
            .unwrap();

        let holder = holder_service(kms, vault);

        let input = case.create_presentation_input();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        match creds {
            CredentialsFindResult::Credentials(credentials) => {
                if revoke {
                    panic!(
                        "Wrong return type from holder.find_vcs_for_presentation. Should be reason with 'No valid credentials found'"
                    )
                }
                assert_eq!(credentials.len(), 1);
            }
            CredentialsFindResult::Reason(FindVCsFailReason::CredentialsNotFound) => {
                if !revoke {
                    panic!(
                        "Wrong return type from holder.find_vcs_for_presentation. Should be non empty credentials"
                    )
                }
            }
            _ => {
                panic!(
                    "Wrong return type from holder.find_vcs_for_presentation. Should be reason with 'No valid credentials found'",
                )
            }
        }
    }

    #[rstest]
    #[case::not_expired_sd_jwt(CredTestCase::sd_jwt(), false)]
    #[case::expired_sd_jwt(CredTestCase::sd_jwt(), true)]
    #[case::not_expired_ldp_vc(CredTestCase::ldp_vc(), false)]
    #[case::expired_ldp_vc(CredTestCase::ldp_vc(), true)]
    #[tokio::test]
    async fn holder_find_vcs_filter_expired_creds(
        #[case] case: CredTestCase,
        #[case] expire: bool,
    ) {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let (entry1, did_url1) = case
            .generate_vc(&kms, expire.then_some(Default::default()))
            .await;

        let ids = vault
            .store_entries(vec![(&entry1, did_url1.as_str())])
            .await
            .unwrap();

        let holder = holder_service(kms, vault);

        let input = case.create_presentation_input();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        match creds {
            CredentialsFindResult::Credentials(credentials) => {
                if expire {
                    panic!(
                        "Wrong return type from holder.find_vcs_for_presentation. Should be reason with 'No valid credentials found'"
                    )
                }
                assert_eq!(credentials.len(), 1);
            }
            CredentialsFindResult::Reason(FindVCsFailReason::CredentialsNotFound) => {
                if !expire {
                    panic!(
                        "Wrong return type from holder.find_vcs_for_presentation. Should be non empty credentials"
                    )
                }
            }
            _ => {
                panic!(
                    "Wrong return type from holder.find_vcs_for_presentation. Should be reason with 'No valid credentials found'"
                )
            }
        }
    }

    #[tokio::test]
    async fn holder_find_vcs_for_presentation_returns_paths() {
        let case_1 = CredTestCase {
            protocol_data: Some(CredentialDefinitionData::SdJwt {
                vct: "https://issuer.net/cred_schema".to_owned(),
                disclosures: vec!["$.givenName".to_owned(), "$.familyName".to_owned()],
                lifetime: Duration::days(5 * 365),
            }),
            claims: json!({
                "givenNameFake": "John",
                "familyNameFake": "Doe",
                "birthDate": "1978-7-17",
                "children": {
                    "givenName": "John",
                    "familyName": "Wick",
                    "birthDate": "1999-7-10",
                }
            })
            .try_into()
            .unwrap(),
            ..CredTestCase::sd_jwt()
        };
        let case_2 = CredTestCase {
            protocol_data: Some(CredentialDefinitionData::SdJwt {
                vct: "https://issuer.net/cred_schema".to_owned(),
                disclosures: vec!["$.givenName".to_owned(), "$.familyName".to_owned()],
                lifetime: Duration::days(5 * 365),
            }),
            claims: json!({
                "givenName": "John",
                "familyName": "Doe",
                "birthDate": "1978-7-17",
                "children": {
                    "givenName": "John",
                    "familyName": "Wick",
                    "birthDate": "1999-7-10",
                }
            })
            .try_into()
            .unwrap(),
            ..CredTestCase::sd_jwt()
        };
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let (entry1, did_url1) = case_1.generate_vc(&kms, None).await;
        let (entry2, did_url2) = case_2.generate_vc(&kms, None).await;

        let ids = vault
            .store_entries(vec![
                (&entry1, did_url1.as_str()),
                (&entry2, did_url2.as_str()),
            ])
            .await
            .unwrap();

        let holder = holder_service(kms, vault);

        let case_for_input = CredTestCase {
            type_: "https://issuer.net/cred_schema_2".to_string(),
            ..case_1.clone()
        };

        let input = case_for_input.create_presentation_input_with_fake_constraints();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        let CredentialsFindResult::Reason(FindVCsFailReason::Paths(claim_paths)) = creds else {
            panic!(
                "Wrong return type from holder.find_vcs_for_presentation. Should reasons of not passing filtering",
            )
        };

        assert_eq!(claim_paths.len(), 1);
        assert_eq!(claim_paths.first().unwrap().len(), 2);
        assert_eq!(
            claim_paths.first().unwrap(),
            &vec!["$.birthDate", "$.children.birthDate"]
        );
    }

    #[tokio::test]
    async fn holder_find_vcs_for_presentation_returns_types_not_matched() {
        let case_1 = CredTestCase::sd_jwt();
        let case_2 = CredTestCase {
            protocol_data: Some(CredentialDefinitionData::SdJwt {
                vct: "https://issuer.net/cred_schema_1".to_owned(),
                disclosures: vec!["$.givenName".to_owned(), "$.familyName".to_owned()],
                lifetime: Duration::days(5 * 365),
            }),
            ..case_1.clone()
        };
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let (entry1, did_url1) = case_1.generate_vc(&kms, None).await;
        let (entry2, did_url2) = case_2.generate_vc(&kms, None).await;

        let ids = vault
            .store_entries(vec![
                (&entry1, did_url1.as_str()),
                (&entry2, did_url2.as_str()),
            ])
            .await
            .unwrap();

        let holder = holder_service(kms, vault);

        let case_for_input = CredTestCase {
            type_: "https://issuer.net/cred_schema_2".to_string(),
            ..case_1.clone()
        };

        let input = case_for_input.create_presentation_input();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        let CredentialsFindResult::Reason(FindVCsFailReason::TypesNotMatched) = creds else {
            panic!(
                "Wrong return type from holder.find_vcs_for_presentation. Should reasons of not passing filtering",
            )
        };
    }

    #[tokio::test]
    async fn holder_find_credential_returns_reason_when_no_creds_found_in_vault() {
        let case = CredTestCase::sd_jwt();

        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let (entry1, did_url1) = case.generate_vc(&kms, None).await;

        let holder = holder_service(kms, vault);

        let input = case.create_presentation_input();

        let creds = holder.find_vcs_for_presentation(&input).await.unwrap();

        let CredentialsFindResult::Reason(FindVCsFailReason::CredentialsNotFound) = creds else {
            panic!(
                "Wrong return type from holder.find_vcs_for_presentation. Should reasons with CredentialNotFound",
            )
        };
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_find_credential_fails_when_vault_fails(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let mut vault = MockVault::new();
        vault.expect_find_credentials().return_once(|_, _| {
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

        let (entry, _) = case.generate_vc(&kms, None).await;

        let holder = holder_service(kms, vault.clone());

        let nonce = random_nonce().await;

        let presentation = holder
            .create_presentation(
                Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &case.create_presentation_input(),
                &entry,
            )
            .await
            .unwrap();

        if let Presentation::LdpVp(vp) = presentation.to_owned() {
            let proof = vp.proofs.iter().find(|v| !v.domains.is_empty()).unwrap();
            assert!(proof.domains.contains(&VERIFIER_ID.to_string()));
            assert!(proof.challenge.to_owned().unwrap().as_str() == nonce.secret());
        }
        case.assert_presentation(&presentation, &entry.credential)
            .await;
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn holder_creates_presentation_correctly_without_holder_binding(
        #[case] case: CredTestCase,
    ) {
        let case = CredTestCase::ldp_vc();
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let (entry, _) = case.generate_vc(&kms, None).await;

        let holder = holder_service(kms, vault.clone());

        let presentation = holder
            .create_presentation(None, &case.create_presentation_input(), &entry)
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

        let (entry, _) = case.generate_vc(&kms, None).await;

        let holder = holder_service(kms, vault.clone());

        let nonce = random_nonce().await;

        let res = holder
            .create_presentation(
                Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: VERIFIER_ID.to_string(),
                }),
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
                Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: VERIFIER_ID.to_string(),
                }),
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

        let (entry, did_url) = case.generate_vc(&kms, None).await;
        vault
            .store_entries(vec![(&entry, did_url.as_str())])
            .await
            .unwrap();

        let holder = holder_service(kms, vault);

        let nonce = random_nonce().await;

        let presentation = holder
            .create_presentation_auto(
                Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &case.create_presentation_input(),
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
    async fn holder_create_presentation_auto_fails_when_vault_fails(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let mut vault = MockVault::new();
        vault.expect_find_credentials().return_once(|_, _| {
            FormatNotSupportedSnafu {
                format: "test".to_string(),
            }
            .fail()
        });

        let (entry, _) = case.generate_vc(&kms, None).await;

        let holder = holder_service(kms, vault);

        let nonce = random_nonce().await;

        let res = holder
            .create_presentation_auto(
                Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &case.create_presentation_input(),
            )
            .await;

        assert!(matches!(res.err(), Some(Error::Vault { .. })));
    }

    fn holder_service(kms: LocalKms, vault: impl Vault) -> impl Holder {
        HolderService::new(
            kms,
            vault,
            HolderMetadata {
                client_id: "wallet-dev".to_string(),
                pop: ProofOfPossessionMetadata {
                    lifetime: Duration::minutes(5),
                    not_before: None,
                },
            },
            UniversalResolver::default(),
            Arc::new(ReqwestClientBuilder::new().insecure().build().unwrap()),
        )
    }

    async fn issue_status_list_with_revoked_indexes(
        status_issuer: &impl StatusIssuer,
        revoked: Vec<usize>,
    ) -> String {
        let mut statuses = VCStatuses::new();

        for idx in revoked {
            statuses.set(idx, VCStatus::Invalid);
        }

        let status_list = status_issuer
            .issue_status_list("test", VCStatusesData::StatusListToken(statuses))
            .await
            .unwrap();

        let crate::vc::StatusList::StatusListTokenJwt(status_list) = status_list;

        status_list
    }

    async fn build_status_issuer(status_list_url: Url) -> impl StatusIssuer {
        // Initialization
        println!("Status issuer creating...");

        let kms = LocalKms::new();
        let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

        let metadata = StatusIssuerMetadata {
            issuer_id: "123456".to_string(),
            supported_status_lists: vec![StatusListDefinition {
                id: "test".to_string(),
                format: StatusListFormat::StatusListTokenJwt(
                    vc::status_formats::status_list_token_jwt::SLMetadata {
                        statuses_nr: 32,
                        status_list_url,
                        status_size: StatusSize::try_from(1u8).unwrap(),
                    },
                ),
                key_metadata,
            }],
        };

        StatusIssuerService::new(kms, metadata)
    }

    async fn create_did_keymetadata_keyhandle(kms: &LocalKms) -> (DID, KeyMetadata, KeyHandle) {
        let (kid, kh) = kms
            .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
            .await
            .unwrap();

        let did = DIDKey::generate(kh.clone()).unwrap();

        let vm = UniversalResolver::default()
            .resolve_into_any_verification_method(DIDBuf::from_str(&did).unwrap().as_did())
            .await
            .unwrap()
            .unwrap()
            .id;

        (
            did,
            KeyMetadata {
                kid,
                did_url: vm.to_string(),
            },
            kh,
        )
    }
}
