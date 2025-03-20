use crate::kms;
use crate::nonce::Nonce;
use crate::vc::claims::Claims;
use crate::vc::core::api::{ContextParsingSnafu, InvalidDIDUrlSnafu};
use crate::vc::core::{
    AlgNotSupportedSnafu, CredDefNotFoundSnafu, CredentialOfferContent,
    CredentialStatusProtocolNotSupportedSnafu, FormatNotSupportedSnafu,
    InconsistentProtocolDataSnafu, KMSSnafu, ProofFormatNotSupportedSnafu, ProofSnafu, Result,
    VCSnafu,
};
use crate::vc::core::{
    CredentialDefinition, CredentialDefinitionData, CredentialOffer, CredentialOfferData,
    CredentialRequest, Issuer, IssuerMetadata,
};

use crate::vc::core::api::CredentialStatusInfo;

use crate::vc::formats::json_ld_vc;
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::API;

use crate::vc::pop::jwt_pop::JwtProofOfPossession;
use crate::vc::pop::ProofOfPossession;
use crate::vc::{pop, Credential, VCFormat};
use async_trait::async_trait;
use iref::{IriRefBuf, UriBuf};
use snafu::{ensure, ResultExt};
use ssi::dids::DIDURLBuf;
use std::marker::PhantomData;
use std::str::FromStr;
use tracing::{debug, info, instrument, trace, Level};

pub struct IssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    kms: KMS,
    metadata: IssuerMetadata,
    _marker: PhantomData<KH>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<KH, KMS> Issuer for IssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn offer_credential(
        &self,
        cred_def_id: &str,
        protocol_data: Option<&CredentialOfferData>,
    ) -> Result<CredentialOffer> {
        let cred_def = self.find_cred_def(cred_def_id)?;

        let id = uuid::Uuid::new_v4().to_string();

        let credential_offer = CredentialOffer {
            cred_offer_id: Some(id),
            issuer_id: self.metadata.issuer_id.to_owned(),
            cred_def_id: cred_def.cred_def_id.to_owned(),
            content: CredentialOfferContent::CredDef(cred_def.to_owned()),
            protocol_data: protocol_data.map(|p| p.to_owned()),
        };

        Ok(credential_offer)
    }

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    async fn issue_credential(
        &self,
        credential_request: &CredentialRequest,
        claims: &Claims,
        nonce: &Nonce,
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<Credential> {
        trace!(?credential_request, ?claims, ?nonce);

        let cred_def = self.resolve_cred_def_by_request(credential_request)?;

        let (pop_fmt, proof) = Self::resolve_proof(cred_def, credential_request)?;

        let (hld_did, hld_key) = match pop_fmt {
            pop::Format::Jwt => {
                let verification_opts = self.resolve_pop_verification_options(credential_request);
                JwtProofOfPossession::verify(proof, nonce, verification_opts)
            }
            .await
            .context(ProofSnafu)?,
            _ => {
                return ProofFormatNotSupportedSnafu {
                    format: pop_fmt.to_string(),
                }
                .fail()
            }
        };
        debug!(resolved_holder_did = ?hld_did);

        let vc_fmt = &cred_def.format;

        let (iss_did, iss_key) = self.resolve_key_metadata(cred_def).await?;
        let alg = &iss_key.alg();
        debug!(signing_alg = ?alg);

        let vc = match vc_fmt {
            VCFormat::SdJwtVc => {
                trace!(claims_to_issue = ?claims);

                let metadata =
                    self.sd_jwt_vc_metadata(claims, cred_def.protocol_data.clone(), status_info)?;
                let cred = SdJwtAPI::create_vc(
                    claims.clone(),
                    (&iss_did, iss_key),
                    (&hld_did, hld_key),
                    metadata,
                )
                .await
                .context(VCSnafu)?;

                Credential::SdJwt(cred)
            }
            VCFormat::LdpVc => {
                trace!(claims_to_issue = ?claims);

                let metadata =
                    self.json_ld_vc_metadata(cred_def.protocol_data.clone(), status_info)?;
                let cred = JsonLdAPI::create_vc(
                    claims.clone(),
                    (&iss_did, iss_key),
                    (&hld_did, hld_key),
                    metadata,
                )
                .await
                .context(VCSnafu)?;

                Credential::LdpVc(cred)
            }
            _ => {
                return FormatNotSupportedSnafu {
                    format: vc_fmt.to_string(),
                }
                .fail()
            }
        };

        Ok(vc)
    }
}

impl<KH, KMS> IssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(kms))]
    pub fn new(kms: KMS, metadata: IssuerMetadata) -> Self {
        Self {
            kms,
            metadata,
            _marker: Default::default(),
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn sd_jwt_vc_metadata(
        &self,
        claims: &sd_jwt_vc::Claims,
        protocol_data: Option<CredentialDefinitionData>,
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<sd_jwt_vc::VCMetadata> {
        trace!(?protocol_data);

        let vc_metadata = match protocol_data {
            Some(CredentialDefinitionData::SdJwt {
                vct,
                disclosures,
                lifetime,
            }) => {
                // TODO: try to reduce nesting here
                let credential_status = match status_info {
                    None => None,
                    Some(CredentialStatusInfo::TokenStatusList { idx, uri }) => {
                        Some(crate::vc::formats::sd_jwt_vc::CredentialStatus {
                            status_list_credential_url: uri,
                            status_list_index: idx,
                        })
                    }
                    Some(_) => CredentialStatusProtocolNotSupportedSnafu {
                        format: VCFormat::SdJwtVc.to_string(),
                    }
                    .fail()?,
                };

                sd_jwt_vc::VCMetadata {
                    vct: vct.to_owned(),
                    lifetime,
                    disclosures: disclosures.to_owned(),
                    credential_status,
                }
            }
            _ => InconsistentProtocolDataSnafu {
                format: VCFormat::SdJwtVc.to_string(),
            }
            .fail()?,
        };

        Ok(vc_metadata)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn json_ld_vc_metadata(
        &self,
        protocol_data: Option<CredentialDefinitionData>,
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<json_ld_vc::VCMetadata> {
        trace!(?protocol_data);

        match status_info {
            None => {}
            _ => CredentialStatusProtocolNotSupportedSnafu {
                format: VCFormat::LdpVc.to_string(),
            }
            .fail()?,
        }

        let metadata = match protocol_data {
            Some(CredentialDefinitionData::Ldp {
                contexts: ctx_strs,
                vc_types,
                credential_id,
                lifetime,
            }) => {
                let mut contexts = vec![];
                for context in ctx_strs {
                    let c = IriRefBuf::new(context.to_owned()).context(ContextParsingSnafu)?;
                    contexts.push(c);
                }

                let mut metadata =
                    json_ld_vc::VCMetadata::new(contexts, vc_types, lifetime).context(VCSnafu)?;
                if let Some(credential_id) = credential_id {
                    let cred_id = UriBuf::from_str(&credential_id).map_err(|e| {
                        InconsistentProtocolDataSnafu {
                            format: format!(
                                "ldp-vc credential ID should be URI: id = {credential_id}"
                            ),
                        }
                        .build()
                    })?;
                    metadata.set_credential_id(cred_id);
                }

                metadata
            }
            _ => InconsistentProtocolDataSnafu {
                format: VCFormat::LdpVc.to_string(),
            }
            .fail()?,
        };

        Ok(metadata)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_cred_def_by_request(
        &self,
        credential_request: &CredentialRequest,
    ) -> Result<&CredentialDefinition> {
        trace!(?credential_request);
        // TODO: support flow for CredentialOffer handling (if present)
        let id = &credential_request.cred_def_id;
        let cred_def = &self.find_cred_def(id)?;

        Ok(cred_def)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn find_cred_def(&self, id: &str) -> Result<&CredentialDefinition> {
        let cred_defs = &self.metadata.cred_defs;
        let cred_def = cred_defs
            .iter()
            .find(|i| i.cred_def_id == id)
            .ok_or(CredDefNotFoundSnafu { id }.build())?;

        Ok(cred_def)
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    fn resolve_proof(
        cred_def: &CredentialDefinition,
        credential_request: &CredentialRequest,
    ) -> Result<(pop::Format, String)> {
        trace!(credential_definition_id = ?cred_def, ?credential_request);

        let proof = &credential_request.proof;
        let fmt = &proof.format;
        let fmt = pop::Format::from_str(fmt).context(ProofSnafu)?;

        // Check supported proofs only if they were set explicitly
        if let Some(proofs) = &cred_def.supported_proofs {
            let algs = proofs.get(&fmt).ok_or(
                ProofFormatNotSupportedSnafu {
                    format: fmt.to_string(),
                }
                .build(),
            )?;

            let alg = match fmt {
                pop::Format::Jwt => JwtProofOfPossession::alg(&proof.proof).context(ProofSnafu)?,
                _ => ProofFormatNotSupportedSnafu {
                    format: fmt.to_string(),
                }
                .fail()?,
            };

            ensure!(
                algs.contains(&alg),
                ProofFormatNotSupportedSnafu {
                    format: fmt.to_string()
                }
            );
        }

        Ok((fmt, proof.proof.to_owned()))
    }

    #[instrument(level = Level::TRACE, skip(self), err())]
    async fn resolve_key_metadata(
        &self,
        cred_def: &CredentialDefinition,
    ) -> Result<(DIDURLBuf, KH)> {
        trace!(credential_definition_id = ?cred_def);

        let key_meta = &cred_def.key_metadata;

        let did_url = DIDURLBuf::from_str(&key_meta.did_url).map_err(|e| {
            InvalidDIDUrlSnafu {
                input: format!("{}: {}", key_meta.did_url, e),
            }
            .build()
        })?;

        info!("access to the key {}", key_meta.kid);
        let kh = self.kms.get(&key_meta.kid).await.context(KMSSnafu)?;

        // Check signing algs only if they were set explicitly
        if let Some(algs) = &cred_def.supported_signing_algs {
            let alg = kh.alg();

            ensure!(
                algs.contains(&alg),
                AlgNotSupportedSnafu {
                    alg: alg.to_string()
                },
            );
        }

        debug!(resolved_did_url = ?did_url);

        Ok((did_url, kh))
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    fn resolve_pop_verification_options(
        &self,
        credential_request: &CredentialRequest,
    ) -> pop::VerifyOptions {
        let clock_tolerance = credential_request
            .protocol_data
            .as_ref()
            .map(|p| p.proof_tolerance)
            .unwrap_or_default();

        pop::VerifyOptions {
            audience: self.metadata.issuer_id.clone(),
            clock_tolerance,
            issuer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::inmem::kms::LocalKms;
    use crate::kms::KeyType;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::core::tests::fixtures::{
        sample_cred_def, sample_issuer_metadata, CRED_DEF_ID, ISSUER_ID,
    };
    use crate::vc::core::tests::utils::{random_nonce, CredTestCase};
    use crate::vc::core::{
        CredentialOfferContent, CredentialRequest, Error, Issuer, IssuerService, KeyMetadata,
    };
    use rstest::rstest;
    use time::OffsetDateTime;

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn issuer_offers_credential_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let issuer = issuer_service(kms, key_metadata.clone(), &case);

        let offer = issuer.offer_credential(CRED_DEF_ID, None).unwrap();

        assert_eq!(offer.issuer_id, ISSUER_ID);
        assert_eq!(
            offer.content,
            CredentialOfferContent::CredDef(sample_cred_def(&case, key_metadata))
        )
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn issuer_issues_credential_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = random_nonce().await;
        let proof = case.generate_pop(&kms, &nonce, KeyType::P256).await;

        let issuer = issuer_service(kms, key_metadata, &case);

        let request = case.create_cred_request(proof);

        let credential = issuer
            .issue_credential(&request, &case.claims, &nonce, None)
            .await
            .unwrap();

        case.assert_credential(&credential).await;
    }

    #[tokio::test]
    async fn issuer_issues_credential_correctly_when_pop_verification_tolerance_is_given() {
        let case = CredTestCase::sd_jwt();
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = random_nonce().await;
        let proof = case
            .generate_pop_with_lifetime(
                &kms,
                &nonce,
                KeyType::P256,
                OffsetDateTime::now_utc().checked_add(time::Duration::seconds(3)),
                OffsetDateTime::now_utc().checked_add(time::Duration::minutes(5)),
            )
            .await;

        let issuer = issuer_service(kms, key_metadata, &case);

        let request =
            case.create_cred_request_with_pop_tolerance(proof, time::Duration::seconds(3));

        let credential = issuer
            .issue_credential(&request, &case.claims, &nonce, None)
            .await
            .unwrap();

        case.assert_credential(&credential).await;
    }

    #[should_panic(expected = "proof of possession is not yet valid")]
    #[tokio::test]
    async fn issuer_issues_credential_fails_when_pop_verification_tolerance_is_not_set() {
        let case = CredTestCase::sd_jwt();
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = random_nonce().await;
        let proof = case
            .generate_pop_with_lifetime(
                &kms,
                &nonce,
                KeyType::P256,
                OffsetDateTime::now_utc().checked_add(time::Duration::seconds(3)),
                OffsetDateTime::now_utc().checked_add(time::Duration::minutes(5)),
            )
            .await;

        let issuer = issuer_service(kms, key_metadata, &case);
        let request = case.create_cred_request(proof);

        let credential = issuer
            .issue_credential(&request, &case.claims, &nonce, None)
            .await
            .unwrap();
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn issuer_issues_credential_fails_on_unknown_cred_def(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = random_nonce().await;
        let proof = case.generate_pop(&kms, &nonce, KeyType::P256).await;

        let issuer = issuer_service(kms, key_metadata, &case);

        let request = case.create_cred_request(proof);
        let request = CredentialRequest {
            cred_def_id: "unknown".to_string(),
            ..request
        };

        let res = issuer
            .issue_credential(&request, &case.claims, &nonce, None)
            .await;

        assert!(matches!(res.err(), Some(Error::CredDefNotFound { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn issuer_issues_credential_fails_on_unsupported_proof(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = random_nonce().await;
        let proof = case.generate_pop(&kms, &nonce, KeyType::Ed25519).await;

        let issuer = issuer_service(kms, key_metadata, &case);

        let request = case.create_cred_request(proof);

        let res = issuer
            .issue_credential(&request, &case.claims, &nonce, None)
            .await;

        assert!(matches!(
            res.err(),
            Some(Error::ProofFormatNotSupported { .. })
        ));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn issuer_issues_credential_fails_on_invalid_proof(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = random_nonce().await;
        let proof = "invalid_proof".to_string();

        let issuer = issuer_service(kms, key_metadata, &case);

        let request = case.create_cred_request(proof);

        let res = issuer
            .issue_credential(&request, &case.claims, &nonce, None)
            .await;

        assert!(matches!(res.err(), Some(Error::Proof { .. })));
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn issuer_issues_credential_fails_on_invalid_key(#[case] case: CredTestCase) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let nonce = random_nonce().await;
        let proof = case.generate_pop(&kms, &nonce, KeyType::P256).await;

        let key_metadata = KeyMetadata {
            did_url: key_metadata.did_url,
            kid: "invalid-kid".to_string(),
        };

        let issuer = issuer_service(kms, key_metadata, &case);

        let request = case.create_cred_request(proof);

        let res = issuer
            .issue_credential(&request, &case.claims, &nonce, None)
            .await;

        assert!(matches!(res.err(), Some(Error::KMS { .. })));
    }

    fn issuer_service(
        kms: LocalKms,
        key_metadata: KeyMetadata,
        case: &CredTestCase,
    ) -> impl Issuer {
        IssuerService::new(kms, sample_issuer_metadata(key_metadata, case))
    }
}
