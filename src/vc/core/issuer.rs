use crate::did::DIDURL;
use crate::kms;
use crate::vc::core::{
    AlgNotSupportedSnafu, CredDefNotFoundSnafu, CredentialOfferContent, FormatNotSupportedSnafu,
    InconsistentProtocolDataSnafu, KMSSnafu, MetadataSnafu, ProofFormatNotSupportedSnafu,
    ProofSnafu, Result, VCSnafu,
};
use crate::vc::core::{
    CredentialDefinition, CredentialDefinitionData, CredentialOffer, CredentialOfferData,
    CredentialRequest, Issuer, IssuerMetadata,
};
use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata};
use crate::vc::formats::API;
use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use crate::vc::pop::jwt_pop::JwtProofOfPossession;
use crate::vc::pop::ProofOfPossession;
use crate::vc::{pop, Claims, Credential, CredentialMetadata, VCFormat};
use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;
use snafu::{ensure, ResultExt};
use std::marker::PhantomData;
use std::str::FromStr;
use tracing::{debug, instrument, trace, Level};

pub struct IssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    kms: KMS,
    metadata: IssuerMetadata,
    _marker: PhantomData<KH>,
}

#[async_trait]
impl<KH, KMS> Issuer for IssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(
        level = Level::TRACE,
        skip(self, protocol_data),
        err(),
        ret(level = Level::TRACE),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    async fn issue_credential(
        &self,
        credential_request: &CredentialRequest,
        claims: &Claims,
        nonce: &str,
    ) -> Result<(Credential, CredentialMetadata)> {
        trace!(?credential_request, ?claims, %nonce);

        let cred_def = self.resolve_cred_def_by_request(credential_request)?;

        let (pop_fmt, proof) = Self::resolve_proof(cred_def, credential_request)?;

        let (hld_did, hld_key) = match pop_fmt {
            pop::Format::Jwt => JwtProofOfPossession::verify(
                proof,
                Nonce::new(nonce.into()),
                pop::VerifyOptions {
                    cred_iss_id: self.metadata.issuer_id.clone(),
                    client_id: None,
                },
            )
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

        let vc = match vc_fmt {
            VCFormat::SdJwtVc => {
                let claims = SdJwtAPI::resolve_claims(claims);
                trace!(claims_to_issue = ?claims);
                let alg = &iss_key.alg();
                debug!(signing_alg = ?alg);

                let metadata = self.sd_jwt_vc_metadata(cred_def.protocol_data.clone())?;
                let cred =
                    SdJwtAPI::create_vc(claims, (&iss_did, iss_key), (&hld_did, hld_key), metadata)
                        .await
                        .context(VCSnafu)?;

                Credential::SdJwt(cred)
            }
            _ => {
                return FormatNotSupportedSnafu {
                    format: vc_fmt.to_string(),
                }
                .fail()
            }
        };

        let meta = DefaultMetadataProcessor::resolve_metadata(&vc).context(MetadataSnafu)?;

        Ok((vc, meta))
    }
}

impl<KH, KMS> IssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(
        level = Level::TRACE,
        skip(kms)
    )]
    pub fn new(kms: KMS, metadata: IssuerMetadata) -> Self {
        Self {
            kms,
            metadata,
            _marker: Default::default(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    fn sd_jwt_vc_metadata(
        &self,
        protocol_data: Option<CredentialDefinitionData>,
    ) -> Result<VCMetadata> {
        trace!(?protocol_data);

        let vc_metadata = match protocol_data {
            Some(CredentialDefinitionData::SdJwt {
                vct,
                disclosures,
                lifetime,
            }) => VCMetadata {
                vct: vct.to_owned(),
                lifetime: lifetime.unwrap_or(time::Duration::days(365)),
                disclosures: disclosures.to_owned(),
            },
            _ => InconsistentProtocolDataSnafu {
                format: VCFormat::SdJwtVc.to_string(),
            }
            .fail()?,
        };

        Ok(vc_metadata)
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
    fn find_cred_def(&self, id: &str) -> Result<&CredentialDefinition> {
        let cred_defs = &self.metadata.cred_defs;
        let cred_def = cred_defs
            .iter()
            .find(|i| i.cred_def_id == id)
            .ok_or(CredDefNotFoundSnafu { id }.build())?;

        Ok(cred_def)
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
    async fn resolve_key_metadata(&self, cred_def: &CredentialDefinition) -> Result<(DIDURL, KH)> {
        trace!(credential_definition_id = ?cred_def);

        let key_meta = &cred_def.key_metadata;

        let did_url = DIDURL::from_str(&key_meta.did_url).unwrap();

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
}
