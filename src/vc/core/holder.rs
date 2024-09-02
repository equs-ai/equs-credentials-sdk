use std::marker::PhantomData;
use std::str::FromStr;
use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;
use snafu::ResultExt;
use tracing::{instrument, Level, debug, trace};

use crate::did::DIDURL;
use crate::vault::{FindCriteria};
use crate::vc::core::{CredDefRequiredSnafu, FormatNotSupportedSnafu, KMSSnafu, ProofFormatRequiredSnafu, ProofSnafu, RequestedCredentialNotFoundSnafu, Result, VaultSnafu, VCSnafu};
use crate::vc::core::{CredentialOffer, CredentialRequest, CredentialRequestData, Holder, HolderMetadata, PresentationInput, Proof};
use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VPMetadata};
use crate::vc::formats::{API};
use crate::vc::pop::jwt_pop::JwtProofOfPossession;
use crate::vc::pop::ProofOfPossession;
use crate::vc::{pop, Credential, CredentialMetadata, Presentation, HasVCFormat};
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

#[async_trait]
impl<KH, KMS, V> Holder for HolderService<KH, KMS, V>
where
    KMS: kms::Kms<KH>,
    KH: kms::KeyHandle,
    V: vault::Vault,
{
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    async fn request_credential(
        &self,
        credential_offer: &CredentialOffer,
        nonce: &str,
    ) -> Result<CredentialRequest> {
        trace!(?credential_offer, %nonce);

        let (cred_def_id, proofs) = self.resolve_cred_offer(&credential_offer)?;

        let pop_fmt = self.resolve_proof_format(proofs)?;
        let (did_url, key) = self.resolve_key_metadata().await?;
        let proof = match pop_fmt {
            pop::Format::Jwt => {
                JwtProofOfPossession::generate(
                    &did_url,
                    key,
                    Nonce::new(nonce.into()),
                    pop::GenerateOptions {
                        cred_iss_id: credential_offer.issuer_id.clone(),
                        client_id: None,
                        lifetime: None,
                    },
                ).await.context(ProofSnafu)?
            }
            _ => return FormatNotSupportedSnafu {
                format: <pop::Format as Into<&str>>::into(pop_fmt)
            }.fail(),
        };
        trace!(resolved_proof = %proof);

        let fmt: &str = pop_fmt.into();
        let credential_request = CredentialRequest {
            cred_def_id: cred_def_id.clone(),
            cred_offer_id: credential_offer.cred_offer_id.clone(),
            proof: Proof { format: fmt.to_owned(), proof: proof.to_string() },
            protocol_data: Some(CredentialRequestData { ..Default::default() }),
        };

        Ok(credential_request)
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    async fn store_credential(
        &self,
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<String> {
        trace!(?credential, credential_metadata = ?metadata);

        let id = self.vault
            .store_credential(credential.to_owned(), metadata)
            .await
            .context(VaultSnafu)?;

        Ok(id)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, nonce, presentation_input),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn create_presentation_auto(
        &self,
        nonce: &str,
        verifier_id: &str,
        presentation_input: &PresentationInput,
    ) -> Result<Presentation> {
        trace!(%nonce, ?presentation_input);

        let credentials = self.find_vcs_for_presentation(presentation_input).await?;
        let selected = credentials.get(0)
            .ok_or(RequestedCredentialNotFoundSnafu.build())?;

        let presentation = self.create_presentation(nonce, verifier_id, presentation_input, selected).await?;

        Ok(presentation)
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    async fn find_vcs_for_presentation(
        &self,
        presentation_input: &PresentationInput,
    ) -> Result<Vec<Credential>> {
        trace!(?presentation_input);

        let criteria = self.resolve_find_criteria(presentation_input)?;
        let credentials = self.vault
            .find_credentials(criteria)
            .await
            .context(VaultSnafu)?;

        Ok(credentials.into_iter().collect())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, nonce, presentation_input, credential),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn create_presentation(
        &self,
        nonce: &str,
        verifier_id: &str,
        presentation_input: &PresentationInput,
        credential: &Credential,
    ) -> Result<Presentation> {
        trace!(%nonce, ?presentation_input, ?credential);

        let (did_url, key) = self.resolve_key_metadata().await?;

        let presentation = match credential {
            Credential::SdJwt(vc) => {
                // For now, only top level supported
                let disclosures = Self::resolve_disclosures(presentation_input);
                let vp = SdJwtAPI::create_vp(
                    vc,
                    (&did_url, key),
                    Nonce::new(nonce.into()), verifier_id,
                    VPMetadata { disclosures },
                ).await.context(VCSnafu)?;

                Presentation::SdJwtVp(vp)
            }
            _ => return FormatNotSupportedSnafu { format: credential.format().to_string() }.fail()
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
    #[instrument(
        level = Level::TRACE,
        skip(kms, vault),
    )]
    pub fn new(kms: KMS, vault: V, metadata: HolderMetadata) -> Self {
        debug!(holder_metadata = ?metadata);

        Self { kms, vault, metadata, _marker: Default::default() }
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::DEBUG),
    )]
    fn resolve_cred_offer(&self, credential_offer: &CredentialOffer) -> Result<(String, Vec<String>)> {
        trace!(?credential_offer);
        // Offer contains either full cred_def or cred_def_id+supported_proofs
        let (cred_def_id, supported_proofs) = match credential_offer {
            CredentialOffer {
                cred_def: Some(cred_def),
                ..
            } => (&cred_def.cred_def_id, &cred_def.supported_proofs),
            CredentialOffer {
                cred_def_id: Some(cred_def_id),
                supported_proofs: Some(supported_proofs),
                ..
            } => (cred_def_id, supported_proofs),
            _ => return CredDefRequiredSnafu.fail(),
        };

        Ok((cred_def_id.to_owned(), supported_proofs.to_owned()))
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn resolve_proof_format(&self, supported_proofs: Vec<String>) -> Result<pop::Format> {
        // TODO: add logic on supported proof formats of Holder
        let pop_fmt = supported_proofs.iter().next().ok_or(ProofFormatRequiredSnafu.build())?;
        let pop_fmt = pop::Format::from_str(pop_fmt).context(ProofSnafu)?;
        Ok(pop_fmt)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
    )]
    async fn resolve_key_metadata(&self) -> Result<(DIDURL, KH)> {
        let key_meta = &self.metadata.key_metadata;
        let did_url = DIDURL::from_str(&key_meta.did_url).unwrap();
        let kh = self.kms.get(&key_meta.kid).await.context(KMSSnafu)?;

        debug!(resolved_did = ?did_url);

        Ok((did_url, kh))
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    fn resolve_find_criteria(&self, input: &PresentationInput) -> Result<FindCriteria> {
        trace!(presentation_input = ?input);

        // TODO: more generic solution to support different criterias
        let type_ = input.type_.to_owned();
        let criteria = FindCriteria::ByTypeAndFormat(type_, input.format.clone());

        Ok(criteria)
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(level = Level::TRACE),
    )]
    fn resolve_disclosures(input: &PresentationInput) -> serde_json::Map<String, serde_json::Value> {
        trace!(presentation_input = ?input);

        let claims = input.claims.clone();

        let stripped: Vec<_> = claims.keys().into_iter()
            .map(|k| (k.to_owned(), serde_json::Value::Bool(true)))
            .collect();

        serde_json::Map::from_iter(stripped.into_iter())
    }
}
