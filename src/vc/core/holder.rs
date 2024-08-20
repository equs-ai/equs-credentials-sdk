use std::marker::PhantomData;
use std::str::FromStr;

use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;

use crate::{kms, vault, vc};
use crate::did::DIDURL;
use crate::vault::FindCriteria;
use crate::vc::{Credential, CredentialMetadata, pop, Presentation};
use crate::vc::core::{CredentialOffer, CredentialRequest, CredentialRequestData, Error, Holder, HolderMetadata, PresentationInput, Proof};
use crate::vc::core::Result;
use crate::vc::formats::API;
use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VPMetadata};
use crate::vc::pop::jwt_pop::JwtProofOfPossession;
use crate::vc::pop::ProofOfPossession;

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
    async fn request_credential(
        &self,
        credential_offer: &CredentialOffer,
        nonce: &str,
    ) -> Result<CredentialRequest> {
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
                ).await?
            }
            _ => Err(pop::Error::FormatNotSupported)?,
        };

        let fmt: &str = pop_fmt.into();
        let credential_request = CredentialRequest {
            cred_def_id: cred_def_id.clone(),
            cred_offer_id: credential_offer.cred_offer_id.clone(),
            proof: Proof { format: fmt.to_owned(), proof: proof.to_string() },
            protocol_data: Some(CredentialRequestData { ..Default::default() }),
        };

        Ok(credential_request)
    }

    async fn store_credential(
        &mut self,
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<String> {
        let id = self.vault.store_credential(credential.to_owned(), metadata).await?;
        Ok(id)
    }

    async fn create_presentation_auto(
        &self,
        nonce: &str,
        verifier_id: &str,
        presentation_input: &PresentationInput,
    ) -> Result<Presentation> {
        let credentials = self.find_vcs_for_presentation(presentation_input).await?;
        let selected = credentials.get(0).ok_or(Error::NoCredential)?;

        let presentation = self.create_presentation(nonce, verifier_id, presentation_input, selected).await?;

        Ok(presentation)
    }

    async fn find_vcs_for_presentation(
        &self,
        presentation_input: &PresentationInput,
    ) -> Result<Vec<Credential>> {
        let criteria = self.resolve_find_criteria(presentation_input)?;
        let credentials = self.vault.find_credentials(criteria).await?;

        Ok(credentials.into_iter().collect())
    }

    async fn create_presentation(
        &self,
        nonce: &str,
        verifier_id: &str,
        presentation_input: &PresentationInput,
        credential: &Credential,
    ) -> Result<Presentation> {
        let (did_url, key) = self.resolve_key_metadata().await?;

        let presentation = match credential {
            Credential::SdJwt(vc) => {
                let vp = SdJwtAPI::create_vp(vc,
                                             (&did_url, key),
                                             Nonce::new(nonce.into()), verifier_id,
                                             VPMetadata { disclosures: presentation_input.claims.clone() },
                ).await?;

                Presentation::SdJwtVp(vp)
            }
            _ => Err(Error::FormatNotSupported)?
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
    pub fn new(kms: KMS, vault: V, metadata: HolderMetadata) -> Self {
        Self { kms, vault, metadata, _marker: Default::default() }
    }

    fn resolve_cred_offer(&self, credential_offer: &CredentialOffer) -> Result<(String, Vec<String>)> {
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
            _ => return Err(Error::CredDefNotFound),
        };

        Ok((cred_def_id.to_owned(), supported_proofs.to_owned()))
    }
    fn resolve_proof_format(&self, supported_proofs: Vec<String>) -> Result<pop::Format> {
        // TODO: add logic on supported proof formats of Holder
        let pop_fmt = supported_proofs.iter().next().ok_or(Error::ProofFormatNotFound)?;
        let pop_fmt = pop::Format::from_str(pop_fmt)?;
        Ok(pop_fmt)
    }

    async fn resolve_key_metadata(&self) -> Result<(DIDURL, KH)> {
        let key_meta = &self.metadata.key_metadata;
        let did_url = DIDURL::from_str(&key_meta.did_url).unwrap();
        let kh = self.kms.get(&key_meta.kid).await.unwrap();

        Ok((did_url, kh))
    }

    fn resolve_find_criteria(&self, input: &PresentationInput) -> Result<FindCriteria> {
        // TODO: more generic solution to support different criterias
        let vc_fmt = &input.format;
        let vc_fmt = vc::VCFormat::from_str(vc_fmt)?;

        let criteria = FindCriteria::ByIdAndFormat(input.id.clone(), vc_fmt.clone());

        Ok(criteria)
    }
}
