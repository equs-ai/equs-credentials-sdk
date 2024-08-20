use std::marker::PhantomData;
use std::str::FromStr;

use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;

use crate::{kms, vc};
use crate::did::DIDURL;
use crate::vc::{Claims, Credential, CredentialMetadata, pop};
use crate::vc::core::{CredentialDefinition, CredentialDefinitionData, CredentialOffer, CredentialOfferData, CredentialRequest, Error, Issuer, IssuerMetadata};
use crate::vc::core::Result;
use crate::vc::formats::API;
use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata};
use crate::vc::pop::jwt_pop::JwtProofOfPossession;
use crate::vc::pop::ProofOfPossession;

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
    fn offer_credential(
        &self,
        cred_def_id: &str,
        protocol_data: Option<&CredentialOfferData>,
    ) -> Result<CredentialOffer> {
        let cred_def = self.find_cred_def(cred_def_id)?;

        let id = uuid::Uuid::new_v4().to_string();

        let credential_offer = CredentialOffer {
            issuer_id: self.metadata.issuer_id.to_owned(),
            cred_offer_id: Some(id),
            supported_proofs: None,
            cred_def_id: None,
            cred_def: Some(cred_def.to_owned()),
            protocol_data: protocol_data.map(|p| p.to_owned()),
        };

        Ok(credential_offer)
    }

    async fn issue_credential(
        &self,
        credential_request: &CredentialRequest,
        claims: &Claims,
        nonce: &str,
    ) -> Result<(Credential, CredentialMetadata)> {
        let cred_def = self.resolve_cred_def_by_request(credential_request)?;

        let (pop_fmt, proof) = Self::resolve_proof(cred_def, credential_request)?;

        let (hld_did, hld_key) = match pop_fmt {
            pop::Format::Jwt => {
                JwtProofOfPossession::verify(
                    proof,
                    Nonce::new(nonce.into()),
                    pop::VerifyOptions {
                        cred_iss_id: self.metadata.issuer_id.clone(),
                        client_id: None,
                    },
                ).await?
            }
            _ => Err(pop::Error::FormatNotSupported)?,
        };

        let vc_fmt = &cred_def.format;
        let vc_fmt = vc::VCFormat::from_str(vc_fmt)?;

        let (iss_did, iss_key) = self.resolve_key_metadata(cred_def).await?;

        let (vc, meta) = match vc_fmt {
            vc::VCFormat::SdJwtVc => {
                let claims = SdJwtAPI::resolve_claims(claims);
                let alg = &iss_key.alg();

                let metadata = self.sd_jwt_vc_metadata(&cred_def.protocol_data)?;
                let cred = SdJwtAPI::create_vc(
                    claims,
                    (&iss_did, iss_key),
                    (&hld_did, hld_key),
                    metadata,
                ).await?;

                (Credential::SdJwt(cred), CredentialMetadata { id: cred_def.cred_def_id.to_owned(), format: vc_fmt, alg: alg.to_owned() })
            }
            _ => Err(Error::FormatNotSupported)?
        };

        Ok((vc, meta))
    }
}

impl<KH, KMS> IssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    pub fn new(kms: KMS, metadata: IssuerMetadata) -> Self {
        Self { kms, metadata, _marker: Default::default() }
    }

    fn sd_jwt_vc_metadata(&self, protocol_data: &Option<CredentialDefinitionData>) -> Result<VCMetadata> {
        let data = &protocol_data.clone().unwrap_or(Default::default());

        Ok(VCMetadata {
            lifetime: data.lifetime.unwrap_or(time::Duration::days(365)),
            disclosures: data.disclosures.to_owned(),
        })
    }

    fn resolve_cred_def_by_request(&self, credential_request: &CredentialRequest) -> Result<&CredentialDefinition> {
        // TODO: support flow for CredentialOffer handling (if present)
        let id = &credential_request.cred_def_id;
        let cred_def = &self.find_cred_def(id)?;

        Ok(cred_def)
    }

    fn find_cred_def(&self, id: &str) -> Result<&CredentialDefinition> {
        let cred_defs = &self.metadata.cred_defs;
        let cred_def = cred_defs.iter().find(|i| i.cred_def_id == id).ok_or(Error::CredDefNotFound)?;

        Ok(cred_def)
    }

    fn resolve_proof<P: pop::Proof>(cred_def: &CredentialDefinition,
                                    credential_request: &CredentialRequest,
    ) -> Result<(pop::Format, P)>
    {
        let proof = &credential_request.proof;
        let fmt = &proof.format;
        let fmt = pop::Format::from_str(fmt)?;

        // TODO: add more validation for proof (against format, supported alg's, etc)

        let proof = P::parse(&proof.proof)?;
        Ok((fmt, proof))
    }

    async fn resolve_key_metadata(&self, cred_def: &CredentialDefinition) -> Result<(DIDURL, KH)> {
        let key_meta = match &cred_def.key_metadata {
            Some(m) => m,
            None => &self.metadata.key_metadata,
        };

        let did_url = DIDURL::from_str(&key_meta.did_url).unwrap();
        let kh = self.kms.get(&key_meta.kid).await.unwrap();

        Ok((did_url, kh))
    }
}