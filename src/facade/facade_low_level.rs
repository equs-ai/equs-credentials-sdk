use std::collections::HashMap;
use std::str::FromStr;

use async_trait::async_trait;

use crate::core_::{crypto, did, kms, pop, vault, vc};
use crate::core_::crypto::Signer;
use crate::core_::pop::ProofOfPossession as PopAPI;
use crate::core_::vault::FindCriteria;
use crate::core_::vc::{API, VerifyOptions};
use crate::exchange;
use crate::impls::pop::jwt_pop::JwtProofOfPossession;
use crate::impls::vc::sd_jwt_vc::{SdJwtAPI, VCMetadata, VPMetadata};

//  --------- DATA MODEL -------------

#[derive(Debug, PartialEq, Clone)]
pub struct IssuerMetadata {
    pub issuer_id: String,
    pub cred_defs: Vec<CredentialDefinition>,
    pub protocol_data: Option<IssuerMetadataData>, // Protocol specific
    pub key_metadata: KeyMetadata,
}

#[derive(Debug, PartialEq, Clone)]
pub enum IssuerMetadataData {
    Oidc4Vc(exchange::oid4vc::oid4vci::IssuerMetadata)
}

#[derive(Debug, Clone, PartialEq)]
pub struct CredentialDefinition {
    pub cred_def_id: String,
    pub format: String,
    pub claims: HashMap<String, Display>,
    pub supported_proofs: Vec<String>,
    pub display: Option<Display>,
    pub protocol_data: Option<CredentialDefinitionData>, // Protocol specific
    pub key_metadata: Option<KeyMetadata>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct KeyMetadata {
    pub did_url: String,
    pub kid: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HolderMetadata {
    pub client_id: String,
    pub key_metadata: KeyMetadata,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CredentialDefinitionData {
    pub disclosures: Vec<&'static str>,
    pub lifetime: Option<time::Duration>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct CredentialOffer {
    pub issuer_id: String,
    pub cred_offer_id: Option<String>,
    pub cred_def_id: Option<String>,
    pub supported_proofs: Option<Vec<String>>,
    pub cred_def: Option<CredentialDefinition>,
    pub protocol_data: Option<CredentialOfferData>, // Protocol specific
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CredentialOfferData {}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ProofOfPossession {
    pub format: String,
    pub proof: String,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CredentialRequest {
    pub cred_def_id: String,
    pub cred_offer_id: Option<String>,
    pub proof: ProofOfPossession,
    pub protocol_data: Option<CredentialRequestData>, // Protocol specific
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CredentialRequestData {}

#[derive(Debug, PartialEq, Clone)]
pub struct PresentationInput {
    pub id: String,
    pub format: String,
    pub claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Display;

pub type CredentialClaims = serde_json::Value;
pub type Credential = vc::Credential;
pub type CredentialMetadata = vc::CredentialMetadata;
pub type Presentation = vc::Presentation;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("cred def not found")]
    CredDefNotFound,
    #[error("proof format not found")]
    ProofFormatNotFound,
    #[error("no protocol data")]
    NoProtocolData,
    #[error("no credential found")]
    NoCredential,
    #[error("missing claim: {0}")]
    MissingClaim(String),
    #[error(transparent)]
    VC(#[from] vc::Error),
    #[error(transparent)]
    Proof(#[from] pop::Error),
    #[error(transparent)]
    Vault(#[from] vault::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

// API

#[async_trait]
pub trait Issuer: Send + Sync
{
    fn offer_credential(
        &self,
        cred_def_id: &str,
        protocol_data: Option<&CredentialOfferData>,
    ) -> Result<CredentialOffer>;

    async fn issue_credential(
        &self,
        credential_request: &CredentialRequest,
        claims: &CredentialClaims,
        nonce: &str,
    ) -> Result<(Credential, CredentialMetadata)>;
}

#[async_trait]
pub trait Holder: Send + Sync
{
    async fn request_credential(
        &self,
        credential_offer: &CredentialOffer,
        nonce: &str,
    ) -> Result<CredentialRequest>;

    async fn store_credential(
        &mut self,
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<String>;

    async fn create_presentation_auto(
        &self,
        nonce: &str,
        verifier_id: &str,
        presentation_input: &PresentationInput,
    ) -> Result<Presentation>;

    async fn find_vcs_for_presentation(
        &self,
        presentation_input: &PresentationInput,
    ) -> Result<Vec<Credential>>;

    async fn create_presentation(
        &self,
        nonce: &str,
        verifier_id: &str,
        presentation_input: &PresentationInput,
        credential: &Credential,
    ) -> Result<Presentation>;
}

#[async_trait]
pub trait Verifier: Send + Sync
{
    async fn verify_presentation(
        &self,
        nonce: &str, // same as in create_presentation
        presentation: &Presentation,
    ) -> Result<CredentialClaims>;
}

// Services

// Issuer

pub struct IssuerService<KH: kms::KeyHandle + 'static> {
    kms: Box<dyn kms::Kms<KH>>,
    metadata: IssuerMetadata,
}

#[async_trait]
impl<KH: kms::KeyHandle + 'static> Issuer for IssuerService<KH> {
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
        claims: &CredentialClaims,
        nonce: &str,
    ) -> Result<(Credential, CredentialMetadata)> {
        let cred_def = self.resolve_cred_def_by_request(credential_request)?;

        let (pop_fmt, proof) = Self::resolve_proof(cred_def, credential_request)?;

        let (hld_did, hld_key) = match pop_fmt {
            pop::Format::Jwt => {
                JwtProofOfPossession::verify(
                    proof,
                    vc::Nonce::new(nonce.into()),
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
            _ => Err(vc::Error::FormatNotSupported)?
        };

        Ok((vc, meta))
    }
}

impl<KH: kms::KeyHandle + 'static> IssuerService<KH> {
    pub fn new(kms: impl kms::Kms<KH> + 'static, metadata: IssuerMetadata) -> Self {
        Self { kms: Box::new(kms), metadata }
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

    fn resolve_proof<P>(cred_def: &CredentialDefinition,
                        credential_request: &CredentialRequest) -> Result<(pop::Format, P)>
    where
        P: pop::Proof,
    {
        let proof = &credential_request.proof;
        let fmt = &proof.format;
        let fmt = pop::Format::from_str(fmt)?;

        // TODO: add more validation for proof (against format, supported alg's, etc)

        let proof = P::parse(&proof.proof)?;
        Ok((fmt, proof))
    }

    async fn resolve_key_metadata(&self, cred_def: &CredentialDefinition) -> Result<(did::DIDURL, impl Signer)> {
        let key_meta = match &cred_def.key_metadata {
            Some(m) => m,
            None => &self.metadata.key_metadata,
        };

        let did_url = did::DIDURL::from_str(&key_meta.did_url).unwrap();
        let kh = self.kms.get(&key_meta.kid).await.unwrap();

        Ok((did_url, kh))
    }
}

// Holder

pub struct HolderService<KH: kms::KeyHandle + 'static> {
    kms: Box<dyn kms::Kms<KH>>,
    vault: Box<dyn vault::Vault>,
    metadata: HolderMetadata,
}

#[async_trait]
impl<KH: kms::KeyHandle + 'static> Holder for HolderService<KH> {
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
                    vc::Nonce::new(nonce.into()),
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
            proof: ProofOfPossession { format: fmt.to_owned(), proof: proof.to_string() },
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

        Ok(credentials.into_iter().cloned().collect())
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
                                             vc::Nonce::new(nonce.into()), verifier_id,
                                             VPMetadata { disclosures: presentation_input.claims.clone() },
                ).await?;

                Presentation::SdJwtVp(vp)
            }
            _ => Err(vc::Error::FormatNotSupported)?
        };

        Ok(presentation)
    }
}

impl<KH: kms::KeyHandle + 'static> HolderService<KH> {
    pub fn new(kms: impl kms::Kms<KH> + 'static, vault: impl vault::Vault + 'static, metadata: HolderMetadata) -> Self {
        Self { kms: Box::new(kms), vault: Box::new(vault), metadata }
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

    async fn resolve_key_metadata(&self) -> Result<(did::DIDURL, impl crypto::SigningKey)> {
        let key_meta = &self.metadata.key_metadata;
        let did_url = did::DIDURL::from_str(&key_meta.did_url).unwrap();
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


//  Verifier

pub struct VerifierService {
    verifier_id: String,
}

#[async_trait]
impl Verifier for VerifierService {
    // Step 6.
    async fn verify_presentation(
        &self,
        nonce: &str, // same as in create_presentation
        presentation: &Presentation,
    ) -> Result<CredentialClaims> {
        let cred_claims: CredentialClaims = match presentation {
            Presentation::SdJwtVp(vp) => {
                SdJwtAPI::verify_vp(
                    vp,
                    vc::Nonce::new(nonce.into()), &self.verifier_id,
                    VerifyOptions {},
                ).await?
            }
            _ => Err(vc::Error::FormatNotSupported)?
        };

        Ok(cred_claims)
    }
}

impl VerifierService {
    pub fn new(verifier_id: &str) -> Self {
        Self { verifier_id: verifier_id.to_owned() }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;
    use ssi::did::DIDURL;

    use crate::core_::{kms, vc};
    use crate::core_::crypto::Key;
    use crate::core_::kms::Kms;
    use crate::facade::facade_low_level::{CredentialDefinition, CredentialDefinitionData, Holder, HolderMetadata, HolderService, Issuer, IssuerMetadata, IssuerService, KeyMetadata, PresentationInput, Verifier, VerifierService};
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::vault::inmem::InMemVault;

    #[tokio::test]
    async fn e2e() {
        // Initialization
        let issuer = issuer().await;
        let mut holder = holder().await;
        let verifier = verifier("ver-id");

        println!("Issue credential...");

        let offer = issuer.offer_credential(
            "SD_JWT_cred",
            None,
        );
        assert!(offer.is_ok());
        let offer = offer.unwrap();

        let nonce = vc::Nonce::new_random();
        let request = holder.request_credential(&offer, nonce.secret()).await;
        assert!(request.is_ok());
        let request = request.unwrap();

        let claims = json!( {
                "vct": "SD_JWT_cred",
                "type": ["SD_JWT_cred"],
                "given_name": "John",
                "family_name": "Doe",
                "dob": "09/09/1989",
            });
        let cl = claims.as_object().unwrap().clone();
        println!("Claims: {:?}", cl);

        let vc_res = issuer.issue_credential(&request, &claims, nonce.secret()).await;
        assert!(vc_res.is_ok());

        let (vc, vc_meta) = vc_res.unwrap();
        println!("Credential {:?}", &vc);

        let store_res = holder.store_credential(&vc, &vc_meta).await;
        assert!(store_res.is_ok());

        println!("Present proof...");

        let presentation_input = PresentationInput {
            id: "SD_JWT_cred".into(),
            format: "vc+sd-jwt".into(),
            claims: json!({
               "given_name": true,
               "family_name": true,
            }).as_object().unwrap().to_owned(),
        };

        let nonce = vc::Nonce::new_random();

        let vp_res = holder.create_presentation_auto(
            nonce.secret(), "ver-id",
            &presentation_input,
        ).await;
        assert!(vp_res.is_ok());

        let vp = vp_res.unwrap();
        println!("Presentation {:?}", vp);

        let ver_res = verifier.verify_presentation(
            nonce.secret(),
            &vp,
        ).await;
        assert!(ver_res.is_ok());

        let res_claims = ver_res.unwrap();
        println!("Presentation claims {:?}", res_claims);

        assert!(res_claims.as_object().unwrap().contains_key("given_name"));
        assert!(res_claims.as_object().unwrap().contains_key("family_name"));
        // should return not only requested claims, but all in credential
        assert!(res_claims.as_object().unwrap().contains_key("dob"));
    }

    async fn issuer() -> impl Issuer {
        // Initialization
        println!("Issuer creating...");

        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(&kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        let metadata = IssuerMetadata {
            issuer_id: did_url.to_string(),
            cred_defs: vec![
                CredentialDefinition {
                    cred_def_id: "SD_JWT_cred".into(),
                    format: vc::VCFormat::SdJwtVc.to_string(),
                    claims: Default::default(),
                    supported_proofs: vec![
                        "jwt".into()
                    ],
                    display: None,
                    protocol_data: Some(CredentialDefinitionData {
                        disclosures: vec!["$.given_name", "$.family_name"],
                        lifetime: None,
                    }),
                    key_metadata: None,
                }
            ],
            protocol_data: None,
            key_metadata: KeyMetadata {
                did_url: did_url.to_string(),
                kid: kid.clone(),
            },
        };

        IssuerService::new(kms, metadata)
    }

    async fn holder() -> impl Holder {
        // Initialization
        println!("Holder creating...");

        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();
        let vault = InMemVault::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(&kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        HolderService::new(kms, vault, HolderMetadata {
            client_id: "client_id".into(),
            key_metadata: KeyMetadata {
                did_url: did_url.to_string(),
                kid: kid.clone(),
            },
        })
    }

    fn verifier(id: &str) -> impl Verifier {
        VerifierService::new(id)
    }
}