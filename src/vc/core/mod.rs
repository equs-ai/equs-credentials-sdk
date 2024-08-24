use std::collections::HashMap;

use async_trait::async_trait;

#[allow(unused_imports)]
pub use holder::HolderService;
#[allow(unused_imports)]
pub use issuer::IssuerService;
#[allow(unused_imports)]
pub use verifier::VerifierService;

use crate::vc::{metadata, Claims, Credential, CredentialMetadata, Presentation};
use crate::{vault, vc};

pub mod verifier;
pub mod holder;
pub mod issuer;

//  --------- DATA MODEL -------------

#[derive(Debug, PartialEq, Clone)]
pub struct IssuerMetadata {
    pub issuer_id: String,
    pub cred_defs: Vec<CredentialDefinition>,
    pub protocol_data: Option<IssuerMetadataData>, // Protocol specific
    pub key_metadata: KeyMetadata,
}

#[derive(Debug, PartialEq, Clone)]
pub struct IssuerMetadataData {}

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
    pub disclosures: Vec<String>,
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
pub struct Proof {
    pub format: String,
    pub proof: String,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CredentialRequest {
    pub cred_def_id: String,
    pub cred_offer_id: Option<String>,
    pub proof: Proof,
    pub protocol_data: Option<CredentialRequestData>, // Protocol specific
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CredentialRequestData {}

#[derive(Debug, PartialEq, Clone)]
pub struct PresentationInput {
    pub id: String,
    pub format: String,
    pub type_: Option<String>,
    pub claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Display;

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
    #[error("format not supported")]
    FormatNotSupported,
    #[error("find criteria compilation failed: {0}")]
    FindCriteria(String),
    #[error("missing claim: {0}")]
    MissingClaim(String),
    #[error(transparent)]
    VC(#[from] vc::formats::Error),
    #[error(transparent)]
    Metadata(#[from] metadata::Error),
    #[error(transparent)]
    Proof(#[from] vc::pop::Error),
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
        claims: &Claims,
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
        &self,
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
    ) -> Result<Claims>;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oid4vci::openidconnect::Nonce;
    use serde_json::json;
    use ssi::did::DIDURL;

    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::Kms;
    use crate::vc::core::holder::HolderService;
    use crate::vc::core::issuer::IssuerService;
    use crate::vc::core::verifier::VerifierService;
    use crate::vc::core::{CredentialDefinition, CredentialDefinitionData, Holder, HolderMetadata, Issuer, IssuerMetadata, KeyMetadata, PresentationInput, Verifier};
    use crate::{kms, vc};

    #[tokio::test]
    async fn e2e() {
        // Initialization
        let issuer = issuer().await;
        let holder = holder().await;
        let verifier = verifier("ver-id");

        println!("Issue credential...");

        let offer = issuer.offer_credential(
            "SD_JWT_cred",
            None,
        );
        assert!(offer.is_ok());
        let offer = offer.unwrap();

        let nonce = Nonce::new_random();
        let request = holder.request_credential(&offer, nonce.secret()).await;
        assert!(request.is_ok());
        let request = request.unwrap();

        let claims = json!( {
                "vct": "https://credentials.example.com/identity_credential",
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
            type_: Some("https://credentials.example.com/identity_credential".into()),
            format: "vc+sd-jwt".into(),
            claims: json!({
               "given_name": true,
               "family_name": true,
            }).as_object().unwrap().to_owned(),
        };

        let nonce = Nonce::new_random();

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

        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

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
                        disclosures: vec!["$.given_name".to_owned(), "$.family_name".to_owned()],
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

        let kms = LocalKms::new();
        let didkey = DIDKey::new();
        let vault = InMemVault::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

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