// ---------- COMMON TRAITS ----------------
pub trait Vault{}
pub trait Signer{}
pub trait DIDResolver{}



//  --------- DATA MODEL -------------

pub struct IssuerMetadata{
    pub cred_defs: Vector<CredentialDefinition>
    pub protocol_data: Option<IssuerMetadataData> // Protocol specific
}
pub struct IssuerMetadataData{}

pub struct CredentialDefinition{
    pub cred_def_id: String,
    pub format: String,
    pub claims: HashMap<String, Display>
    pub cryptographic_binding_methods_supported: String,
    pub credential_signing_alg_values_supported: String,
    pub cryptographic_binding_methods_supported: String,
    pub display: Display
    pub protocol_data: Option<CredentialDefinitionData> // Protocol specific
}
pub struct CredentialDefinitionData{}

pub struct CredentialOffer{
    pub cred_offer_id: String,
    pub cred_def: CredentialDefinition,
    pub protocol_data: Option<CredentialOfferData> // Protocol specific
}
pub struct CredentialOfferData{}

pub struct CredentialRequest{
    pub cred_offer_id: String,
    pub proof: Option<Proof>,
    pub protocol_data: Option<CredentialRequestData> // Protocol specific
}
pub struct CredentialRequestData{}

pub struct CredentialClaims{}
pub struct Credential{}
pub struct CredentialMetadata{}

pub struct PresentationDefinition{}
pub struct Presentation{}
pub struct PresentationData{} // presentation_submission




//  --------- Issuer API -------------

pub struct IssuerService {
    signer: Signer
}

impl IssuerService {
    // Step 1.
    pub async fn offer_credential(
        cred_def_id: String,
    ) -> Result<CredentialOffer, Box<dyn Error>>

    // Step 3.
    pub async fn issue_credential(
        credential_request: CredentialRequest,
        claims: CredentialClaims,
        nonce: String, // same as in request_credential
    ) -> Result<(Credential, CredentialMetadata), Box<dyn Error>>
}



//  --------- Holder API -------------

pub struct HolderService {
    vault: Vault,
    signer: Signer
}

impl HolderService {

    // Step 2.
    pub async fn request_credential(
        credential_offer: CredentialOffer,
        nonce: String,
        key_id: String,
    ) -> Result<(CredentialRequest, String), Box<dyn Error>>

    // Step 4.
    pub async fn store_credential(
        credential: Credential,
        credential_metadata: CredentialMetadata,
    ) -> Result<Box<dyn Error>> 
    
    // Step 5.
    pub fn create_presentation(
        nonce: String,
        presentation_definition: PresentationDefinition,
    ) -> Result<(Presentation, PresentationData), Box<dyn Error>>
    
}



//  --------- Verifier API -------------

pub struct VerifierService {
    did_resolver: DIDResolver,
}

impl VerifierService {

    // Step 6.
    pub fn verify_presentation(
        presentation_definition: PresentationDefinition,
        nonce: String, // same as in create_presentation
        presentation: Presentation,
        presentation_data: PresentationData,
    ) -> Result<Boolean, Box<dyn Error>>

}