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
pub struct CredentialMapping{} // maps found credentials for the given presentation definition

// THE API is Subject to Change

//  --------- Issuer API -------------

pub struct IssuerService {
    signer: Box<dyn Signer>
}

impl IssuerService {
    // Step 1.
    pub async fn offer_credential(
        cred_def_id: &str,
        protocol_data: Option<&CredentialOfferData>
    ) -> Result<CredentialOffer, Box<dyn Error>>

    // Step 3.
    pub async fn issue_credential(
        credential_request: &CredentialRequest,
        claims: &CredentialClaims,
        nonce: &str, // same as in request_credential
    ) -> Result<(Credential, CredentialMetadata), Box<dyn Error>>
}



//  --------- Holder API -------------

pub struct HolderService {
    vault: Box<dyn Vault>,
    signer: Box<dyn Signer>
}

impl HolderService {

    // Step 2.
    pub async fn request_credential(
        credential_offer: &CredentialOffer,
        nonce: &str,
        key_id: &str,
    ) -> Result<(CredentialRequest, String), Box<dyn Error>>

    // Step 4.
    pub async fn store_credential(
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<Box<dyn Error>> 
    
    // Step 5A.
    // Assume credentials for presentations are selected automatically
    // If there is just one credential matching a presentation request - it's selected
    // If there are multiple selection matching - they are selected according to a default logic (such as take the first one)
    pub fn create_presentation_auto(
        nonce: &str,
        presentation_definition: &PresentationDefinition,
    ) -> Result<(Presentation, PresentationData), Box<dyn Error>>
    
    // Step 5A1
    // Manual approval/consent of credentials to be used for presentation
    // Step 5A1 - find matching credentials
    pub fn find_vcs_for_presentation(
        presentation_definition: &PresentationDefinition,
    ) -> Result<CredentialMapping, Box<dyn Error>>

    // Step 5A2
    // Manual approval/consent of credentials to be used for presentation
    // Step 5A2 - create presentation for a unambiguous Mapping where there is a VC for every presentation request item
    pub fn create_presentation(
        nonce: &str,
        presentation_definition: &PresentationDefinition,
        credential_mapping_selected: &CredentialMapping,
    ) -> Result<(Presentation, PresentationData), Box<dyn Error>>

}



//  --------- Verifier API -------------

pub struct VerifierService {
    did_resolver: Box<dyn DIDResolver>,
}

impl VerifierService {

    // Step 6.
    pub fn verify_presentation(
        presentation_definition: &PresentationDefinition,
        nonce: &str, // same as in create_presentation
        presentation: &Presentation,
        presentation_data: &PresentationData,
    ) -> Result<Boolean, Box<dyn Error>>

}