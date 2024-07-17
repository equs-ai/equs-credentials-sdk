// ---------- COMMON TRAITS ----------------
pub trait HttpCLient{}



//  --------- DATA MODEL -------------
pub struct IssuerMetadata{
    pub cred_defs: Vector<CredentialDefinition>
    pub protocol_data: Option<IssuerMetadataData> // Protocol specific
}
pub struct IssuerMetadataData{}

pub struct PresentationRequest{
    pub presentation_definition: PresentationDefinition,
    pub nonce: String,
    pub presentation_request_metadata: PresentationRequestMetadata,
}
pub struct PresentationRequestMetadata{}

pub type AccessToken = oauth2::AccessToken;

// TODO: Adapters of Common types from facade-low-level to corresponding OID4VC Presentation Objects



//  --------- Issuer API -------------

// Out-of-scope: Authorization Server (Key Cloak) for OAuth 2 (Authorization code flow):
// GET /authorize
// POST /token 

pub struct IssuerService {
    signer: Signer
}

impl IssuerService {

    // (Optional) Step 0. 
    // GET /.well-known/openid-credential-issuer HTTP/1.1
    pub async fn create_issuer_metadata() -> Result<IssuerMetadata, Box<dyn Error>>

    // Step 1
    // GET /credential_offer HTTP/1.1
    pub async fn create_credential_offer() -> Result<CredentialOffer, Box<dyn Error>>

    // Step 2
    // POST /credential HTTP/1.1
    pub async fn issue_credential(
        credential_request: CredentialRequest,
        claims: CredentialClaims,
        token: AccessToken
    ) -> Result<(Credential, CredentialMetadata), Box<dyn Error>>
}

//  --------- Holder API -------------

pub struct HolderService {
    vault: Vault,
    signer: Signer,
    http_client: HttpCLient 
}

impl HolderService {

    // (Optional) Step 0. 
    // Calls GET /.well-known/openid-credential-issuer HTTP/1.1
    pub async fn request_issuer_metadata() -> Result<IssuerMetadata>

    // Step 1
    // Calls GET /credential_offer HTTP/1.1
    pub async fn get_credential_offer(
        issuer_metadata: Option<IssuerMetadata>
    ) -> Result<CredentialOffer, Box<dyn Error>>
    
    // Step 2
    // Calls the following:
    //   1. GET /authorize
    //   2. POST /token 
    //   3. POST /credential HTTP/1.1 to get nonce
    //   5. `request_credential`
    //   6. POST /credential HTTP/1.1 to get credential
    pub async fn request_credential(
        credential_offer: &CredentialOffer,
        key_id: String,
    ) -> Result<(Credential, CredentialMetadata), Box<dyn Error>>
    
    // Step 3
    pub async fn store_credential(
        credential: Credential,
        credential_metadata: CredentialMetadata,
    ) -> Result<Box<dyn Error>> 
    
    // Step 4
    pub fn get_presentation_request(
    ) -> Result<PresentationRequest, Box<dyn Error>> 
    
    // Step 5
    pub fn present_credentials(
        vault: Vault,
        presentation_request: PresentationRequest,
    ) -> Result<Box<dyn Error>>

}


//  --------- Verifier API -------------

pub struct VerifierService {
    did_resolver: DIDResolver,
}

impl VerifierService {

    // Step 4
    pub fn create_presentation_request(
        presentation_definition: PresentationDefinition,
        nonce: String,
    ) -> Result<PresentationRequest, Box<dyn Error>> 

    // Step 5.
    // POST response_uri
    pub fn verify_presentation(
        presentation: Presentation,
        presentation_data: PresentationData,
    ) -> Result<Boolean, Box<dyn Error>>

}





