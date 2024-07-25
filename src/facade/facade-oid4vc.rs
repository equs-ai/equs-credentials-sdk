// ---------- COMMON TRAITS ----------------
pub trait HttpCLient{}



//  --------- DATA MODEL -------------
pub struct IssuerMetadata{
    pub cred_defs: Vector<CredentialDefinition>
    pub protocol_data: Option<IssuerMetadataData> // Protocol specific
}
pub struct IssuerMetadataData{}

pub struct AuthorizationRequest {
    // TODO: will be SpruceID/ASDK type, details will be changed
    pub presentation_definition: PresentationDefinition,
    pub nonce: String,
    pub authorization-response-uri: String,
    pub metadata: AuthorizationRequestMetadata,
}
pub struct AuthorizationRequestMetadata{}

pub struct AuthorizationResponse {} // SpruceID/ASDK type
pub struct AuthorizationResponseMetadata{}

pub type AccessToken = oauth2::AccessToken;


// THE API is Subject to Change

//  --------- Issuer API -------------

// Out-of-scope: Authorization Server (Key Cloak) for OAuth 2 (Authorization code flow):
// GET /authorize
// POST /token 

pub struct IssuerService {
    signer: Box<dyn Signer>
}

impl IssuerService {

    // Step 0
    // GET /.well-known/openid-credential-issuer HTTP/1.1
    pub async fn create_issuer_metadata() -> Result<IssuerMetadata, Box<dyn Error>>

    // Step 1
    // GET /<credential_offer_uri> or pass by value
    pub async fn create_credential_offer(
        cred_def_id: &str,
        protocol_data: Option<&CredentialOfferData> // grant type (auth code, pre-auth code), etc.
    ) -> Result<CredentialOffer, Box<dyn Error>>

    // Step 3
    // POST /credential HTTP/1.1
    pub async fn issue_credential(
        credential_request: &CredentialRequest,
        claims: &CredentialClaims,
        token: &AccessToken
    ) -> Result<(Credential, CredentialMetadata), Box<dyn Error>>
}

//  --------- Holder API -------------

pub struct HolderService {
    vault: Box<dyn Vault>,
    signer: Box<dyn Signer>,
    http_client: Box<dyn HttpCLient> 
}

impl HolderService {

    // Step 2
    // Calls GET /.well-known/openid-credential-issuer HTTP/1.1
    pub async fn request_issuer_metadata(
        credential_offer: &CredentialOffer,
    ) -> Result<IssuerMetadata>

    // Step 3
    // Calls the following:
    //   1. GET /authorize
    //   2. POST /token 
    //   3. POST /credential HTTP/1.1 to get nonce
    //   5. `request_credential`
    //   6. POST /credential HTTP/1.1 to get credential
    pub async fn request_credential(
        credential_offer: &CredentialOffer,
        key_id: &str,
    ) -> Result<(Credential, CredentialMetadata), Box<dyn Error>>
    
    // Step 4
    pub async fn store_credential(
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<Box<dyn Error>> 
    
    // Step 6
    // (Optional) AuthRequest can be sent out-of-band or by GET to auth-req-uri (this call)
    pub fn get_authorization_request(   
        auth-req-uri: &str
    ) -> Result<AuthorizationRequest, Box<dyn Error>> 
    
    // Step 7A
    // Assume credentials for presentations are selected automatically
    // If there is just one credential matching a presentation request - it's selected
    // If there are multiple selection matching - they are selected according to a default logic (such as take the first one)
    pub fn present_credentials_auto(
        auth_request: &AuthorizationRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Box<dyn Error>>

    // Step 7A1
    // Manual approval/consent of credentials to be used for presentation
    // Step 7A1 - find matching credentials
    pub fn find_vcs_for_presentation(
        auth_request: &AuthorizationRequest,
    ) -> Result<CredentialMapping, Box<dyn Error>>

    // Step 7A2
    // Manual approval/consent of credentials to be used for presentation
    // Step 5A2 - create presentation for a unambiguous Mapping where there is a VC for every presentation request item
    pub fn present_credentials(
        auth_request: &AuthorizationRequest,
        credential_mapping_selected: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Box<dyn Error>>

}


//  --------- Verifier API -------------

pub struct VerifierService {
    did_resolver: Box<dyn DIDResolver>,
}

impl VerifierService {

    // Step 5
    // GET /<authorization_req_uri> or pass by value
    pub fn create_authorization_request(
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        metadata: &AuthorizationRequestMetadata,
    ) -> Result<AuthorizationRequest, Box<dyn Error>> 

    // Step 7
    // POST <authorization-response-uri>
    pub fn verify_presentation(
        auth_response: &AuthorizationResponse
    ) -> Result<Boolean, Box<dyn Error>>

}





