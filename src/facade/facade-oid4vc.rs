// ---------- COMMON TRAITS ----------------
pub trait HttpCLient{}



//  --------- DATA MODEL -------------
pub struct IssuerMetadata{
    pub cred_defs: Vector<CredentialDefinition>
    pub protocol_data: Option<IssuerMetadataData> // Protocol specific
}
pub struct AuthorizationMetadata {}

pub struct CredentialOffer {}
pub struct IssuerMetadataData{}


pub enum AuthorizationUrlType {
    Reference(Url),
    Value,
}

pub struct AuthorizationRequest {
    client_id: ClientId,
    request_object_jwt: String,
    authorization_endpoint: Url,
}

impl AuthorizationRequest {
    fn as_url(&self, type_: AuthorizationUrlType) -> Result<Url, Error> {
        let request_indirection = match type_ {
            AuthorizationUrlType::Value => {
                RequestIndirection::ByValue(self.request_object_jwt.clone())
            }
            AuthorizationUrlType::Reference(at) => RequestIndirection::ByReference(at),
        };

        SpruceAuthorizationRequest {
            client_id: self.client_id.0.clone(),
            request_indirection,
        }
            .to_url(self.authorization_endpoint.clone())
            .map_err(|err| {
                Error::RequestCreationFailed(format!(
                    "Cannot convert Authorization Request into URL: {}",
                    err
                ))
            })
    }
}

pub struct AuthorizationResponse {
    vp_token: Json,
    presentation_submission: PresentationSubmission,
}

pub type AccessToken = oauth2::AccessToken;

pub struct TokenResponse {
    token: AccessToken,
    nonce: Option<String>,
}

pub struct CredentialRequest {
    cred_def_id: String,
}

pub enum CredentialResult {
    Deferred { transaction_id: String },
    Credential { credential: Credential, notification_id: Option<String> },
}

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
    pub async fn from_issuer_url(
        issuer_url: String,
    )-> Result<Self, Box<dyn Error>>

    pub async fn from_metadata(
        issuer_metadata: &IssuerMetadata,
        authorization_metadata: &AuthorizationMetadata,
    ) -> Result<Self, Box<dyn Error>>

    pub async fn from_offer(
        credential_offer: &CredentialOffer,
    ) -> Result<Self, Box<dyn Error>>


    pub fn get_issuer_metadata(
        &self,
    ) -> IssuerMetadata

    // Step 3
    // Calls the following:
    //   1. GET /authorize
    //   2. POST /token 
    //   3. POST /credential HTTP/1.1 to get nonce
    //   5. `request_credential`
    //   6. POST /credential HTTP/1.1 to get credential


    pub async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
    ) -> Result<TokenResponse, Box<dyn Error>>

    pub async fn authz_code_flow_with_scope(
        &self,
        cred_def_id: String,
        authorization_callback: fn(Url) -> String,
    ) -> Result<TokenResponse, Box<dyn Error>>

    pub async fn request_credential(
        &self,
        token_response: TokenResponse,
        credential_request: &CredentialRequest,
    ) -> Result<CredentialResult, Box<dyn Error>>
    
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
    verifier: Oid4VpVerifier,
    storage: Box<dyn Storage<String, Json>>,
}

impl VerifierService {

    // Step 5
    // GET /<authorization_req_uri> or pass by value

    pub async fn create_authorization_request(
        &mut self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        wallet_metadata: WalletMetadata,
        response_uri: Url,
    ) -> Result<AuthorizationRequest, Box<dyn Error>> {

    // Step 7
    // POST <authorization-response-uri>
    pub async fn verify_presentation(
        &mut self,
        authorization_response: &AuthorizationResponse,
    ) -> Result<Json, Box<dyn Error>> {

}





