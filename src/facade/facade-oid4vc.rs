// ---------- COMMON TRAITS ----------------
pub trait HttpCLient{}



//  --------- DATA MODEL -------------

pub struct AuthorizationMetadata {}

pub struct CredentialOffer {}

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
    oid4vci_issuer: Oid4VciIssuer,
    storage: Box<dyn Storage<String, Json>>,
    http_client: &'static HttpClient,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Issuance(#[from] exchange::oid4vc::vci_issuer::IssuanceError<reqwest::Error>),
}

impl IssuerService {
    pub fn new<KH>(
        kms: impl kms::Kms<KH> + 'static,
        storage: impl Storage<String, Json> + 'static,
        http_client: &'static HttpClient,
        metadata: IssuerMetadata,
        did_url: String,
        kid: String,
        auth_server_admin_auth_header: Option<HeaderValue>,
    ) -> Self
    where
        KH: kms::KeyHandle + 'static,
    {
        let cred_defs = retrieve_cred_defs(&metadata);

        let issuer_metadata = facade_low_level::IssuerMetadata {
            issuer_id: metadata.credential_issuer().to_string(),
            cred_defs,
            protocol_data: Some(facade_low_level::IssuerMetadataData::Oidc4Vc(
                metadata.clone(),
            )),
            key_metadata: facade_low_level::KeyMetadata { did_url, kid },
        };
        let core_issuer = facade_low_level::IssuerService::new(kms, issuer_metadata);
        let oid4vci_issuer =
            Oid4VciIssuer::new(metadata, core_issuer, auth_server_admin_auth_header);

        Self {
            oid4vci_issuer,
            storage: Box::new(storage),
            http_client,
        }
    }

    // Step 0
    // GET /.well-known/openid-credential-issuer HTTP/1.1
    pub async fn metadata(&self) -> Result<Json> {
        let metadata = self.oid4vci_issuer.metadata()?;

        return Ok(metadata);
    }

    // Step 1
    // GET /<credential_offer_uri> or pass by value
    pub async fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParameters<CoreProfilesOffer>, Url)> {
        let offer = self
            .oid4vci_issuer
            .create_credential_offer(cred_def_ids, grants)?;

        Ok(offer)
    }

    // Step 3
    // POST /credential HTTP/1.1
    pub async fn issue_credential(
        &mut self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &Value,
    ) -> Result<CredentialResponse> {
        let nonce = if let Some(nonce) = self.storage.get(token).await.ok() {
            serde_json::from_value(nonce.to_owned()).ok()
        } else {
            let nonce = serde_json::to_value(Nonce::new(uuid::Uuid::new_v4().to_string())).unwrap();
            let _ = self.storage.put(token.to_string(), nonce).await;

            None
        };

        let (cred, cred_metadata) = self.oid4vci_issuer
            .issue_credential(cred_request, token, nonce, claims, |req| {
                self.http_client.async_call(req)
            })
            .await
            .map_err(Error::Issuance)?;

        if let Some(value) = serde_json::to_value(&cred_metadata).ok() {
            let _ = self.storage.put(cred_metadata.core_metadata.id, value).await;
        }

        Ok(cred)
    }
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





