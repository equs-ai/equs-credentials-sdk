use async_trait::async_trait;
use oauth2::Scope;
use oid4vci::core::profiles::{CoreProfilesOffer, CoreProfilesRequest, CoreProfilesResponse, sd_jwt, w3c};
use oid4vci::credential::{ProofVerificationErrorBody, ResponseEnum};
use oid4vci::credential_offer::{CredentialOfferFormat, CredentialOfferGrants, CredentialOfferParameters};
use oid4vci::openidconnect::Nonce;
use oid4vci::proof_of_possession::Proof as SpruceProof;
use url::Url;

use crate::core_::storage::Storage;
use crate::core_::vc;
use crate::exchange::oid4vc::oid4vci::{CredentialOfferParams, CredentialRequest, CredentialResponse, IssuerMetadata};
use crate::exchange::oid4vc::oid4vci as api;
use crate::exchange::oid4vc::oid4vci::introspect::Introspect;
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::{CredentialClaims, Proof};
use crate::facade::facade_low_level::Proof as AsdkProof;
use crate::impls::http::HttpClient;

const CRED_OFFER_URI: &str = "openid-credential-offer://";

// TODO: tune via config
const NONCE_EXPIRES_IN: i64 = 86440;

pub type Error = api::IssuerError;
pub type Result<T> = core::result::Result<T, Error>;

pub enum TokenValidation<HC: HttpClient> {
    Introspect(Introspect<HC>),
    None,
    //TODO: implement jwks
}

pub struct IssuerService<IS, ST, HC>
where
    IS: facade_low_level::Issuer,
    ST: Storage<String, String>,
    HC: HttpClient,
{
    issuer: IS,
    storage: ST,
    issuer_metadata: IssuerMetadata,
    token_validation: TokenValidation<HC>,
}

impl<IS, ST, HC> IssuerService<IS, ST, HC>
where
    IS: facade_low_level::Issuer,
    ST: Storage<String, String>,
    HC: HttpClient,
{
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: IS,
        storage: ST,
        token_validation: TokenValidation<HC>,
    ) -> Self {
        Self {
            issuer,
            storage,
            issuer_metadata,
            token_validation,
        }
    }
}

#[async_trait]
impl<IS, ST, HC> api::Issuer for IssuerService<IS, ST, HC>
where
    IS: facade_low_level::Issuer,
    ST: Storage<String, String>,
    HC: HttpClient,
{
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants,
    ) -> Result<(CredentialOfferParams, Url)> {
        self.validate_cred_def_ids(&cred_def_ids)?;

        let cred_offer_params: CredentialOfferParameters<CoreProfilesOffer> =
            CredentialOfferParameters::new(
                self.issuer_metadata.credential_issuer().clone(),
                cred_def_ids
                    .iter()
                    .map(|c| CredentialOfferFormat::Reference(Scope::new(c.to_string())))
                    .collect(),
                Some(grants.to_owned()),
            );

        let cred_offer = serde_json::to_string(&cred_offer_params)?;

        let mut url = Url::parse(CRED_OFFER_URI)?;
        url.set_query(Some(format!("credential_offer={}", cred_offer).as_str()));

        Ok((cred_offer_params, url))
    }

    async fn issue_credential(
        &mut self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &CredentialClaims,
    ) -> Result<CredentialResponse> {
        self.validate_token(token).await?;

        let nonce = self.resolve_nonce(token).await;

        if cred_request.proof().is_none() || nonce.is_err() {
            let nonce = self.upsert_nonce(token).await?;
            return Err(Self::invalid_proof(nonce));
        }

        let nonce = nonce.unwrap();

        let cred_def_id = self.resolve_cred_def_id(cred_request)?;
        let cred_req = facade_low_level::CredentialRequest {
            cred_def_id,
            cred_offer_id: None,
            proof: Proof::from(cred_request.proof().unwrap()),
            protocol_data: None,
        };

        let result = self.issuer.issue_credential(&cred_req, claims, nonce.secret()).await;

        let new_nonce = self.upsert_nonce(token).await?;

        if let Err(facade_low_level::Error::Proof(e)) = &result {
            return Err(Self::invalid_proof(new_nonce));
        }

        if result.is_err() {
            return Err(Error::VC(result.err().unwrap()));
        }

        let (cred, _) = result.unwrap();
        let resp = CredentialResponse::new(ResponseEnum::Immediate(cred.into()))
            .set_nonce(Some(new_nonce))
            .set_nonce_expiration(Some(NONCE_EXPIRES_IN));

        Ok(resp)
    }
}

impl<IS, ST, HC> IssuerService<IS, ST, HC>
where
    IS: facade_low_level::Issuer,
    ST: Storage<String, String>,
    HC: HttpClient,
{
    fn resolve_cred_def_id(&self, req: &CredentialRequest) -> Result<String> {
        let id = match req.additional_profile_fields() {
            CoreProfilesRequest::SDJWTVC(det) => {
                match det {
                    // TODO: scope=vct only supported by now
                    sd_jwt::Request { vct: Some(id), .. } => id,
                    _ => Err(Error::NotSupportedCredentialConfigurationId("invalid authorization".to_string()))?
                }
            }
            _ => Err(Error::FormatNotSupported)?,
        };

        Ok(id.to_owned())
    }

    fn validate_cred_def_ids(&self, cred_def_ids: &Vec<&str>) -> Result<()> {
        if cred_def_ids.is_empty() {
            return Err(Error::MissingCredentialConfigurationIds);
        }

        let supported: Vec<String> = self.issuer_metadata
            .credential_configurations_supported()
            .keys()
            .into_iter()
            .map(|e| e.to_owned())
            .collect();

        for c in cred_def_ids {
            if !supported.contains(&c.to_string()) {
                return Err(Error::NotSupportedCredentialConfigurationId(
                    c.to_string(),
                ));
            }
        }

        Ok(())
    }

    async fn resolve_nonce(&mut self, token: &String) -> Result<Nonce> {
        let nonce = self.storage.get(token).await?;

        Ok(Nonce::new(nonce.to_owned()))
    }

    async fn upsert_nonce(&mut self, token: &String) -> Result<Nonce> {
        let nonce = Nonce::new_random();

        self.storage.put(token.clone(), nonce.secret().to_owned()).await?;

        Ok(nonce)
    }

    pub async fn validate_token(&self, token: &str) -> Result<()> {
        match &self.token_validation {
            TokenValidation::Introspect(svc) => {
                svc.validate(token).await?
            }
            TokenValidation::None => {}
        }

        Ok(())
    }

    fn invalid_proof(nonce: Nonce) -> Error {
        Error::InvalidProof(ProofVerificationErrorBody {
            error: "invalid_proof".to_string(),
            error_description: "Generate PoP for provided nonce".to_string(),
            c_nonce: Some(nonce),
            c_nonce_expires_in: Some(NONCE_EXPIRES_IN),
        })
    }
}

impl From<&SpruceProof> for AsdkProof {
    fn from(value: &SpruceProof) -> AsdkProof {
        match value {
            SpruceProof::JWT { jwt } => { AsdkProof { format: "jwt".to_string(), proof: jwt.to_string() } }
            SpruceProof::CWT { cwt } => { AsdkProof { format: "cwt".to_string(), proof: cwt.to_owned() } }
        }
    }
}

impl Into<CoreProfilesResponse> for vc::Credential {
    fn into(self) -> CoreProfilesResponse {
        match self {
            vc::Credential::JwtVcJson(cred) => { CoreProfilesResponse::JWTVC(w3c::jwt::Response::new(cred)) }
            vc::Credential::JwtVcJsonLd(_) => { CoreProfilesResponse::JWTLDVC(w3c::jwtld::Response {}) }
            vc::Credential::LdpVc(cred) => { CoreProfilesResponse::LDVC(w3c::ldp::Response::new(cred)) }
            vc::Credential::SdJwt(cred) => { CoreProfilesResponse::SDJWTVC(sd_jwt::Response::new(cred)) }
        }
    }
}