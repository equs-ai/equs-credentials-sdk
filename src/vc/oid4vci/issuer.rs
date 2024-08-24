use std::collections::HashMap;
use async_trait::async_trait;
use oauth2::Scope;
use oid4vci::core::profiles::{CoreProfilesMetadata, CoreProfilesOffer, CoreProfilesRequest, CoreProfilesResponse, sd_jwt, w3c};
use oid4vci::credential::{ProofVerificationErrorBody, ResponseEnum};
use oid4vci::credential_offer::{CredentialOfferFormat, CredentialOfferGrants, CredentialOfferParameters};
use oid4vci::openidconnect::Nonce;
use oid4vci::proof_of_possession::{KeyProofType, Proof as SpruceProof, ProofType};
use serde_json::{Map, Value};
use ssi::jwt::decode_unverified;
use url::Url;

use crate::storage::Storage;
use crate::utils::http::HttpClient;
use crate::vc;
use crate::vc::core::{Proof as AsdkProof, Proof};
use crate::vc::oid4vci::{CredentialOfferParams, CredentialRequest, CredentialResponse, IssuerMetadata};
use crate::vc::{Claims, oid4vci as api};
use crate::vc::oid4vci::metadata::CredentialMetadata;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};

const CRED_OFFER_URI: &str = "openid-credential-offer://";

// TODO: tune via config
const NONCE_EXPIRES_IN: i64 = 86440;

pub type Error = api::IssuerError;
pub type Result<T> = core::result::Result<T, Error>;

pub enum TokenValidation<HC: HttpClient> {
    Introspect(Introspect<HC>),
    ByJwks(ByJwks<HC>),
    None,
}

pub struct IssuerService<IS, ST, HC>
where
    IS: vc::core::Issuer,
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
    IS: vc::core::Issuer,
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
    IS: vc::core::Issuer,
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
        &self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &Claims,
    ) -> Result<CredentialResponse> {
        self.validate_token(token).await?;

        let nonce = if let Ok(nonce) = self.resolve_nonce(token).await {
            nonce
        } else {
            let nonce = self.upsert_nonce(token).await?;

            return Err(Self::invalid_proof(nonce));
        };

        let proof = if let Some(proof) =  cred_request.proof() {
            proof
        } else {
            return Err(Self::invalid_proof(nonce));
        };

        let cred_def_id = self.resolve_cred_def_id(cred_request)?;

        self.validate_scope(token, &cred_def_id)?;
        self.validate_claim_names(claims, &cred_def_id)?;
        self.validate_proof_type(&proof, &cred_def_id)?;

        let proof = Proof::from(proof);

        let cred_req = vc::core::CredentialRequest {
            cred_def_id,
            cred_offer_id: None,
            proof,
            protocol_data: None,
        };

        let result = self.issuer.issue_credential(&cred_req, claims, nonce.secret()).await;

        let new_nonce = self.upsert_nonce(token).await?;

        if let Err(vc::core::Error::Proof(e)) = &result {
            return Err(Self::invalid_proof(new_nonce));
        }

        if result.is_err() {
            return Err(Error::VC(result.err().unwrap()));
        }

        let (cred, _) = result?;
        let resp = CredentialResponse::new(ResponseEnum::Immediate(cred.into()))
            .set_nonce(Some(new_nonce))
            .set_nonce_expiration(Some(NONCE_EXPIRES_IN));

        Ok(resp)
    }
}

impl<IS, ST, HC> IssuerService<IS, ST, HC>
where
    IS: vc::core::Issuer,
    ST: Storage<String, String>,
    HC: HttpClient,
{
    fn resolve_cred_def_id(&self, req: &CredentialRequest) -> Result<String> {
        let vct = match req.additional_profile_fields() {
            CoreProfilesRequest::SDJWTVC(det) => {
                det.vct()
            }
            _ => {
                return Err(Error::FormatNotSupported)?
            }
        };

        let (cred_def_id, _) = self.issuer_metadata
            .credential_configurations_supported()
            .iter()
            .find(|(id, cred_metadata)| {
                if let CoreProfilesMetadata::SDJWTVC(metadata) = cred_metadata.additional_fields() {
                    return metadata.vct() == vct
                }
                false
            })
            .ok_or(Error::NotSupportedCredentialConfigurationId(
                format!("credential configuration id with vct = \"{}\" is not found", vct)
            ))?;

        Ok(cred_def_id.to_owned())
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

    fn validate_proof_type(&self, proof: &SpruceProof, cred_def_id: &str) -> Result<()> {
        let cred_metadata = self.get_credential_metadata(&cred_def_id)?;
        let proof_types = if let Some(proof_types) = cred_metadata.proof_types_supported() {
            proof_types
        } else {
            &Self::supported_proof_types()
        };

        let (proof_type, proof) = if let SpruceProof::JWT{ jwt } = proof {
            (KeyProofType::Jwt, jwt)
        } else {
            return Err(
                Error::ProofTypeValidation(
                    "only \"jwt\" proof type is supported".to_owned()
                ))
        };

        let proof_type = proof_types
            .get(&proof_type)
            .ok_or(Error::ProofTypeValidation(
                format!("proof type = \"{}\" is not supported", cred_def_id)
            ))?;

        let proof_header = jsonwebtoken::decode_header(&proof)
            .map_err( |e|
                Error::ProofTypeValidation(
                    format!("can not retrieve \"alg\" from the proof's header {}", e.to_string())
                )
            )?;

        let sign_alg = serde_json::from_value(
            serde_json::to_value(proof_header.alg)?
        )?;

        if !proof_type.proof_signing_alg_values_supported.contains(&sign_alg) {
            return Err(
                Error::ProofTypeValidation(
                    format!("proof_type signing algorithm = \"{:?}\" is not supported", sign_alg)
                ))
        }

        Ok(())
    }

    fn supported_proof_types() -> HashMap<KeyProofType, ProofType> {
        HashMap::from([(
            KeyProofType::Jwt,
            ProofType::new(vec![
                "ES256".to_owned(),
                "EdDSA".to_owned()
            ])
        )])
    }

    fn validate_scope(&self, token: &String, cred_def_id: &str) -> Result<()> {
        let token: Map<String, Value>   = decode_unverified(token.as_str())
            .map_err( |e|
                Error::ScopeValidation(
                    format!("could not parse the access token: {}", e.to_string())
                ))?;

        let supported: Vec<Option<&Scope>> = self.issuer_metadata
            .credential_configurations_supported()
            .values()
            .map(|cred_metadata| cred_metadata.scope())

            .collect();

        if let Some (Value::String(scopes)) = token.get("scope") {
            let not_supported = scopes
                .split(" ")
                .find(
                    |s| !supported.contains(
                        &Some(&Scope::new(s.to_string())
                        ))
                );

            if let Some(not_supported) = not_supported {
                return Err(Error::ScopeValidation(
                    format!("\"{}\" scope is not supported", not_supported)
                ))
            }

            return Ok(())
        }

        Err(
            Error::ScopeValidation(
            "access token does not have \"scope\" field".to_owned())
        )
    }

    fn validate_claim_names(&self, claims: &Value, cred_def_id: &str) -> Result<()> {
        let claim_names: Vec<&str> = if let Value::Object(claims) = claims {
            claims.keys().map(|k| k.as_str()).collect()
        } else {
            return Err(Error::ClaimNamesValidation("provided \"claims\" is not json object".to_owned()))
        };

        let cred_metadata = self.get_credential_metadata(&cred_def_id)?;
        let sd_jwt_vc_metadata = if let CoreProfilesMetadata::SDJWTVC(metadata) = cred_metadata.additional_fields() {
            metadata
        } else {
            //TODO Support other formats
            return Err(Error::FormatNotSupported)
        };

        let supported_claims = if let Some(claims) = sd_jwt_vc_metadata.credential_definition().claims() {
            let mut supported: Vec<&str> = claims.keys().map(|k| k.as_str()).collect();
            supported.push("vct");

            supported
        } else {
            return Ok(())
        };

        let not_supported = claim_names
            .iter()
            .find(
                |c| !supported_claims.contains(c)
            );
        if let Some(not_supported) = not_supported {
            return Err(Error::ClaimNamesValidation(
                format!("\"{}\" claim name is not supported", not_supported)
            ))
        }

        Ok(())
    }

    fn get_credential_metadata(&self, cred_def_id: &str) -> Result<&CredentialMetadata> {
        self.issuer_metadata.
            credential_configurations_supported()
            .get(cred_def_id)
            .ok_or(
                Error::NotSupportedCredentialConfigurationId(
                    format!("credential configuration with \"{}\" id is not found", cred_def_id)
                )
            )
    }

    async fn resolve_nonce(&self, token: &String) -> Result<Nonce> {
        let nonce = self.storage.get(token).await?;

        Ok(Nonce::new(nonce.to_owned()))
    }

    async fn upsert_nonce(&self, token: &String) -> Result<Nonce> {
        let nonce = Nonce::new_random();

        self.storage.put(token.clone(), nonce.secret().to_owned()).await?;

        Ok(nonce)
    }

    pub async fn validate_token(&self, token: &str) -> Result<()> {
        match &self.token_validation {
            TokenValidation::Introspect(svc) => {
                svc.validate(token).await?
            }
            TokenValidation::ByJwks(svc) => {
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