use std::collections::HashMap;
use async_trait::async_trait;
use oauth2::Scope;
use oid4vci::core::profiles::{CoreProfilesMetadata, CoreProfilesOffer, CoreProfilesRequest, CoreProfilesResponse, sd_jwt, w3c};
use oid4vci::credential::{ErrorType, ResponseEnum};
use oid4vci::credential_offer::{CredentialOfferFormat, CredentialOfferGrants, CredentialOfferParameters};
use oid4vci::openidconnect::Nonce;
use oid4vci::proof_of_possession::{KeyProofType, Proof as SpruceProof, ProofType};
use serde_json::{Map, Value};
use ssi::jwt::decode_unverified;
use url::Url;
use tracing::{instrument, Level, debug, info, trace};

use crate::storage::Storage;
use crate::utils::http::HttpClient;
use crate::vc;
use crate::vc::core::{Proof as AsdkProof, Proof};
use crate::vc::oid4vci::{CredentialOfferParams, CredentialRequest, CredentialResponse, InternalError, IssuerMetadata, ProtocolErrorResponse};
use crate::vc::{Claims, oid4vci as api};
use crate::vc::oid4vci::metadata::CredentialMetadata;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};

const CRED_OFFER_URI: &str = "openid-credential-offer://";

// TODO: tune via config
const NONCE_EXPIRES_IN: i64 = 86440;
const INVALID_PROOF_ERR_DESC: &str = "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.";

pub type Error = api::Error;
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
    #[instrument(
        level = Level::TRACE,
        skip(issuer, storage, token_validation)
    )]
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: IS,
        storage: ST,
        token_validation: TokenValidation<HC>,
    ) -> Self {
        info!("oid4vci issuer service is initialized");

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
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(level = Level::DEBUG)
    )]
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, grants),
        err(),
        ret(level = Level::TRACE),
    )]
    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants,
    ) -> Result<(CredentialOfferParams, Url)> {
        info!("creation of credential offer is started");
        trace!(?grants);

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

        let cred_offer = serde_json::to_string(&cred_offer_params)
            .map_err(InternalError::Parse)?;

        let mut url = Url::parse(CRED_OFFER_URI)
            .map_err(InternalError::Url)?;

        url.set_query(Some(format!("credential_offer={}", cred_offer).as_str()));

        info!("credential offer is created");

        Ok((cred_offer_params, url))
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    async fn issue_credential(
        &self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &Claims,
    ) -> Result<CredentialResponse> {
        info!("issuance of credential is started");
        trace!(credential_request = ?cred_request, %token, claims_to_issue = ?claims);

        self.validate_token(token).await?;

        let nonce = match self.resolve_nonce(token).await {
            Ok(Some(nonce)) => nonce,
            _ => return Err(self.invalid_proof(&token, INVALID_PROOF_ERR_DESC).await?)
        };

        let proof = match cred_request.proof() {
            Some(proof) => proof,
            _ => return Err(self.invalid_proof(&token, INVALID_PROOF_ERR_DESC).await?)
        };

        let cred_def_id = self.resolve_cred_def_id(cred_request)?;

        self.validate_scope(token, &cred_def_id)?;
        self.validate_claim_names(claims, &cred_def_id)?;
        self.validate_proof_type(&proof, &cred_def_id, token).await?;

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
            return Err(
                self.invalid_proof(&token, INVALID_PROOF_ERR_DESC).await?
            );
        }

        let (cred, _) = result
            .map_err(InternalError::VC)?;

        let resp = CredentialResponse::new(ResponseEnum::Immediate(cred.into()))
            .set_nonce(Some(new_nonce))
            .set_nonce_expiration(Some(NONCE_EXPIRES_IN));

        info!("credential is issued");

        Ok(resp)
    }
}

impl<IS, ST, HC> IssuerService<IS, ST, HC>
where
    IS: vc::core::Issuer,
    ST: Storage<String, String>,
    HC: HttpClient,
{

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::DEBUG),
    )]
    fn resolve_cred_def_id(&self, req: &CredentialRequest) -> Result<String> {
        trace!(credential_request = ?req);

        let vct = match req.additional_profile_fields() {
            CoreProfilesRequest::SDJWTVC(det) => {
                det.vct()
            }
            _ => {
                return Err(
                    ProtocolErrorResponse::new(
                        ErrorType::UnsupportedCredentialFormat,
                        "only \"vc+sd-jwt\" format is supported"
                    )
                )?
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
            .ok_or(
                ProtocolErrorResponse::new(
                    ErrorType::UnsupportedCredentialType,
                    &format!("credential configuration id with vct = \"{}\" is not found", vct)
                )
            )?;

        Ok(cred_def_id.to_owned())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn validate_cred_def_ids(&self, cred_def_ids: &Vec<&str>) -> Result<()> {
        if cred_def_ids.is_empty() {
            return Err(
                ProtocolErrorResponse::new(
                    ErrorType::InvalidRequest,
                    "Missed credential configuration ids").into()
            );
        }

        let supported: Vec<String> = self.issuer_metadata
            .credential_configurations_supported()
            .keys()
            .into_iter()
            .map(|e| e.to_owned())
            .collect();

        debug!(supported_credential_definition_ids = ?supported);

        for c in cred_def_ids {
            if !supported.contains(&c.to_string()) {

                return Err(
                    ProtocolErrorResponse::new(
                    ErrorType::UnsupportedCredentialType,
                    &format!("Credential definition id = {} is not supported", c)
                    ).into()
                );
            }
        }

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, proof, token),
        err(),
        ret(level = Level::DEBUG),
    )]
    async fn validate_proof_type(
        &self,
        proof: &SpruceProof,
        cred_def_id: &str,
        token: &String
    ) -> Result<()>
    {
        trace!(?proof, %token);

        let cred_metadata = self.get_credential_metadata(&cred_def_id)?;
        debug!(resolved_credential_metadata = ?cred_metadata);

        let proof_types = match cred_metadata.proof_types_supported() {
            Some(proof_types)  => proof_types,
            _ => &Self::supported_proof_types()
        };

        let (proof_type, proof) = match proof {
            SpruceProof::JWT{ jwt } => (KeyProofType::Jwt, jwt),
            _ => {
                let err = self.invalid_proof(token, "only \"jwt\" proof type is supported").await?;

                return Err(err)
            }
        };

        let proof_type = match proof_types.get(&proof_type) {
            Some(proof_type)  => proof_type,
            _ => {
                let proof_type = serde_json::to_string(&proof_type).map_err(InternalError::Parse)?;
                let err = self.invalid_proof(
                    token,
                    &format!("proof type = \"{}\" is not supported", proof_type)
                ).await?;

                return Err(err)
            }
        };
        debug!(resolved_proof_type = ?proof_type);

        let proof_header = match jsonwebtoken::decode_header(&proof) {
            Ok(proof_header) => proof_header,
            _ => {
                let err = self.invalid_proof(
                    &token,
                    "can not retrieve \"alg\" from the proof's header"
                ).await?;

                return Err(err)
            }
        };

        let sign_alg = serde_json::from_value(
            serde_json::to_value(proof_header.alg)
                .map_err(InternalError::Parse)?
        ).map_err(InternalError::Parse)?;
        debug!(resolved_signing_algorithm = %sign_alg);

        if !proof_type.proof_signing_alg_values_supported.contains(&sign_alg) {
            let err = self.invalid_proof(
                token,
                &format!("proof_type signing algorithm = \"{}\" is not supported", sign_alg)
            ).await?;

            return Err(err)
        }

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        ret(level = Level::DEBUG),
    )]
    fn supported_proof_types() -> HashMap<KeyProofType, ProofType> {
        HashMap::from([(
            KeyProofType::Jwt,
            ProofType::new(vec![
                "ES256".to_owned(),
                "EdDSA".to_owned()
            ])
        )])
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, token),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn validate_scope(&self, token: &String, cred_def_id: &str) -> Result<()> {
        trace!(token_to_validate = %token);

        let token: Map<String, Value>   = decode_unverified(token.as_str())
            .map_err( |_|
                ProtocolErrorResponse::new(
                    ErrorType::InvalidToken,
                    "could not parse the access token"
                )
            )?;

        let supported: Vec<Option<&Scope>> = self.issuer_metadata
            .credential_configurations_supported()
            .values()
            .map(|cred_metadata| cred_metadata.scope())

            .collect();
        debug!(supported_credential_definition_ids = ?supported);

        if let Some (Value::String(scopes)) = token.get("scope") {
            let not_supported = scopes
                .split(" ")
                .find(
                    |s| !supported.contains(
                        &Some(&Scope::new(s.to_string())
                        ))
                );

            if let Some(not_supported) = not_supported {
                return Err(
                    ProtocolErrorResponse::new(
                        ErrorType::InvalidToken,
                        &format!("\"{}\" scope declared in the token is not supported", not_supported)
                    ).into()
                )
            }

            return Ok(())
        }

        Err(
            ProtocolErrorResponse::new(
                ErrorType::InvalidToken,
                "access token does not have \"scope\" field"
            ).into()
        )
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, claims),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn validate_claim_names(&self, claims: &Value, cred_def_id: &str) -> Result<()> {
        trace!(?claims);

        let claim_names: Vec<&str> = match claims {
            Value::Object(claims) => claims.keys().map(|k| k.as_str()).collect(),
            _ => return Err(
                InternalError::ClaimNamesValidation("provided \"claims\" is not json object".to_owned())
                    .into()
            )
        };

        let cred_metadata = self.get_credential_metadata(&cred_def_id)?;
        let sd_jwt_vc_metadata = match cred_metadata.additional_fields() {
            CoreProfilesMetadata::SDJWTVC(metadata) => metadata,
            _ =>
            //TODO Support other formats
                return Err(
                    ProtocolErrorResponse::new(
                        ErrorType::UnsupportedCredentialFormat,
                        "only \"vc+sd-jwt\" format is supported"
                    ).into()
                )
        };
        debug!(resolved_credential_metadata = ?sd_jwt_vc_metadata);

        let supported_claims =  match sd_jwt_vc_metadata.credential_definition().claims() {
            Some(claims) => {
                let mut supported: Vec<&str> = claims.keys().map(|k| k.as_str()).collect();
                supported.push("vct");

                supported
            }

            _ => return Ok(())
        };
        debug!(?supported_claims);

        let not_supported = claim_names
            .iter()
            .find(
                |c| !supported_claims.contains(c)
            );
        if let Some(not_supported) = not_supported {
            return Err(
                InternalError::ClaimNamesValidation(
                    format!("\"{}\" claim name is not supported", not_supported)
                ).into()
            )
        }

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn get_credential_metadata(&self, cred_def_id: &str) -> Result<&CredentialMetadata> {
        self.issuer_metadata.
            credential_configurations_supported()
            .get(cred_def_id)
            .ok_or(
                InternalError::CredDefNotFound(
                    format!("credential configuration with \"{}\" id is not found", cred_def_id)
                ).into()
            )
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, token),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn resolve_nonce(&self, token: &String) -> Result<Option<Nonce>> {
        trace!(%token);

        let nonce = self.storage.get(token)
            .await
            .map_err(InternalError::Storage)?;

        Ok(nonce.map(Nonce::new))
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    async fn upsert_nonce(&self, token: &String) -> Result<Nonce> {
        trace!(%token);

        let nonce = Nonce::new_random();

        self.storage.put(token.clone(), nonce.secret().to_owned())
            .await
            .map_err(InternalError::Storage)?;

        Ok(nonce)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, token),
        err(),
        ret(level = Level::TRACE),
    )]
    pub async fn validate_token(&self, token: &str) -> Result<()> {
        trace!(%token);

        match &self.token_validation {
            TokenValidation::Introspect(svc) => {
                svc.validate(token)
                    .await
                    .map_err( |_|
                        ProtocolErrorResponse::new(
                            ErrorType::InvalidToken,
                            "could not validate the token"
                        )
                    )?
            }
            TokenValidation::ByJwks(svc) => {
                svc.validate(token)
                    .await
                    .map_err( |_|
                        ProtocolErrorResponse::new(
                            ErrorType::InvalidToken,
                            "could not validate the token"
                        )
                    )?
            }
            TokenValidation::None => {}
        }

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, token),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn invalid_proof(&self, token: &String, description: &str) -> Result<Error> {
        trace!(%token);

        let nonce = self.upsert_nonce(token).await?;
        let err = Error::Protocol(
            ProtocolErrorResponse::new_with_nonce(
                ErrorType::InvalidProof,
                description,
                nonce,
                NONCE_EXPIRES_IN,
            )
        );

        Ok(err)
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