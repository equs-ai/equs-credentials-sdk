use crate::http::HttpClient;
use crate::vc;
use crate::vc::core::{Proof as AsdkProof, Proof};
use crate::vc::oid4vci::internal_error::{
    ClaimsValidationSnafu, NoScopeSetSnafu, ParseSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::protocol_error::ProtocolSnafu;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};
use crate::vc::oid4vci::{
    CredDefMetadata, CredentialOfferParams, CredentialRequest, CredentialResponse, IssuanceSession,
    IssuerMetadata, Nonce, NonceData,
};
use crate::vc::{oid4vci as api, Claims, HasVCFormat};
use async_trait::async_trait;
use oauth2::Scope;
use oid4vci::core::profiles::{
    sd_jwt, w3c, CoreProfilesMetadata, CoreProfilesOffer, CoreProfilesRequest, CoreProfilesResponse,
};
use oid4vci::credential::{ErrorType, ResponseEnum};
use oid4vci::credential_offer::{
    CredentialOfferFormat, CredentialOfferGrants, CredentialOfferParameters,
};
use oid4vci::proof_of_possession::{KeyProofType, Proof as SpruceProof, ProofType};
use serde_json::{Map, Value};
use snafu::{ensure, ResultExt};
use ssi::jwt::decode_unverified;
use std::collections::HashMap;
use std::ops::Add;
use time::ext::NumericalDuration;
use tracing::{debug, error, info, instrument, trace, Level};
use url::Url;
use uuid::Uuid;

const CRED_OFFER_URI: &str = "openid-credential-offer://";

// TODO: tune via config
const NONCE_EXPIRES_IN: i64 = 86440;
const INVALID_PROOF_ERR_DESC: &str =
    "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.";

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

pub enum TokenValidation<HC: HttpClient> {
    Introspect(Introspect<HC>),
    ByJwks(ByJwks<HC>),
    None,
}

pub struct IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    issuer: IS,
    issuer_metadata: IssuerMetadata,
    token_validation: TokenValidation<HC>,
}

impl<IS, HC> IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    #[instrument(
        level = Level::TRACE,
        skip(issuer, token_validation)
    )]
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: IS,
        token_validation: TokenValidation<HC>,
    ) -> Self {
        info!("oid4vci-issuer service is initialized");

        Self {
            issuer,
            issuer_metadata,
            token_validation,
        }
    }
}

#[async_trait]
impl<IS, HC> api::Issuer for IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
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
        skip(self),
        ret(level = Level::DEBUG)
    )]
    fn get_cred_def_metadata(&self, cred_request: &CredentialRequest) -> Option<CredDefMetadata> {
        self.resolve_cred_def(cred_request)
            .map(|(_, cred_def)| cred_def)
            .ok()
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

        let cred_offer = serde_json::to_string(&cred_offer_params).context(ParseSnafu)?;

        let mut url = Url::parse(CRED_OFFER_URI).context(UrlParseSnafu)?;

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
        token: &str,
        claims: &Claims,
        session: &mut IssuanceSession,
    ) -> Result<CredentialResponse> {
        info!("issuance of credential is started");
        trace!(credential_request = ?cred_request, %token, claims_to_issue = ?claims);

        self.validate_token(token).await?;

        let nonce = self.validate_nonce(session)?.nonce;

        let proof = cred_request.proof().ok_or_else(|| {
            self.invalid_proof(session, INVALID_PROOF_ERR_DESC.to_string())
                .build()
        })?;

        let (cred_def_id, cred_def) = self.resolve_cred_def(cred_request)?;

        // FIXME: Remove this check after adopting authorization details
        ensure!(
            cred_def.scope().is_some(),
            NoScopeSetSnafu {
                id: cred_def_id.to_owned()
            }
        );

        if let Some(scope) = cred_def.scope() {
            self.validate_scope(token, &cred_def_id, scope)?;
        }
        self.validate_claim_names(claims, &cred_def)?;
        self.validate_proof_type(proof, &cred_def, session).await?;

        let proof = Proof::from(proof);

        let cred_req = vc::core::CredentialRequest {
            cred_def_id,
            cred_offer_id: None,
            proof,
            protocol_data: None,
        };

        let result = self
            .issuer
            .issue_credential(&cred_req, claims, nonce.secret())
            .await;

        let (cred, _) = match result {
            Err(vc::core::Error::Proof { location, source }) => self
                .invalid_proof(session, INVALID_PROOF_ERR_DESC.to_string())
                .fail()?,
            _ => result.context(VCSnafu)?,
        };

        let mut resp = CredentialResponse::new(ResponseEnum::Immediate(cred.into()));
        resp = Self::update_cred_resp_and_session_data(resp, session);

        info!("credential is issued");

        Ok(resp)
    }
}

impl<IS, HC> IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::DEBUG),
    )]
    fn resolve_cred_def(&self, req: &CredentialRequest) -> Result<(String, CredDefMetadata)> {
        trace!(credential_request = ?req);

        let vct = match req.additional_profile_fields() {
            CoreProfilesRequest::SDJWTVC(det) => det.vct(),
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!(
                    "Unsupported credential format: {}",
                    req.additional_profile_fields().format()
                ),
            )
            .fail()?,
        };

        let (cred_def_id, cred_metadata) = self
            .issuer_metadata
            .credential_configurations_supported()
            .iter()
            .find(|(id, cred_metadata)| {
                if let CoreProfilesMetadata::SDJWTVC(metadata) = cred_metadata.additional_fields() {
                    return metadata.vct() == vct;
                }
                false
            })
            .ok_or(
                ProtocolSnafu::new(
                    ErrorType::UnsupportedCredentialType,
                    format!("Credential configuration id with vct = \"{vct}\" is not found"),
                )
                .build(),
            )?;

        Ok((cred_def_id.to_owned(), cred_metadata.to_owned()))
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn validate_cred_def_ids(&self, cred_def_ids: &Vec<&str>) -> Result<()> {
        ensure!(
            !cred_def_ids.is_empty(),
            ProtocolSnafu::new(
                ErrorType::InvalidRequest,
                "Missed credential configuration ids".to_string()
            )
        );

        let supported: Vec<String> = self
            .issuer_metadata
            .credential_configurations_supported()
            .keys()
            .map(|e| e.to_owned())
            .collect();

        debug!(supported_credential_definition_ids = ?supported);

        for id in cred_def_ids {
            ensure!(
                supported.contains(&id.to_string()),
                ProtocolSnafu::new(
                    ErrorType::UnsupportedCredentialType,
                    format!("Unsupported Credential definition ID: {id}")
                )
            );
        }

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
    fn validate_nonce(&self, session: &mut IssuanceSession) -> Result<NonceData> {
        match &session.nonce {
            Some(nonce_data) => {
                if let (Some(created), Some(expires_in)) =
                    (nonce_data.created, nonce_data.expires_in)
                {
                    let expires = created.add(expires_in.seconds());
                    ensure!(
                        time::OffsetDateTime::now_utc() < expires,
                        self.invalid_proof(session, INVALID_PROOF_ERR_DESC.to_string())
                    );
                }

                Ok(nonce_data.to_owned())
            }
            _ => self
                .invalid_proof(session, INVALID_PROOF_ERR_DESC.to_string())
                .fail()?,
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, proof, session),
        err(),
        ret(level = Level::DEBUG),
    )]
    async fn validate_proof_type(
        &self,
        proof: &SpruceProof,
        cred_metadata: &CredDefMetadata,
        session: &mut IssuanceSession,
    ) -> Result<()> {
        trace!(?proof, ?session);

        debug!(?cred_metadata);

        let proof_types = match cred_metadata.proof_types_supported() {
            Some(proof_types) => proof_types,
            _ => &Self::supported_proof_types(),
        };

        let (proof_type, proof) = match proof {
            SpruceProof::JWT { jwt } => (KeyProofType::Jwt, jwt),
            SpruceProof::CWT { cwt } => self
                .invalid_proof(session, "Unsupported proof type: CWT".to_string())
                .fail()?,
        };

        let proof_type = proof_types.get(&proof_type).ok_or_else(|| {
            self.invalid_proof(session, format!("Unsupported proof type: {:?}", proof_type))
                .build()
        })?;

        debug!(resolved_proof_type = ?proof_type);

        let proof_header = jsonwebtoken::decode_header(proof).map_err(|err| {
            error!("Can not retrieve \"alg\" from the proof's header: {err}");
            self.invalid_proof(
                session,
                "Can not retrieve \"alg\" from the proof's header".to_string(),
            )
            .build()
        })?;

        let sign_alg =
            serde_json::from_value(serde_json::to_value(proof_header.alg).context(ParseSnafu)?)
                .context(ParseSnafu)?;
        debug!(resolved_signing_algorithm = %sign_alg);

        ensure!(
            proof_type
                .proof_signing_alg_values_supported
                .contains(&sign_alg),
            self.invalid_proof(
                session,
                format!("Unsupported proof type's signing algorithm: '{sign_alg}'")
            )
        );

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        ret(level = Level::DEBUG),
    )]
    fn supported_proof_types() -> HashMap<KeyProofType, ProofType> {
        HashMap::from([(
            KeyProofType::Jwt,
            ProofType::new(vec!["ES256".to_owned(), "EdDSA".to_owned()]),
        )])
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, token),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn validate_scope(&self, token: &str, cred_def_id: &str, scope: &Scope) -> Result<()> {
        trace!(token_to_validate = %token);

        let scope = scope.to_string();

        let token: Map<String, Value> = decode_unverified(token).map_err(|err| {
            error!("Could not parse the access token: {err}");
            ProtocolSnafu::new(
                ErrorType::InvalidToken,
                "Could not parse the access token".to_string(),
            )
            .build()
        })?;

        if let Some(Value::String(scopes)) = token.get("scope") {
            ensure!(
                scopes.split(' ').any(|s| s == scope),
                ProtocolSnafu::new(
                    ErrorType::InvalidToken,
                    format!(
                        "Access token should have scope=\"{scope}\" for issuing \"{cred_def_id}\""
                    ),
                ),
            );

            return Ok(());
        }

        ProtocolSnafu::new(
            ErrorType::InvalidToken,
            "Access token does not have \"scope\" field".to_string(),
        )
        .fail()?
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, claims),
        err(),
        ret(level = Level::DEBUG),
    )]
    fn validate_claim_names(&self, claims: &Value, cred_metadata: &CredDefMetadata) -> Result<()> {
        trace!(?claims);

        let claim_names: Vec<&str> = match claims {
            Value::Object(claims) => claims.keys().map(|k| k.as_str()).collect(),
            _ => ClaimsValidationSnafu {
                details: "Provided \"claims\" is not json object",
            }
            .fail()?,
        };

        // TODO: Support other formats
        let sd_jwt_vc_metadata = match cred_metadata.additional_fields() {
            CoreProfilesMetadata::SDJWTVC(metadata) => metadata,
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!(
                    "Unsupported credential format: {}",
                    cred_metadata.additional_fields().format()
                ),
            )
            .fail()?,
        };
        debug!(resolved_credential_metadata = ?sd_jwt_vc_metadata);

        let supported_claims = match sd_jwt_vc_metadata.credential_definition().claims() {
            Some(claims) => {
                let mut supported: Vec<&str> = claims.keys().map(|k| k.as_str()).collect();
                supported.push("vct");

                supported
            }

            _ => return Ok(()),
        };
        debug!(?supported_claims);

        let not_supported = claim_names.iter().find(|c| !supported_claims.contains(c));
        if let Some(not_supported) = not_supported {
            ClaimsValidationSnafu {
                details: format!("Unsupported claim name: {not_supported}"),
            }
            .fail()?;
        }

        Ok(())
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
            TokenValidation::Introspect(svc) => svc.validate(token).await.map_err(|_| {
                ProtocolSnafu::new(
                    ErrorType::InvalidToken,
                    "Could not validate the token".to_string(),
                )
                .build()
            })?,
            TokenValidation::ByJwks(svc) => svc.validate(token).await.map_err(|_| {
                ProtocolSnafu::new(
                    ErrorType::InvalidToken,
                    "Could not validate the token".to_string(),
                )
                .build()
            })?,
            TokenValidation::None => {}
        }

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, session),
        ret(level = Level::TRACE),
    )]
    fn invalid_proof(
        &self,
        session: &mut IssuanceSession,
        description: String,
    ) -> ProtocolSnafu<vc::oid4vci::ErrorType, Option<String>, Option<Nonce>, Option<i64>> {
        trace!(?session);

        let nonce_data = NonceData::new_random();
        session.nonce = Some(nonce_data.clone());

        ProtocolSnafu::new_with_nonce(
            ErrorType::InvalidProof,
            description,
            nonce_data.nonce,
            nonce_data.expires_in,
        )
    }

    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE),
    )]
    fn update_cred_resp_and_session_data(
        resp: CredentialResponse,
        session: &mut IssuanceSession,
    ) -> CredentialResponse {
        let nonce_data = NonceData::new_random();
        let notification_id = Uuid::new_v4().to_string();

        session.nonce = Some(nonce_data.clone());
        session.notification_id = Some(notification_id.clone());
        trace!(issuance_session = ?session);

        resp.set_nonce(Some(nonce_data.nonce))
            .set_nonce_expiration(nonce_data.expires_in)
            .set_notification_id(Some(notification_id))
    }
}

impl From<&SpruceProof> for AsdkProof {
    fn from(value: &SpruceProof) -> AsdkProof {
        match value {
            SpruceProof::JWT { jwt } => AsdkProof {
                format: "jwt".to_string(),
                proof: jwt.to_string(),
            },
            SpruceProof::CWT { cwt } => AsdkProof {
                format: "cwt".to_string(),
                proof: cwt.to_owned(),
            },
        }
    }
}

impl From<vc::Credential> for CoreProfilesResponse {
    fn from(value: vc::Credential) -> Self {
        match value {
            vc::Credential::JwtVcJson(cred) => {
                CoreProfilesResponse::JWTVC(w3c::jwt::Response::new(cred))
            }
            vc::Credential::JwtVcJsonLd(_) => {
                CoreProfilesResponse::JWTLDVC(w3c::jwtld::Response {})
            }
            vc::Credential::LdpVc(cred) => {
                CoreProfilesResponse::LDVC(w3c::ldp::Response::new(cred))
            }
            vc::Credential::SdJwt(cred) => {
                CoreProfilesResponse::SDJWTVC(sd_jwt::Response::new(cred))
            }
        }
    }
}

impl NonceData {
    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
    )]
    pub(self) fn new_random() -> Self {
        Self {
            nonce: Nonce::new_random(),
            expires_in: Some(NONCE_EXPIRES_IN),
            created: Some(time::OffsetDateTime::now_utc()),
        }
    }
}
