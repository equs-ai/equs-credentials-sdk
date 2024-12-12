use crate::http::HttpClient;
use crate::nonce::{Nonce, NonceData, NonceGenerator};
use crate::vc;
use crate::vc::core::{CredentialRequestData, Proof as AsdkProof, Proof};
use crate::vc::formats::sd_jwt_vc::{EXP_CLAIM, IAT_CLAIM, NBF_CLAIM, VCT_CLAIM};
use crate::vc::oid4vci::internal_error::{
    ClaimsValidationSnafu, NoScopeSetSnafu, NonceGenerationSnafu, ParseSnafu, UrlParseSnafu,
    VCSnafu,
};
use crate::vc::oid4vci::protocol_error::ProtocolSnafu;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};
use crate::vc::oid4vci::{
    CredDefMetadata, CredentialOfferParams, CredentialRequest, CredentialResponse, IssuanceSession,
    IssuerMetadata,
};
use crate::vc::{oid4vci as api, pop, Claims, HasVCFormat};
use async_trait::async_trait;
use oauth2::Scope;
use oid4vci::core::profiles::{
    sd_jwt, w3c, CoreProfilesMetadata, CoreProfilesOffer, CoreProfilesRequest, CoreProfilesResponse,
};
use oid4vci::credential::{ErrorType, ResponseEnum};
use oid4vci::credential_offer::{
    CredentialOfferFormat, CredentialOfferGrants, CredentialOfferParameters,
};
use oid4vci::openidconnect;
use oid4vci::proof_of_possession::Proof as SpruceProof;
use serde_json::{Map, Value};
use snafu::{ensure, ResultExt};
use ssi::jwt::decode_unverified;
use time::Duration;
use tracing::{debug, error, info, instrument, trace, warn, Level};
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
}

pub struct IssuerService<IS, HC, NG>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
    NG: NonceGenerator,
{
    issuer: IS,
    nonce_generator: NG,
    issuer_metadata: IssuerMetadata,
    token_validation: Option<TokenValidation<HC>>,
    clock_skew: Option<Duration>,
}

impl<IS, HC, NG> IssuerService<IS, HC, NG>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
    NG: NonceGenerator,
{
    #[instrument(level = Level::TRACE, skip(issuer, nonce_generator, token_validation))]
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: IS,
        nonce_generator: NG,
        token_validation: Option<TokenValidation<HC>>,
        clock_skew: Option<Duration>,
    ) -> Self {
        info!("oid4vci-issuer service is initialized");

        Self {
            issuer,
            nonce_generator,
            issuer_metadata,
            token_validation,
            clock_skew,
        }
    }
}

#[async_trait]
impl<IS, HC, NG> api::Issuer for IssuerService<IS, HC, NG>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
    NG: NonceGenerator,
{
    #[instrument(level = Level::TRACE, skip_all, ret())]
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    fn get_cred_def_metadata(&self, cred_request: &CredentialRequest) -> Option<CredDefMetadata> {
        self.resolve_cred_def(cred_request)
            .map(|(_, cred_def)| cred_def)
            .ok()
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
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

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
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
        info!("access token is validated");

        let nonce = self.validate_nonce(session).await?;
        info!("nonce is validated");

        let proof = if let Some(proof) = cred_request.proof() {
            proof
        } else {
            self.invalid_proof(session, INVALID_PROOF_ERR_DESC)
                .await?
                .fail()?
        };

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

        let proof = Proof::from(proof);

        let cred_req = vc::core::CredentialRequest {
            cred_def_id,
            proof,
            protocol_data: self.resolve_cred_req_protocol_data(),
            cred_offer_id: None,
        };

        let result = self
            .issuer
            .issue_credential(&cred_req, claims, &nonce.value)
            .await;

        let cred = match result {
            Err(vc::core::Error::Proof { source, .. }) => {
                self.resolve_pop_protocol_error(source, session).await?.fail()?
            }
            Err(vc::core::Error::ProofFormatNotSupported { format }) => self
                .invalid_proof(
                    session,
                    &format!("proof of possession with '{format}' format is not supported. {INVALID_PROOF_ERR_DESC}"),
                )
                .await?
                .fail()?,
            _ => result.context(VCSnafu)?,
        };

        let mut resp = CredentialResponse::new(ResponseEnum::Immediate(cred.into()));
        resp = self
            .update_cred_resp_and_session_data(resp, session)
            .await?;

        info!("credential is issued");

        Ok(resp)
    }
}

impl<IS, HC, NG> IssuerService<IS, HC, NG>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
    NG: NonceGenerator,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_cred_def(&self, req: &CredentialRequest) -> Result<(String, CredDefMetadata)> {
        trace!(credential_request = ?req);

        match req.additional_profile_fields() {
            CoreProfilesRequest::SDJWTVC(_) => (),
            CoreProfilesRequest::LDVC(_) => (),
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
                    if let CoreProfilesRequest::SDJWTVC(det) = req.additional_profile_fields() {
                        return metadata.vct() == det.vct();
                    }
                }

                if let CoreProfilesMetadata::LDVC(metadata) = cred_metadata.additional_fields() {
                    if let CoreProfilesRequest::LDVC(det) = req.additional_profile_fields() {
                        return det.credential_definition().credential_definition().r#type()
                            == metadata
                                .credentials_definition()
                                .credential_definition()
                                .r#type();
                    }
                }

                false
            })
            .ok_or(
                ProtocolSnafu::new(
                    ErrorType::UnsupportedCredentialType,
                    "Credential configuration id is not found".to_string(),
                )
                .build(),
            )?;

        Ok((cred_def_id.to_owned(), cred_metadata.to_owned()))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
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

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn validate_nonce(&self, session: &mut IssuanceSession) -> Result<NonceData> {
        match &session.nonce {
            Some(nonce) => {
                ensure!(
                    !nonce.is_expired(),
                    self.invalid_proof(session, INVALID_PROOF_ERR_DESC).await?
                );

                Ok(nonce.to_owned())
            }
            _ => self
                .invalid_proof(session, INVALID_PROOF_ERR_DESC)
                .await?
                .fail()?,
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
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

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn validate_claim_names(&self, claims: &Value, cred_metadata: &CredDefMetadata) -> Result<()> {
        trace!(?claims);

        let claim_names: Vec<&str> = match claims {
            Value::Object(claims) => claims.keys().map(|k| k.as_str()).collect(),
            _ => ClaimsValidationSnafu {
                details: "Provided \"claims\" is not json object",
            }
            .fail()?,
        };

        // TODO: split it into two parts: required/optional claims
        let supported_claims = match cred_metadata.additional_fields() {
            CoreProfilesMetadata::SDJWTVC(metadata) => {
                debug!(resolved_credential_metadata = ?metadata);

                match metadata.claims() {
                    Some(claims) => {
                        let mut supported: Vec<&str> = claims.keys().map(|k| k.as_str()).collect();
                        supported.extend_from_slice(&[VCT_CLAIM, NBF_CLAIM, IAT_CLAIM, EXP_CLAIM]);

                        supported
                    }

                    _ => return Ok(()),
                }
            }
            CoreProfilesMetadata::LDVC(metadata) => {
                debug!(resolved_credential_metadata = ?metadata);

                let mut supported: Vec<&str> = metadata
                    .credentials_definition()
                    .credential_definition()
                    .credential_subject()
                    .ok_or_else(|| {
                        ClaimsValidationSnafu {
                            details: "Credential definition does not include claims",
                        }
                        .build()
                    })?
                    .keys()
                    .map(|k| k.as_str())
                    .collect();

                supported.push("type");

                supported
            }
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!(
                    "Unsupported credential format: {}",
                    cred_metadata.additional_fields().format()
                ),
            )
            .fail()?,
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

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    pub async fn validate_token(&self, token: &str) -> Result<()> {
        match &self.token_validation {
            Some(TokenValidation::Introspect(svc)) => svc.validate(token).await.map_err(|_| {
                ProtocolSnafu::new(
                    ErrorType::InvalidToken,
                    "Could not validate the token".to_string(),
                )
                .build()
            })?,
            Some(TokenValidation::ByJwks(svc)) => svc.validate(token).await.map_err(|_| {
                ProtocolSnafu::new(
                    ErrorType::InvalidToken,
                    "Could not validate the token".to_string(),
                )
                .build()
            })?,
            None => {}
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn invalid_proof(
        &self,
        session: &mut IssuanceSession,
        description: &str,
    ) -> Result<
        ProtocolSnafu<vc::oid4vci::ErrorType, Option<String>, Option<Nonce>, Option<Duration>>,
    > {
        trace!(?session);

        let nonce = self
            .nonce_generator
            .with_expiration(Duration::seconds(NONCE_EXPIRES_IN))
            .await
            .context(NonceGenerationSnafu)?;
        session.nonce = Some(nonce.clone());

        let protocol_error = ProtocolSnafu::new_with_nonce(
            ErrorType::InvalidProof,
            description,
            &nonce.value,
            &nonce.expires_in,
        );

        Ok(protocol_error)
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn update_cred_resp_and_session_data(
        &self,
        resp: CredentialResponse,
        session: &mut IssuanceSession,
    ) -> Result<CredentialResponse> {
        let nonce = self
            .nonce_generator
            .with_expiration(Duration::seconds(NONCE_EXPIRES_IN))
            .await
            .context(NonceGenerationSnafu)?;
        session.nonce = Some(nonce.clone());

        let notification_id = Uuid::new_v4().to_string();
        session.notification_id = Some(notification_id.clone());
        trace!(issuance_session = ?session);

        let resp = resp
            .set_nonce(Some(openidconnect::Nonce::new(nonce.secret().to_owned())))
            .set_nonce_expiration(nonce.expires_in.map(|d| d.whole_seconds()))
            .set_notification_id(Some(notification_id));

        Ok(resp)
    }

    #[allow(clippy::type_complexity)]
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn resolve_pop_protocol_error(
        &self,
        proof_err: pop::Error,
        session: &mut IssuanceSession,
    ) -> Result<
        ProtocolSnafu<vc::oid4vci::ErrorType, Option<String>, Option<Nonce>, Option<Duration>>,
    > {
        if let pop::Error::Verification { source, .. } = proof_err {
            return self
                .invalid_proof(session, &format!("{}. {INVALID_PROOF_ERR_DESC}", source))
                .await;
        }

        self.invalid_proof(session, INVALID_PROOF_ERR_DESC).await
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    fn resolve_cred_req_protocol_data(&self) -> Option<CredentialRequestData> {
        if let Some(duration) = self.clock_skew {
            return Some(CredentialRequestData {
                proof_tolerance: Some(duration),
            });
        }

        None
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Add;

    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::utils::http::test::mock_http_req_body;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
    use crate::vc::oid4vci::issuer::TokenValidation::ByJwks;
    use crate::vc::oid4vci::metadata::convert_metadata;
    use crate::vc::oid4vci::tests::fixtures::{
        sample_claims, sample_credential_definition, sample_credential_offer,
        SampleCredentialRequest, SampleIssuerMetadata, ACCESS_TOKEN, ACCESS_TOKEN_WITHOUT_SCOPE,
        AUTH_URL, CRED_DEF_ID, ISSUER_URL, JWKS_URL, NONCE, SAMPLE_PROOF_JWT, SCOPE,
        TOKEN_INTROSPECT_URL,
    };
    use crate::vc::oid4vci::Error::Protocol;
    use crate::vc::oid4vci::{token_validation, AuthorizationCodeGrant};
    use api::Issuer;
    use oauth2::http::{Method, StatusCode};
    use oid4vci::openidconnect::JsonWebKeySetUrl;
    use rstest::rstest;
    use serde_json::json;
    use time::OffsetDateTime;

    #[tokio::test]
    async fn get_issuer_metadata_returns_correct_data() {
        let issuer = issuer_service(None, None).await;

        let metadata = issuer.get_issuer_metadata();

        assert_eq!(metadata, SampleIssuerMetadata::with_sdjwtvc_conf());
    }

    #[tokio::test]
    async fn create_credential_offer_returns_correct_data() {
        let issuer = issuer_service(None, None).await;

        let offer = issuer
            .create_credential_offer(
                vec![CRED_DEF_ID],
                &CredentialOfferGrants {
                    authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
                    pre_authorized_code: None,
                },
            )
            .unwrap();

        assert_eq!(
            serde_json::to_value(offer.0).unwrap(),
            sample_credential_offer()
        );
    }

    #[tokio::test]
    async fn issue_credential_succeeds_when_nonce_is_provided() {
        let issuer = issuer_service(None, None).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                &mut sample_session_with_nonce(),
            )
            .await;

        iss_result.unwrap();
    }

    #[tokio::test]
    async fn issue_credential_succeeds_when_time_based_claims_are_provided() {
        let issuer = issuer_service(None, None).await;
        let mut claims = sample_claims().as_object_mut().unwrap().to_owned();

        let exp = OffsetDateTime::now_utc()
            .add(Duration::days(365))
            .unix_timestamp();
        let nbf = OffsetDateTime::now_utc()
            .add(Duration::days(1))
            .unix_timestamp();
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        claims.insert(EXP_CLAIM.to_string(), serde_json::Value::from(exp));
        claims.insert(NBF_CLAIM.to_string(), serde_json::Value::from(nbf));
        claims.insert(IAT_CLAIM.to_string(), serde_json::Value::from(iat));

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &serde_json::Value::Object(claims.to_owned()),
                &mut sample_session_with_nonce(),
            )
            .await;

        let resp = iss_result.unwrap();

        if let ResponseEnum::Immediate(CoreProfilesResponse::SDJWTVC(resp)) =
            resp.additional_profile_fields()
        {
            let claims_str = SdJwtAPI::strip_disclosures(resp.credential()).unwrap();
            let claims: Map<String, Value> = decode_unverified(claims_str).unwrap();
            assert_eq!(claims.get(EXP_CLAIM).unwrap(), exp);
            assert_eq!(claims.get(NBF_CLAIM).unwrap(), nbf);
            assert_eq!(claims.get(IAT_CLAIM).unwrap(), iat);
        } else {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn issue_credential_fails_with_invalid_proof_error_when_nonce_is_not_provided() {
        let issuer = issuer_service(None, None).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                &mut IssuanceSession::default(),
            )
            .await;

        assert!(matches!(
            iss_result.err().unwrap(),
            Protocol { source } if *source.error_type() == ErrorType::InvalidProof
        ));
    }

    #[tokio::test]
    async fn issue_credential_succeeds_requesting_token_validity_from_auth_server() {
        let mut http_client = MockHttpClient::new();
        let token_intro_url = Url::parse(TOKEN_INTROSPECT_URL).unwrap();

        mock_http_req_body(
            &mut http_client,
            Method::POST,
            token_intro_url.clone(),
            format!("token={}", ACCESS_TOKEN),
            json!({
                  "active": true,
            }),
            StatusCode::OK,
            1.into(),
        );

        let token_validator =
            TokenValidation::Introspect(Introspect::new(http_client, token_intro_url, None));
        let issuer = issuer_service(None, Some(token_validator)).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                &mut sample_session_with_nonce(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn issue_credential_fails_with_invalid_token_error_when_token_is_not_active() {
        let mut http_client = MockHttpClient::new();
        let token_intro_url = Url::parse(TOKEN_INTROSPECT_URL).unwrap();

        mock_http_req_body(
            &mut http_client,
            Method::POST,
            Url::parse(TOKEN_INTROSPECT_URL).unwrap(),
            format!("token={}", ACCESS_TOKEN),
            json!({
                  "active": false,
            }),
            StatusCode::OK,
            1.into(),
        );

        let token_validator =
            TokenValidation::Introspect(Introspect::new(http_client, token_intro_url, None));
        let issuer = issuer_service(None, Some(token_validator)).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                &mut sample_session_with_nonce(),
            )
            .await;

        assert!(matches!(
            iss_result.err().unwrap(),
            Protocol { source } if *source.error_type() == ErrorType::InvalidToken
        ));
    }

    #[tokio::test]
    async fn resolve_cred_def_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None).await;

        let cred_req = SampleCredentialRequest::with_sdjwtvc_conf();
        let (cred_def_id, cred_def_metadata) = issuer_service.resolve_cred_def(&cred_req).unwrap();

        assert_eq!(
            (CRED_DEF_ID.to_owned(), sample_credential_definition()),
            (cred_def_id, cred_def_metadata)
        )
    }

    #[tokio::test]
    async fn validate_cred_def_ids_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None).await;

        let cred_def_ids = vec![CRED_DEF_ID];
        let validate_res = issuer_service.validate_cred_def_ids(&cred_def_ids);

        validate_res.unwrap();
    }

    #[tokio::test]
    async fn validate_nonce_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None).await;

        let mut session = sample_session_with_nonce();
        let nonce_data = session.nonce.clone().unwrap();
        let nonce_data_to_check = issuer_service.validate_nonce(&mut session).await.unwrap();

        assert_eq!(nonce_data_to_check, nonce_data);
    }

    #[tokio::test]
    async fn validate_scope_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None).await;
        let scope = Scope::new(SCOPE.to_owned());

        let validate_res = issuer_service.validate_scope(ACCESS_TOKEN, CRED_DEF_ID, &scope);

        validate_res.unwrap()
    }

    #[tokio::test]
    async fn validate_claim_names_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None).await;

        let claims = json!({
            "given_name": "Bois",
            "family_name": "Tursunov"
        });
        let cred_def = sample_credential_definition();

        let validate_res = issuer_service.validate_claim_names(&claims, &cred_def);

        validate_res.unwrap()
    }

    #[rstest]
    #[case(SampleCredentialRequest::with_jwtvcjson_conf())]
    #[case(SampleCredentialRequest::with_jwtldvc_conf())]
    #[case(SampleCredentialRequest::with_ldpvc_conf())]
    #[case(SampleCredentialRequest::with_msomdoc_conf())]
    #[tokio::test]
    async fn get_cred_def_metadata_returns_none_on_unsupported_credential_format(
        #[case] credential_request: CredentialRequest,
    ) {
        let issuer_service = issuer_service(None, None).await;
        let result = issuer_service.get_cred_def_metadata(&credential_request);
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_cred_def_metadata_returns_none_on_incorrect_sd_jwt_cred() {
        let issuer_service = issuer_service(None, None).await;
        let cred_req = sample_sdjwtvc_credential_request_with_fake_vct();
        let result = issuer_service.get_cred_def_metadata(&cred_req);
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn validate_token_does_nothing_on_token_validation_being_none() {
        let issuer = issuer_service(None, None).await;
        issuer.validate_token("").await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Missed credential configuration ids")]
    async fn create_credential_offer_fails_on_empty_cred_def_ids() {
        let issuer_service = issuer_service(None, None).await;
        let grants = create_empty_credential_offer_grants();
        issuer_service
            .create_credential_offer(vec![], &grants)
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported Credential definition ID: fake_cred_def_id")]
    async fn create_credential_offer_fails_on_not_matching_cred_def_ids() {
        let issuer_service = issuer_service(None, None).await;
        let grants = create_empty_credential_offer_grants();
        issuer_service
            .create_credential_offer(vec![CRED_DEF_ID, "fake_cred_def_id"], &grants)
            .unwrap();
    }

    #[rstest]
    #[case::sync_case(IssuanceSession::default())]
    #[case::async_case(sample_session_with_expired_nonce().await)]
    #[tokio::test]
    #[should_panic(
        expected = "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."
    )]
    async fn issue_credential_fails_on_invalid_sessions_nonce(
        #[case] mut session: IssuanceSession,
    ) {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = json!({});
        let issuer_service = issuer_service(None, None).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, &mut session)
            .await
            .unwrap();
    }

    #[rstest]
    #[case(SampleCredentialRequest::with_jwtvcjson_conf())]
    #[case(SampleCredentialRequest::with_jwtldvc_conf())]
    #[case(SampleCredentialRequest::with_ldpvc_conf())]
    #[case(SampleCredentialRequest::with_msomdoc_conf())]
    #[tokio::test]
    #[should_panic(
        expected = "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."
    )]
    async fn issue_credential_fails_on_unsupported_format(
        #[case] credential_request: CredentialRequest,
    ) {
        let claims = json!({});
        let mut session = sample_session_with_nonce();

        let issuer_service = issuer_service(None, None).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, &mut session)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Credential configuration id is not found")]
    async fn issue_credential_fails_on_incorrect_cred_def() {
        let credential_request = sample_sdjwtvc_credential_request_with_fake_vct();
        let claims = json!({});
        let mut session = sample_session_with_nonce();

        let issuer_service = issuer_service(None, None).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, &mut session)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "No scope set for Credential definition ID: SD_JWT_cred_sample. Only scope authorization supported"
    )]
    async fn issue_credential_fails_on_absent_scope() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = json!({});
        let mut session = sample_session_with_nonce();

        let issuer_service =
            issuer_service_with_metadata(None, None, sample_issuer_metadata_without_scope()).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, &mut session)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Could not parse the access token")]
    async fn issue_credential_fails_on_non_decodable_token() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = json!({});
        let mut session = sample_session_with_nonce();

        let issuer_service = issuer_service(None, None).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, &mut session)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "Access token should have scope=\\\"fake_scope\\\" for issuing \\\"SD_JWT_cred_sample\\\""
    )]
    async fn issue_credential_fails_on_incorrect_scope() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = json!({});
        let mut session = sample_session_with_nonce();

        let issuer_service =
            issuer_service_with_metadata(None, None, sample_issuer_metadata_with_incorrect_scope())
                .await;
        issuer_service
            .issue_credential(&credential_request, ACCESS_TOKEN, &claims, &mut session)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Access token does not have \\\"scope\\\" field")]
    async fn issue_credential_fails_on_absent_token_scope() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = json!({});
        let mut session = sample_session_with_nonce();

        let issuer_service = issuer_service(None, None).await;
        issuer_service
            .issue_credential(
                &credential_request,
                ACCESS_TOKEN_WITHOUT_SCOPE,
                &claims,
                &mut session,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case(json!("[0,1,2]"))]
    #[case(json!("1"))]
    #[case(json!("true"))]
    #[case(json!("string_value"))]
    #[case(json!(null))]
    #[tokio::test]
    #[should_panic(expected = "Claims validation error: Provided \"claims\" is not json object")]
    async fn issue_credential_fails_on_non_json_claims(#[case] claims: Value) {
        let issuer = issuer_service(None, None).await;
        issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &claims,
                &mut sample_session_with_nonce(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported claim name: unsupported_key")]
    async fn issue_credential_fails_on_claims_having_unsupported_key() {
        let claims = json!({"unsupported_key": "unsupported_keys_value"});

        let issuer = issuer_service(None, None).await;
        issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &claims,
                &mut sample_session_with_nonce(),
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case(sample_sdjwtvc_credential_request_with_cwt_proof_format())]
    #[case(sample_sdjwtvc_credential_request_with_empty_proofs_jwt())]
    #[case(sample_sdjwtvc_credential_request_without_proof())]
    #[tokio::test]
    #[should_panic(
        expected = "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."
    )]
    async fn issue_credential_fails_on_invalid_proof(
        #[case] credential_request: CredentialRequest,
    ) {
        let claims = json!({});

        let issuer = issuer_service(None, None).await;
        issuer
            .issue_credential(
                &credential_request,
                ACCESS_TOKEN,
                &claims,
                &mut sample_session_with_nonce(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Could not validate the token")]
    async fn validate_token_fails_on_incorrect_http_response() {
        let mut http_client = MockHttpClient::new();

        mock_http_req_body(
            &mut http_client,
            Method::GET,
            Url::parse(JWKS_URL).unwrap(),
            "".to_string(),
            json!({}),
            StatusCode::OK,
            1.into(),
        );

        let token_validator = ByJwks(token_validation::ByJwks::new(
            http_client,
            JsonWebKeySetUrl::new(JWKS_URL.to_string()).unwrap(),
        ));
        let issuer = issuer_service(None, Some(token_validator)).await;
        issuer.validate_token("").await.unwrap();
    }

    fn sample_session_with_nonce() -> IssuanceSession {
        let mut session = IssuanceSession::default();
        let created_time = OffsetDateTime::now_utc().unix_timestamp();
        let nonce_data: NonceData = serde_json::from_value(json!(
            {
                "value": NONCE,
                "expires_in": NONCE_EXPIRES_IN,
                "created": created_time
            }
        ))
        .unwrap();

        session.nonce = Some(nonce_data);
        session
    }

    async fn sample_session_with_expired_nonce() -> IssuanceSession {
        let nonce_gen = LocalNonceGenerator::default();
        let nonce = nonce_gen
            .with_expiration(Duration::seconds(0))
            .await
            .unwrap();
        IssuanceSession {
            nonce: Some(nonce),
            notification_id: None,
            transaction_id: None,
        }
    }

    async fn issuer_service(
        http_client: Option<MockHttpClient>,
        token_validation: Option<TokenValidation<MockHttpClient>>,
    ) -> IssuerService<impl vc::core::Issuer, impl HttpClient, impl NonceGenerator> {
        issuer_service_with_metadata(
            http_client,
            token_validation,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await
    }

    async fn issuer_service_with_metadata(
        http_client: Option<MockHttpClient>,
        token_validation: Option<TokenValidation<MockHttpClient>>,
        issuer_metadata: IssuerMetadata,
    ) -> IssuerService<impl vc::core::Issuer, impl HttpClient, impl NonceGenerator> {
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceGenerator::default();
        let introspect = Introspect::new(
            http_client.unwrap_or_default(),
            Url::parse(TOKEN_INTROSPECT_URL).unwrap(),
            None,
        );

        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let issuer_metadata_inner =
            convert_metadata(&issuer_metadata, &Default::default(), &key_metadata).unwrap();

        let inner = vc::core::IssuerService::new(kms, issuer_metadata_inner);

        IssuerService::new(issuer_metadata, inner, nonce_gen, token_validation, None)
    }

    fn sample_sdjwtvc_credential_request_with_fake_vct() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_identifier": CRED_DEF_ID,
                "format":"vc+sd-jwt",
                "vct":"fake_sd_jwt_cred",
                "proof":{
                    "proof_type":"jwt",
                    "jwt":SAMPLE_PROOF_JWT
                },
                "credential_response_encryption":null
            }
        ))
        .unwrap()
    }

    fn sample_sdjwtvc_credential_request_with_empty_proofs_jwt() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_identifier": CRED_DEF_ID,
                "format":"vc+sd-jwt",
                "vct":"SD_JWT_cred",
                "proof":{
                    "proof_type":"jwt",
                    "jwt":""
                },
                "credential_response_encryption":null
            }
        ))
        .unwrap()
    }

    fn sample_sdjwtvc_credential_request_with_cwt_proof_format() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_identifier": CRED_DEF_ID,
                "format":"vc+sd-jwt",
                "vct":"SD_JWT_cred",
                "proof":{
                    "proof_type":"cwt",
                    "cwt":SAMPLE_PROOF_JWT
                },
                "credential_response_encryption":null
            }
        ))
        .unwrap()
    }

    fn sample_sdjwtvc_credential_request_without_proof() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_identifier": CRED_DEF_ID,
                "format":"vc+sd-jwt",
                "vct":"fake_sd_jwt_cred",
                "credential_response_encryption":null
            }
        ))
        .unwrap()
    }

    fn sample_issuer_metadata_without_scope() -> IssuerMetadata {
        serde_json::from_value(json!(
            {
                "credential_issuer": ISSUER_URL,
                "authorization_servers": [AUTH_URL],
                "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                "credential_configurations_supported": {
                    CRED_DEF_ID: {
                    "format": "vc+sd-jwt",
                    "vct": "SD_JWT_cred",
                    "claims": {},
                    },
                },
            }
        ))
        .unwrap()
    }

    fn sample_issuer_metadata_with_incorrect_scope() -> IssuerMetadata {
        serde_json::from_value(json!(
            {
                "credential_issuer": ISSUER_URL,
                "authorization_servers": [AUTH_URL],
                "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                "credential_configurations_supported": {
                    CRED_DEF_ID: {
                    "format": "vc+sd-jwt",
                    "vct": "SD_JWT_cred",
                    "scope": "fake_scope",
                    "claims": {},
                    },
                },
            }
        ))
        .unwrap()
    }

    fn create_empty_credential_offer_grants() -> CredentialOfferGrants {
        CredentialOfferGrants {
            authorization_code: None,
            pre_authorized_code: None,
        }
    }
}
