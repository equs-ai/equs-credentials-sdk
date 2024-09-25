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
use oid4vci::proof_of_possession::Proof as SpruceProof;
use serde_json::{Map, Value};
use snafu::{ensure, ResultExt};
use ssi::jwt::decode_unverified;
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
}

pub struct IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    issuer: IS,
    issuer_metadata: IssuerMetadata,
    token_validation: Option<TokenValidation<HC>>,
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
        token_validation: Option<TokenValidation<HC>>,
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
        ret()
    )]
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret()
    )]
    fn get_cred_def_metadata(&self, cred_request: &CredentialRequest) -> Option<CredDefMetadata> {
        self.resolve_cred_def(cred_request)
            .map(|(_, cred_def)| cred_def)
            .ok()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
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
        skip(self),
        err(),
        ret(),
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

        let cred = match result {
            Err(vc::core::Error::Proof { .. })
            | Err(vc::core::Error::ProofFormatNotSupported { .. }) => self
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
        skip(self),
        err(),
        ret(),
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
        ret(),
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
        ret(),
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
        skip(self),
        err(),
        ret(),
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
        skip(self),
        err(),
        ret(),
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
        skip(self),
        err(),
        ret(),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
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
        ret(),
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
        ret()
    )]
    pub(self) fn new_random() -> Self {
        Self {
            nonce: Nonce::new_random(),
            expires_in: Some(NONCE_EXPIRES_IN),
            created: Some(time::OffsetDateTime::now_utc()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::utils::http::test::mock_http_req_body;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vci::metadata::convert_metadata;
    use crate::vc::oid4vci::tests::fixtures::{
        sample_claims, sample_credential_definition, sample_credential_offer,
        sample_credential_request, SampleIssuerMetadata, ACCESS_TOKEN, CRED_DEF_ID, NONCE, SCOPE,
        TOKEN_INTROSPECT_URL,
    };
    use crate::vc::oid4vci::AuthorizationCodeGrant;
    use crate::vc::oid4vci::Error::Protocol;
    use api::Issuer;
    use oauth2::http::{Method, StatusCode};
    use serde_json::json;

    #[tokio::test]
    async fn issuer_returns_metadata_correctly() {
        let issuer = issuer_service(None, None).await;

        let metadata = issuer.get_issuer_metadata();

        assert_eq!(metadata, SampleIssuerMetadata::with_sdjwtvc_conf());
    }

    #[tokio::test]
    async fn issuer_creates_credential_offer_correctly() {
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
    async fn issuance_succeeds_when_nonce_is_provided() {
        let issuer = issuer_service(None, None).await;

        let iss_result = issuer
            .issue_credential(
                &sample_credential_request(),
                ACCESS_TOKEN,
                &sample_claims(),
                &mut sample_session_with_nonce(),
            )
            .await;

        iss_result.unwrap();
    }

    #[tokio::test]
    async fn issuance_fails_with_invalid_proof_error_when_nonce_is_not_provided() {
        let issuer = issuer_service(None, None).await;

        let iss_result = issuer
            .issue_credential(
                &sample_credential_request(),
                ACCESS_TOKEN,
                &sample_claims(),
                &mut sample_session_without_nonce(),
            )
            .await;

        assert!(matches!(
            iss_result.err().unwrap(),
            Protocol { source } if *source.error_type() == ErrorType::InvalidProof
        ));
    }

    #[tokio::test]
    async fn issuer_requests_token_validity_from_auth_server() {
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
                &sample_credential_request(),
                ACCESS_TOKEN,
                &sample_claims(),
                &mut sample_session_with_nonce(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn issuance_fails_with_invalid_token_error_when_token_is_not_active() {
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
                &sample_credential_request(),
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
    async fn issuer_resolves_credential_definition_correctly() {
        let issuer_service = issuer_service(None, None).await;

        let cred_req = sample_credential_request();
        let (cred_def_id, cred_def_metadata) = issuer_service.resolve_cred_def(&cred_req).unwrap();

        assert_eq!(
            (CRED_DEF_ID.to_owned(), sample_credential_definition()),
            (cred_def_id, cred_def_metadata)
        )
    }

    #[tokio::test]
    async fn issuer_validates_credential_definition_ids_correctly() {
        let issuer_service = issuer_service(None, None).await;

        let cred_def_ids = vec![CRED_DEF_ID];
        let validate_res = issuer_service.validate_cred_def_ids(&cred_def_ids);

        validate_res.unwrap();
    }

    #[tokio::test]
    async fn issuer_validates_nonce_correctly() {
        let issuer_service = issuer_service(None, None).await;

        let mut session = sample_session_with_nonce();
        let nonce_data = session.nonce.clone().unwrap();
        let nonce_data_to_check = issuer_service.validate_nonce(&mut session).unwrap();

        assert_eq!(nonce_data_to_check, nonce_data);
    }

    #[tokio::test]
    async fn issuer_validates_scope_correctly() {
        let issuer_service = issuer_service(None, None).await;
        let scope = Scope::new(SCOPE.to_owned());

        let validate_res = issuer_service.validate_scope(ACCESS_TOKEN, CRED_DEF_ID, &scope);

        validate_res.unwrap()
    }

    #[tokio::test]
    async fn issuer_validates_claim_names_correctly() {
        let issuer_service = issuer_service(None, None).await;

        let claims = json!({
            "given_name": "Bois",
            "family_name": "Tursunov"
        });
        let cred_def = sample_credential_definition();

        let validate_res = issuer_service.validate_claim_names(&claims, &cred_def);

        validate_res.unwrap()
    }

    fn sample_session_with_nonce() -> IssuanceSession {
        let mut session = IssuanceSession::default();

        let nonce_data: NonceData = serde_json::from_value(json!(
            {
                "nonce": NONCE,
                "expires_in": 86440,
                "created": null
            }
        ))
        .unwrap();

        session.nonce = Some(nonce_data);
        session
    }

    fn sample_session_without_nonce() -> IssuanceSession {
        IssuanceSession::default()
    }

    async fn issuer_service(
        http_client: Option<MockHttpClient>,
        token_validation: Option<TokenValidation<MockHttpClient>>,
    ) -> IssuerService<impl vc::core::Issuer, impl HttpClient> {
        let kms = LocalKms::new();
        let introspect = Introspect::new(
            http_client.unwrap_or_default(),
            Url::parse(TOKEN_INTROSPECT_URL).unwrap(),
            None,
        );

        let issuer_metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let issuer_metadata_inner =
            convert_metadata(&issuer_metadata, &Default::default(), &key_metadata).unwrap();

        let inner = vc::core::IssuerService::new(kms, issuer_metadata_inner);

        IssuerService::new(issuer_metadata, inner, token_validation)
    }
}
