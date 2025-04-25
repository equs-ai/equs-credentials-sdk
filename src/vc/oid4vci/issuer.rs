use crate::http::HttpClient;
use crate::nonce::{Nonce, NonceHandler};
use crate::vc;
use crate::vc::claims::Claims;
use crate::vc::core::api::CredentialStatusInfo;
use crate::vc::core::{CredentialRequestData, Proof as AsdkProof, Proof};
use crate::vc::formats::sd_jwt_vc::{EXP_CLAIM, IAT_CLAIM, NBF_CLAIM, VCT_CLAIM};
use crate::vc::oid4vci::internal_error::{
    ClaimsValidationSnafu, IssuerServiceSnafu, NoScopeSetSnafu, NonceHandlerSnafu, ParseSnafu,
    TypeConversionSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::protocol_error::ProtocolSnafu;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};
use crate::vc::oid4vci::{
    CredDefMetadata, CredentialOfferParams, CredentialRequest, CredentialResponse, IssuerMetadata,
    NonceResponse,
};
use crate::vc::{oid4vci as api, pop, HasVCFormat};
use async_trait::async_trait;
use oauth2::Scope;
use oid4vci::core::profiles::{
    CoreProfilesCredentialConfiguration, CoreProfilesCredentialRequest,
    CoreProfilesCredentialResponseType,
};
use oid4vci::credential::{ErrorType, Response, ResponseEnum};
use oid4vci::credential_offer::{CredentialOfferGrants, CredentialOfferParameters};
use oid4vci::proof_of_possession::{Proof as SpruceProof, ProofOfPossession};
use oid4vci::types::CredentialConfigurationId;
use serde_json::{Map, Value};
use snafu::{ensure, ResultExt};
use ssi::claims::jwt::decode_unverified;
use ssi::claims::JwsBuf;
use std::str::FromStr;
use time::Duration;
use tracing::{debug, error, info, instrument, trace, warn, Level};
use url::Url;

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

pub struct IssuerService<IS, HC, NH>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
    NH: NonceHandler,
{
    issuer: IS,
    nonce_handler: Option<NH>,
    issuer_metadata: IssuerMetadata,
    token_validation: Option<TokenValidation<HC>>,
    clock_skew: Option<Duration>,
}

impl<IS, HC, NH> IssuerService<IS, HC, NH>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
    NH: NonceHandler,
{
    #[instrument(level = Level::TRACE, skip(issuer, nonce_generator, token_validation))]
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: IS,
        nonce_generator: Option<NH>,
        token_validation: Option<TokenValidation<HC>>,
        clock_skew: Option<Duration>,
    ) -> Self {
        info!("oid4vci-issuer service is initialized");

        Self {
            issuer,
            nonce_handler: nonce_generator,
            issuer_metadata,
            token_validation,
            clock_skew,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<IS, HC, NH> api::Issuer for IssuerService<IS, HC, NH>
where
    IS: vc::core::Issuer,
    HC: HttpClient + 'static,
    NH: NonceHandler,
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

    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn generate_nonce(&self) -> Result<NonceResponse> {
        info!("generation of nonce is started");

        let Some(nonce_handler) = self.nonce_handler.as_ref() else {
            IssuerServiceSnafu {
                details: "Could not generate a nonce. Nonce Handler is not provided",
            }
            .fail()?
        };

        let nonce = nonce_handler.generate().await.context(NonceHandlerSnafu)?;

        info!("a fresh nonce is generated");

        Ok(NonceResponse::new(oid4vci::types::Nonce::new(
            nonce.secret().to_string(),
        )))
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

        let cred_offer_params = CredentialOfferParameters {
            credential_issuer: self.issuer_metadata.credential_issuer().clone(),
            credential_configuration_ids: cred_def_ids
                .iter()
                .map(|c| CredentialConfigurationId::new(c.to_string()))
                .collect(),
            grants: Some(grants.to_owned()),
        };

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
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<CredentialResponse> {
        info!("issuance of credential is started");
        trace!(credential_request = ?cred_request, %token, claims_to_issue = ?claims);

        self.validate_token(token).await?;
        info!("access token is validated");

        let proof = if let Some(proof) = cred_request.proof() {
            proof
        } else {
            ProtocolSnafu::new(ErrorType::InvalidProof, INVALID_PROOF_ERR_DESC.to_string())
                .fail()?
        };
        let nonce = self.resolve_and_validate_nonce(proof).await?;

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
            .issue_credential(&cred_req, claims, nonce, status_info)
            .await;

        let credential = match result {
                Err(vc::core::Error::Proof { source, .. }) => {
                    debug!("Proof of possession verification error: {}", source.to_string());
                    self.resolve_pop_protocol_error(source).fail()?
                }
                Err(vc::core::Error::ProofFormatNotSupported { format }) =>
                    ProtocolSnafu::new(
                        ErrorType::InvalidProof,
                        format!("proof of possession with '{format}' format is not supported. {INVALID_PROOF_ERR_DESC}")
                    )
                    .fail()?,
                _ => result.context(VCSnafu)?,
            };

        let resp = Response::new(ResponseEnum::Immediate {
            credentials: vec![credential.try_into()?],
        });

        info!("credential is issued");

        Ok(resp)
    }
}

impl<IS, HC, NH> IssuerService<IS, HC, NH>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
    NH: NonceHandler,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_cred_def(&self, req: &CredentialRequest) -> Result<(String, CredDefMetadata)> {
        trace!(credential_request = ?req);

        let result = match req.additional_profile_fields() {
            CoreProfilesCredentialRequest::Default { inner, .. } => match inner {
                oid4vci::core::profiles::CredentialRequest::VcSdJwt(sd_jwt_req) => self
                    .issuer_metadata
                    .credential_configurations_supported()
                    .iter()
                    .find(|cred_metadata| {
                        let CoreProfilesCredentialConfiguration::VcSdJwt(supported) =
                            cred_metadata.profile_specific_fields()
                        else {
                            return false;
                        };

                        supported.vct() == sd_jwt_req.vct()
                    }),
                oid4vci::core::profiles::CredentialRequest::LdpVc(ldp_req) => self
                    .issuer_metadata
                    .credential_configurations_supported()
                    .iter()
                    .find(|cred_metadata| {
                        let CoreProfilesCredentialConfiguration::LdpVc(supported) =
                            cred_metadata.profile_specific_fields()
                        else {
                            return false;
                        };

                        supported.credential_definition().r#type()
                            == ldp_req.credential_definition().r#type()
                    }),
                _ => ProtocolSnafu::new(
                    ErrorType::UnsupportedCredentialFormat,
                    format!("Unsupported credential format: {:#?}", inner.format()),
                )
                .fail()?,
            },
            _ => ProtocolSnafu::new(
                ErrorType::InvalidCredentialRequest,
                "Credential request with credential configuration id is not supported".to_string(),
            )
            .fail()?,
        }
        .ok_or(
            ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialType,
                "Credential configuration id is not found".to_string(),
            )
            .build(),
        )?;

        Ok((result.id().to_string().to_owned(), result.to_owned()))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn validate_cred_def_ids(&self, cred_def_ids: &Vec<&str>) -> Result<()> {
        ensure!(
            !cred_def_ids.is_empty(),
            ProtocolSnafu::new(
                ErrorType::InvalidCredentialRequest,
                "Missed credential configuration ids".to_string()
            )
        );

        let supported: Vec<CredentialConfigurationId> = self
            .issuer_metadata
            .credential_configurations_supported()
            .iter()
            .map(|c| c.id())
            .map(|e| e.to_owned())
            .collect();

        debug!(supported_credential_definition_ids = ?supported);

        for id in cred_def_ids {
            ensure!(
                supported.contains(&CredentialConfigurationId::new(id.to_string())),
                ProtocolSnafu::new(
                    ErrorType::UnsupportedCredentialType,
                    format!("Unsupported Credential definition ID: {id}")
                )
            );
        }

        Ok(())
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn resolve_and_validate_nonce(
        &self,
        proof: &oid4vci::proof_of_possession::Proof,
    ) -> Result<Option<Nonce>> {
        let pop_body = ProofOfPossession::get_unverified_body(proof)
            .await
            .map_err(|err| {
                debug!("Failed to parse body of unverified proof of possession: {err}");
                ProtocolSnafu::new(ErrorType::InvalidProof, INVALID_PROOF_ERR_DESC.to_string())
                    .build()
            })?;

        let (nonce, nonce_handler) = match (pop_body.nonce, self.nonce_handler.as_ref()) {
            (Some(nonce), Some(handler)) => {
                (Nonce::from_secret(nonce.secret().to_string()), handler)
            }
            (None, Some(_)) => ProtocolSnafu::new(
                ErrorType::InvalidProof,
                format!("Nonce is not provided. {INVALID_PROOF_ERR_DESC}"),
            )
            .fail()?,
            _ => {
                return Ok(None);
            }
        };

        match nonce_handler.validate(&nonce).await {
            Ok(false) => {
                debug!("Nonce is invalid: nonce = {}", nonce.secret());
                ProtocolSnafu::new(
                    ErrorType::InvalidProof,
                    format!("Nonce is invalid. {INVALID_PROOF_ERR_DESC}"),
                )
                .fail()?
            }
            Err(e) => IssuerServiceSnafu {
                details: format!("Nonce validation failed: {e}"),
            }
            .fail()?,
            _ => {}
        };

        Ok(Some(nonce))
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
    fn validate_claim_names(&self, claims: &Claims, cred_metadata: &CredDefMetadata) -> Result<()> {
        trace!(?claims);

        let claim_names: Vec<&str> = claims.claims().keys().map(|k| k.as_str()).collect();

        // TODO: split it into two parts: required/optional claims
        let supported_claims = match cred_metadata.profile_specific_fields() {
            CoreProfilesCredentialConfiguration::VcSdJwt(metadata) => {
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
            CoreProfilesCredentialConfiguration::LdpVc(metadata) => {
                debug!(resolved_credential_metadata = ?metadata);

                let mut supported: Vec<&str> = metadata
                    .credential_definition()
                    .credential_subject()
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
                    cred_metadata.profile_specific_fields().format()
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

    #[instrument(level = Level::TRACE, skip(self), ret())]
    fn resolve_pop_protocol_error(
        &self,
        proof_err: pop::Error,
    ) -> ProtocolSnafu<vc::oid4vci::ErrorType, Option<String>> {
        match proof_err {
            pop::Error::Verification { source, .. } => ProtocolSnafu::new(
                ErrorType::InvalidProof,
                format!("{}. {INVALID_PROOF_ERR_DESC}", source),
            ),
            _ => ProtocolSnafu::new(ErrorType::InvalidProof, INVALID_PROOF_ERR_DESC.to_string()),
        }
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
            SpruceProof::Jwt { jwt } => AsdkProof {
                format: "jwt".to_string(),
                proof: jwt.to_string(),
            },
            SpruceProof::Cwt { cwt } => AsdkProof {
                format: "cwt".to_string(),
                proof: cwt.to_owned(),
            },
            SpruceProof::LdpVp { ldp_vp } => AsdkProof {
                format: "ldp_vp".to_string(),
                proof: ldp_vp.to_string(),
            },
        }
    }
}

impl TryInto<CoreProfilesCredentialResponseType> for vc::Credential {
    type Error = Error;

    fn try_into(self) -> std::result::Result<CoreProfilesCredentialResponseType, Self::Error> {
        match self {
            vc::Credential::JwtVcJson(cred) => {
                let jws_buf = JwsBuf::from_str(cred.as_str()).map_err(|e| {
                    TypeConversionSnafu {
                        details: e.to_string(),
                    }
                    .build()
                })?;
                Ok(CoreProfilesCredentialResponseType::JwtVcJson {
                    credential: jws_buf,
                })
            }
            vc::Credential::JwtVcJsonLd(cred) => {
                let jws_buf = JwsBuf::from_str(cred.as_str()).map_err(|e| {
                    TypeConversionSnafu {
                        details: e.to_string(),
                    }
                    .build()
                })?;

                Ok(CoreProfilesCredentialResponseType::JwtVcJsonLd {
                    credential: jws_buf,
                })
            }
            vc::Credential::LdpVc(cred) => {
                let cred = serde_json::to_value(&cred).context(ParseSnafu)?;
                Ok(CoreProfilesCredentialResponseType::LdpVc { credential: cred })
            }
            vc::Credential::SdJwt(cred) => {
                Ok(CoreProfilesCredentialResponseType::VcSdJwt { credential: cred })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Add;

    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::utils::http::test::mock_http_req_body;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::claims::Claim;
    use crate::vc::formats::json_ld_vc::JsonLdAPI;
    use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
    use crate::vc::formats::GetDateTimeClaim;
    use crate::vc::oid4vci::issuer::TokenValidation::ByJwks;
    use crate::vc::oid4vci::metadata::convert_metadata;
    use crate::vc::oid4vci::tests::fixtures::{
        sample_claims, sample_credential_definition, sample_credential_offer, MockNonceHandler,
        SampleCredentialRequest, SampleIssuerMetadata, ACCESS_TOKEN, ACCESS_TOKEN_WITHOUT_SCOPE,
        AUTH_URL, CRED_DEF_ID, ISSUER_URL, JWKS_URL, NONCE, SAMPLE_PROOF_JWT, SCOPE,
        TOKEN_INTROSPECT_URL,
    };
    use crate::vc::oid4vci::Error::Protocol;
    use crate::vc::oid4vci::{token_validation, AuthorizationCodeGrant};
    use crate::vc::{Credential, HasClaims};
    use api::Issuer;
    use oauth2::http::{Method, StatusCode};
    use openidconnect::JsonWebKeySetUrl;
    use rstest::rstest;
    use serde_json::json;
    use time::OffsetDateTime;

    const CUSTOM_CRED_LIFETIME: i64 = 1024;
    #[tokio::test]
    async fn get_issuer_metadata_returns_correct_data() {
        let issuer = issuer_service(None, None, Some(LocalNonceHandler::default())).await;

        let metadata = issuer.get_issuer_metadata();

        assert_eq!(metadata, SampleIssuerMetadata::with_sdjwtvc_conf());
    }

    #[tokio::test]
    async fn create_credential_offer_returns_correct_data() {
        let issuer = issuer_service(None, None, Some(LocalNonceHandler::default())).await;

        let offer = issuer
            .create_credential_offer(
                vec![CRED_DEF_ID],
                &CredentialOfferGrants {
                    authorization_code: Some(AuthorizationCodeGrant::new(None, None)),
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
    async fn issue_credential_succeeds_when_nonce_handler_is_provided() {
        let issuer = issuer_service(None, None, Some(MockNonceHandler::default())).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        iss_result.unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "Nonce is invalid. Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce"
    )]
    async fn issue_credential_fails_when_nonce_handler_is_provided_but_nonce_is_invalid() {
        let issuer = issuer_service(None, None, Some(LocalNonceHandler::default())).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        iss_result.unwrap();
    }

    #[tokio::test]
    async fn default_credential_lifetime_works_for_sd_jwt() {
        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(MockNonceHandler::default()),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            Some(Duration::days(CUSTOM_CRED_LIFETIME)),
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        let t = iss_result.unwrap();
        match t.response_kind() {
            ResponseEnum::Immediate { credentials } => {
                let credential: Credential = credentials.first().unwrap().try_into().unwrap();
                match credential {
                    Credential::SdJwt(cred) => {
                        let claims = cred.parse_claims().unwrap();
                        let exp_real = *claims.get("exp").unwrap().as_int().unwrap();
                        let exp_expected = (OffsetDateTime::now_utc()
                            + Duration::days(CUSTOM_CRED_LIFETIME))
                        .unix_timestamp();
                        assert!(i64::abs(exp_expected - exp_real) <= 5);
                    }
                    _ => {
                        assert_eq!(false, true);
                    }
                }
            }
            _ => {
                assert_eq!(false, true);
            }
        }
    }

    #[tokio::test]
    async fn default_credential_lifetime_works_for_ldp_json() {
        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(MockNonceHandler::default()),
            SampleIssuerMetadata::with_custom_issuer_metadata_for_ldp_vc(),
            Some(Duration::days(CUSTOM_CRED_LIFETIME)),
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_ldp_vc_conf_correct(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        let t = iss_result.unwrap();
        match t.response_kind() {
            ResponseEnum::Immediate { credentials } => {
                let credential: Credential = credentials.first().unwrap().try_into().unwrap();
                match credential {
                    Credential::LdpVc(cred) => {
                        let claims = cred.parse_claims().unwrap();
                        let exp_real = JsonLdAPI::get_date_time_claim("validUntil", &claims)
                            .unwrap()
                            .date_time
                            .and_utc()
                            .timestamp();
                        let exp_expected = (OffsetDateTime::now_utc()
                            + Duration::days(CUSTOM_CRED_LIFETIME))
                        .unix_timestamp();
                        //There seems to be a delay of 1second
                        assert!(i64::abs(exp_real - exp_expected) < 3);
                    }
                    _ => {
                        assert_eq!(false, true);
                    }
                }
            }
            _ => {
                assert_eq!(false, true);
            }
        }
    }

    #[tokio::test]
    async fn issue_credential_succeeds_when_time_based_claims_are_provided() {
        let issuer = issuer_service(None, None, Some(MockNonceHandler::default())).await;
        let mut claims = sample_claims();

        let exp = OffsetDateTime::now_utc()
            .add(Duration::days(365))
            .unix_timestamp();
        let nbf = OffsetDateTime::now_utc()
            .add(Duration::days(1))
            .unix_timestamp();
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        claims.insert(EXP_CLAIM.to_string(), Claim::Int(exp));
        claims.insert(NBF_CLAIM.to_string(), Claim::Int(nbf));
        claims.insert(IAT_CLAIM.to_string(), Claim::Int(iat));

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &claims,
                None,
            )
            .await;

        let resp = iss_result.unwrap();

        if let ResponseEnum::Immediate { credentials } = resp.response_kind() {
            assert_eq!(credentials.len(), 1);
            if let CoreProfilesCredentialResponseType::VcSdJwt { credential } = &credentials[0] {
                let claims_str = SdJwtAPI::strip_disclosures(credential).unwrap();
                let claims: Map<String, Value> = decode_unverified(claims_str).unwrap();
                assert_eq!(claims.get(EXP_CLAIM).unwrap(), exp);
                assert_eq!(claims.get(NBF_CLAIM).unwrap(), nbf);
                assert_eq!(claims.get(IAT_CLAIM).unwrap(), iat);
            } else {
                panic!("wrong credential type returned");
            }
        } else {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn issue_credential_fails_with_invalid_proof_error_when_nonce_is_invalid() {
        let issuer = issuer_service(None, None, Some(LocalNonceHandler::default())).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
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
        let issuer = issuer_service(
            None,
            Some(token_validator),
            Some(MockNonceHandler::default()),
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn generate_nonce_works_when_nonce_handler_is_provided() {
        let issuer = issuer_service(None, None, Some(MockNonceHandler::default())).await;

        let nonce_resp = issuer.generate_nonce().await.unwrap();

        assert_eq!(nonce_resp.c_nonce().secret(), NONCE);
    }

    #[tokio::test]
    #[should_panic(expected = "Could not generate a nonce. Nonce Handler is not provided")]
    async fn generate_nonce_fails_when_nonce_handler_is_not_provided() {
        let issuer = issuer_service(None, None, None::<MockNonceHandler>).await;

        issuer.generate_nonce().await.unwrap();
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
        let issuer = issuer_service(
            None,
            Some(token_validator),
            Some(MockNonceHandler::default()),
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        assert!(matches!(
            iss_result.err().unwrap(),
            Protocol { source } if *source.error_type() == ErrorType::InvalidToken
        ));
    }

    #[tokio::test]
    async fn resolve_cred_def_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None::<LocalNonceHandler>).await;

        let cred_req = SampleCredentialRequest::with_sdjwtvc_conf();
        let (cred_def_id, cred_def_metadata) = issuer_service.resolve_cred_def(&cred_req).unwrap();

        assert_eq!(
            (CRED_DEF_ID.to_owned(), sample_credential_definition()),
            (cred_def_id, cred_def_metadata)
        )
    }

    #[tokio::test]
    async fn validate_cred_def_ids_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None::<LocalNonceHandler>).await;

        let cred_def_ids = vec![CRED_DEF_ID];
        let validate_res = issuer_service.validate_cred_def_ids(&cred_def_ids);

        validate_res.unwrap();
    }

    #[tokio::test]
    async fn validate_scope_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None::<LocalNonceHandler>).await;
        let scope = Scope::new(SCOPE.to_owned());

        let validate_res = issuer_service.validate_scope(ACCESS_TOKEN, CRED_DEF_ID, &scope);

        validate_res.unwrap()
    }

    #[tokio::test]
    async fn validate_claim_names_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None::<LocalNonceHandler>).await;

        let claims = json!({
            "given_name": "Bois",
            "family_name": "Tursunov"
        })
        .try_into()
        .unwrap();
        let cred_def = sample_credential_definition();

        let validate_res = issuer_service.validate_claim_names(&claims, &cred_def);

        validate_res.unwrap()
    }

    #[rstest]
    #[case(SampleCredentialRequest::with_jwtvcjson_conf())]
    #[case(SampleCredentialRequest::with_jwtldvc_conf())]
    #[case(SampleCredentialRequest::with_msomdoc_conf())]
    #[tokio::test]
    async fn get_cred_def_metadata_returns_none_on_unsupported_credential_format(
        #[case] credential_request: CredentialRequest,
    ) {
        let issuer_service = issuer_service(None, None, Some(LocalNonceHandler::default())).await;
        let result = issuer_service.get_cred_def_metadata(&credential_request);
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn get_cred_def_metadata_returns_none_on_incorrect_sd_jwt_cred() {
        let issuer_service = issuer_service(None, None, Some(LocalNonceHandler::default())).await;
        let cred_req = sample_sdjwtvc_credential_request_with_fake_vct();
        let result = issuer_service.get_cred_def_metadata(&cred_req);
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn validate_token_does_nothing_on_token_validation_being_none() {
        let issuer_service = issuer_service(None, None, Some(LocalNonceHandler::default())).await;
        issuer_service.validate_token("").await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Missed credential configuration ids")]
    async fn create_credential_offer_fails_on_empty_cred_def_ids() {
        let issuer_service = issuer_service(None, None, None::<LocalNonceHandler>).await;
        let grants = create_empty_credential_offer_grants();
        issuer_service
            .create_credential_offer(vec![], &grants)
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported Credential definition ID: fake_cred_def_id")]
    async fn create_credential_offer_fails_on_not_matching_cred_def_ids() {
        let issuer_service = issuer_service(None, None, None::<LocalNonceHandler>).await;
        let grants = create_empty_credential_offer_grants();
        issuer_service
            .create_credential_offer(vec![CRED_DEF_ID, "fake_cred_def_id"], &grants)
            .unwrap();
    }

    #[rstest]
    #[case(SampleCredentialRequest::with_jwtvcjson_conf())]
    #[case(SampleCredentialRequest::with_jwtldvc_conf())]
    #[case(SampleCredentialRequest::with_msomdoc_conf())]
    #[tokio::test]
    #[should_panic(
        expected = "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."
    )]
    async fn issue_credential_fails_on_unsupported_format(
        #[case] credential_request: CredentialRequest,
    ) {
        let claims = Claims::new();

        let issuer_service = issuer_service(None, None, Some(LocalNonceHandler::default())).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Credential configuration id is not found")]
    async fn issue_credential_fails_on_incorrect_cred_def() {
        let credential_request = sample_sdjwtvc_credential_request_with_fake_vct();
        let claims = Claims::new();

        let issuer_service = issuer_service(None, None, Some(MockNonceHandler::default())).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "No scope set for Credential definition ID: SD_JWT_cred_sample. Only scope authorization supported"
    )]
    async fn issue_credential_fails_on_absent_scope() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = Claims::new();

        let issuer_service = issuer_service_with_metadata(
            None,
            None,
            None::<LocalNonceHandler>,
            sample_issuer_metadata_without_scope(),
            None,
        )
        .await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Could not parse the access token")]
    async fn issue_credential_fails_on_non_decodable_token() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = Claims::new();

        let issuer_service = issuer_service(None, None, Some(MockNonceHandler::default())).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "Access token should have scope=\\\"fake_scope\\\" for issuing \\\"SD_JWT_cred_sample\\\""
    )]
    async fn issue_credential_fails_on_incorrect_scope() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = Claims::new();

        let issuer_service = issuer_service_with_metadata(
            None,
            None,
            Some(MockNonceHandler::default()),
            sample_issuer_metadata_with_incorrect_scope(),
            None,
        )
        .await;
        issuer_service
            .issue_credential(&credential_request, ACCESS_TOKEN, &claims, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Access token does not have \\\"scope\\\" field")]
    async fn issue_credential_fails_on_absent_token_scope() {
        let credential_request = SampleCredentialRequest::with_sdjwtvc_conf();
        let claims = Claims::new();

        let issuer_service = issuer_service(None, None, Some(MockNonceHandler::default())).await;
        issuer_service
            .issue_credential(
                &credential_request,
                ACCESS_TOKEN_WITHOUT_SCOPE,
                &claims,
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported claim name: unsupported_key")]
    async fn issue_credential_fails_on_claims_having_unsupported_key() {
        let claims = json!({"unsupported_key": "unsupported_keys_value"})
            .try_into()
            .unwrap();

        let issuer = issuer_service(None, None, Some(MockNonceHandler::default())).await;
        issuer
            .issue_credential(
                &SampleCredentialRequest::with_sdjwtvc_conf(),
                ACCESS_TOKEN,
                &claims,
                None,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case(sample_sdjwtvc_credential_request_with_empty_proofs_jwt())]
    #[case(sample_sdjwtvc_credential_request_without_proof())]
    #[tokio::test]
    #[should_panic(
        expected = "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."
    )]
    async fn issue_credential_fails_on_invalid_proof(
        #[case] credential_request: CredentialRequest,
    ) {
        let claims = Claims::new();

        let issuer = issuer_service(None, None, Some(MockNonceHandler::default())).await;
        issuer
            .issue_credential(&credential_request, ACCESS_TOKEN, &claims, None)
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
        let issuer = issuer_service(
            None,
            Some(token_validator),
            Some(MockNonceHandler::default()),
        )
        .await;
        issuer.validate_token("").await.unwrap();
    }

    async fn issuer_service<NH: NonceHandler>(
        http_client: Option<MockHttpClient>,
        token_validation: Option<TokenValidation<MockHttpClient>>,
        nonce_handler: Option<NH>,
    ) -> IssuerService<impl vc::core::Issuer, impl HttpClient, impl NonceHandler> {
        issuer_service_with_metadata(
            http_client,
            token_validation,
            nonce_handler,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            None,
        )
        .await
    }

    async fn issuer_service_with_metadata<NH: NonceHandler>(
        http_client: Option<MockHttpClient>,
        token_validation: Option<TokenValidation<MockHttpClient>>,
        nonce_handler: Option<NH>,
        issuer_metadata: IssuerMetadata,
        cred_lifetime: Option<Duration>,
    ) -> IssuerService<impl vc::core::Issuer, impl HttpClient, impl NonceHandler> {
        let kms = LocalKms::new();
        let introspect = Introspect::new(
            http_client.unwrap_or_default(),
            Url::parse(TOKEN_INTROSPECT_URL).unwrap(),
            None,
        );

        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;
        let issuer_metadata_inner = convert_metadata(
            &issuer_metadata,
            &Default::default(),
            &key_metadata,
            cred_lifetime.unwrap_or(Duration::days(5 * 365)),
        )
        .unwrap();

        let inner =
            vc::core::IssuerService::new(kms, issuer_metadata_inner, UniversalResolver::default());

        IssuerService::new(
            issuer_metadata,
            inner,
            nonce_handler,
            token_validation,
            None,
        )
    }

    fn sample_sdjwtvc_credential_request_with_fake_vct() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "format":"dc+sd-jwt",
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
                "format":"dc+sd-jwt",
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
                "format":"dc+sd-jwt",
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
                "format":"dc+sd-jwt",
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
                    "format": "dc+sd-jwt",
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
                    "format": "dc+sd-jwt",
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
