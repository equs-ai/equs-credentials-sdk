use crate::http::HttpClient;
use crate::nonce::{Nonce, NonceHandler};
use crate::vc;
use crate::vc::claims::Claims;
use crate::vc::core::api::CredentialStatusInfo;
use crate::vc::core::{CredentialRequestData, Proof as EqusSdkProof, Proof};
use crate::vc::formats::sd_jwt_vc::{EXP_CLAIM, IAT_CLAIM, NBF_CLAIM, VCT_CLAIM};
use crate::vc::oid4vci::internal_error::{
    ClaimsValidationSnafu, IssuerServiceSnafu, NoScopeSetSnafu, NonceHandlerSnafu, ParseSnafu,
    TypeConversionSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::protocol_error::{
    CredentialEndpointError, CredentialOfferEndpointError, ProtocolSnafu,
};
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};
use crate::vc::oid4vci::{
    CredDefMetadata, CredentialOfferParams, CredentialRequest, CredentialResponse, IssuerMetadata,
    NonceResponse,
};
use crate::vc::{Credential, HasVCFormat, oid4vci as api, pop};
use async_trait::async_trait;
use oauth2::Scope;
use oid4vci::core::profiles::claims::ClaimPathPointer;
use oid4vci::core::profiles::{
    CoreProfilesCredentialConfiguration, CoreProfilesCredentialResponseType,
};
use oid4vci::credential::{ErrorType, Proofs, Response, ResponseEnum};
use oid4vci::credential_offer::{CredentialOfferGrants, CredentialOfferParameters};
use oid4vci::metadata::credential_issuer::BatchCredentialIssuance;
use oid4vci::proof_of_possession::{Proof as SpruceProof, ProofOfPossession};
use oid4vci::types::CredentialConfigurationId;
use serde_json::{Map, Value};
use snafu::{ResultExt, ensure};
use ssi::claims::JwsBuf;
use ssi::claims::jwt::decode_unverified;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use time::Duration;
use tracing::{Level, debug, error, info, instrument, trace, warn};
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

pub struct IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    issuer: IS,
    nonce_handler: Option<Box<dyn NonceHandler>>,
    issuer_metadata: IssuerMetadata,
    token_validation: Option<TokenValidation<HC>>,
    clock_skew: Option<Duration>,
}

impl<IS, HC> IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(issuer, nonce_generator, token_validation))]
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: IS,
        nonce_generator: Option<Box<dyn NonceHandler>>,
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
impl<IS, HC> api::Issuer for IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient + 'static,
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

        let cred_offer_params = CredentialOfferParameters::new(
            self.issuer_metadata.credential_issuer().clone(),
            cred_def_ids
                .iter()
                .map(|c| CredentialConfigurationId::new(c.to_string()))
                .collect(),
            Some(grants.to_owned()),
            HashMap::default(),
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
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<CredentialResponse> {
        info!("issuance of credential is started");
        trace!(credential_request = ?cred_request, %token, claims_to_issue = ?claims);

        self.validate_token(token).await?;
        info!("access token is validated");

        let proofs = if let Some(proofs) = cred_request.proofs() {
            proofs
        } else {
            ProtocolSnafu::credential_endpoint(
                ErrorType::InvalidProof,
                INVALID_PROOF_ERR_DESC.to_string(),
            )
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

        let credentials = self
            .batch_issuance(claims, status_info, cred_def_id, proofs)
            .await?;

        let resp = Response::new(ResponseEnum::Immediate { credentials });

        info!("credential is issued");

        Ok(resp)
    }
}

impl<IS, HC> IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_cred_def(&self, req: &CredentialRequest) -> Result<(String, CredDefMetadata)> {
        trace!(credential_request = ?req);

        let oid4vci::credential::CredentialId::CredentialConfigurationId(cred_conf_id) =
            &req.credential_id
        else {
            ProtocolSnafu::credential_endpoint(
                ErrorType::InvalidCredentialRequest,
                "Credential request by providing 'credential_identifier' field is not supported"
                    .to_string(),
            )
            .fail()?
        };

        let cred_conf = self.issuer_metadata
            .credential_configurations_supported()
            .iter()
            .find(|cc| cc.id() == cred_conf_id)
            .ok_or_else(|| {
                ProtocolSnafu::credential_endpoint(
                    ErrorType::InvalidCredentialRequest,
                    format!("Credential configuration with 'credential_configuration_id' = {} is not found in the supported credential configurations metadata", **cred_conf_id),
                ).build()
            })?;

        Ok((cred_conf.id().to_string().to_owned(), cred_conf.to_owned()))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn validate_cred_def_ids(&self, cred_def_ids: &Vec<&str>) -> Result<()> {
        ensure!(
            !cred_def_ids.is_empty(),
            ProtocolSnafu::credential_offer_endpoint(
                CredentialOfferEndpointError::InvalidRequest,
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
                ProtocolSnafu::credential_offer_endpoint(
                    CredentialOfferEndpointError::UnknownCredentialIdentifier,
                    format!("Unknown credential identifier: {id}")
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
                ProtocolSnafu::credential_endpoint(
                    ErrorType::InvalidProof,
                    INVALID_PROOF_ERR_DESC.to_string(),
                )
                .build()
            })?;

        let (nonce, nonce_handler) = match (pop_body.nonce, self.nonce_handler.as_ref()) {
            (Some(nonce), Some(handler)) => {
                (Nonce::from_secret(nonce.secret().to_string()), handler)
            }
            (None, Some(_)) => ProtocolSnafu::credential_endpoint(
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
                ProtocolSnafu::credential_endpoint(
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
            ProtocolSnafu::credential_endpoint(
                ErrorType::InvalidToken,
                "Could not parse the access token".to_string(),
            )
            .build()
        })?;

        if let Some(Value::String(scopes)) = token.get("scope") {
            ensure!(
                scopes.split(' ').any(|s| s == scope),
                ProtocolSnafu::credential_endpoint(
                    ErrorType::InvalidToken,
                    format!(
                        "Access token should have scope=\"{scope}\" for issuing \"{cred_def_id}\""
                    ),
                ),
            );
            return Ok(());
        }

        ProtocolSnafu::credential_endpoint(
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
            CoreProfilesCredentialConfiguration::VcSdJwt(credential_configuration) => {
                debug!(resolved_credential_metadata = ?credential_configuration);
                let well_known = &[VCT_CLAIM, NBF_CLAIM, IAT_CLAIM, EXP_CLAIM];
                let claims_count = credential_configuration
                    .credential_metadata()
                    .map_or(0, |meta| meta.claims().len());
                let capacity = claims_count + well_known.len();
                let mut json_claims = Vec::with_capacity(capacity);

                if let Some(credential_metadata) = credential_configuration.credential_metadata() {
                    for claim in credential_metadata.claims() {
                        if let Some(ClaimPathPointer::ElementKey(key)) = claim.path().0.first() {
                            json_claims.push(key.as_str());
                        }
                    }
                }
                json_claims.extend_from_slice(well_known);

                json_claims
            }
            CoreProfilesCredentialConfiguration::LdpVc(credential_configuration) => {
                debug!(resolved_credential_metadata = ?credential_configuration);
                let well_known = &["type"];
                let claims_count = credential_configuration
                    .credential_metadata()
                    .map_or(0, |meta| meta.claims().len());
                let capacity = claims_count + well_known.len();
                let mut json_claims = Vec::with_capacity(capacity);

                if let Some(credential_metadata) = credential_configuration.credential_metadata() {
                    for claim in credential_metadata.claims() {
                        // The second pointer is taken since "credentialSubject" goes first.
                        if let Some(ClaimPathPointer::ElementKey(key)) = claim.path().0.get(1) {
                            json_claims.push(key.as_str());
                        }
                    }
                }
                json_claims.extend_from_slice(well_known);

                json_claims
            }
            _ => ProtocolSnafu::credential_endpoint(
                ErrorType::UnknownCredentialConfiguration,
                format!(
                    "Unknown credential configuration: {}",
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
                ProtocolSnafu::credential_endpoint(
                    ErrorType::InvalidToken,
                    "Could not validate the token".to_string(),
                )
                .build()
            })?,
            Some(TokenValidation::ByJwks(svc)) => svc.validate(token).await.map_err(|_| {
                ProtocolSnafu::credential_endpoint(
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
    ) -> ProtocolSnafu<vc::oid4vci::protocol_error::ErrorType, Option<String>> {
        match proof_err {
            pop::Error::Verification { source, .. } => ProtocolSnafu::credential_endpoint(
                CredentialEndpointError::InvalidProof,
                format!("{}. {INVALID_PROOF_ERR_DESC}", source),
            ),
            _ => ProtocolSnafu::credential_endpoint(
                CredentialEndpointError::InvalidProof,
                INVALID_PROOF_ERR_DESC.to_string(),
            ),
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

    #[instrument(level = Level::TRACE, skip(self, nonce), ret())]
    async fn single_issuance(
        &self,
        claims: &Claims,
        status_info: Option<&CredentialStatusInfo>,
        proof: &oid4vci::proof_of_possession::Proof,
        cred_def_id: &str,
        nonce: Option<Nonce>,
    ) -> Result<Credential> {
        let proof = Proof::from(proof);

        let cred_req = vc::core::CredentialRequest {
            cred_def_id: cred_def_id.to_string(),
            proof,
            protocol_data: self.resolve_cred_req_protocol_data(),
            cred_offer_id: None,
        };

        let result = self
            .issuer
            .issue_credential(&cred_req, claims, nonce, status_info.cloned())
            .await;

        let credential = match result {
            Err(vc::core::Error::Proof { source, .. }) => {
                debug!("Proof of possession verification error: {}", source.to_string());
                self.resolve_pop_protocol_error(source).fail()?
            }
            Err(vc::core::Error::ProofFormatNotSupported { format }) =>
                ProtocolSnafu::credential_endpoint(
                    ErrorType::InvalidProof,
                    format!("proof of possession with '{format}' format is not supported. {INVALID_PROOF_ERR_DESC}"),
                )
                    .fail()?,
            _ => result.context(VCSnafu)?,
        };
        Ok(credential)
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn batch_issuance(
        &self,
        claims: &Claims,
        status_info: Option<CredentialStatusInfo>,
        cred_def_id: String,
        proofs: &Proofs,
    ) -> Result<Vec<CoreProfilesCredentialResponseType>> {
        ensure!(
            proofs.len() > 0,
            ProtocolSnafu::credential_endpoint(
                ErrorType::InvalidCredentialRequest,
                "At least one proof of possession must be provided".to_string(),
            )
        );

        let batch_size = if let Some(&BatchCredentialIssuance { batch_size }) =
            self.issuer_metadata.batch_credential_issuance()
        {
            batch_size
        } else {
            1
        };

        ensure!(
            batch_size as usize >= proofs.len(),
            ProtocolSnafu::credential_endpoint(
                ErrorType::InvalidCredentialRequest,
                format!(
                    "At most {} proof of possession(s) are supported",
                    batch_size
                ),
            )
        );

        let proofs: Vec<SpruceProof> = match proofs {
            Proofs::DiVp(di_vps) => di_vps
                .iter()
                .map(|di_vp| SpruceProof::DiVp {
                    di_vp: di_vp.to_owned(),
                })
                .collect(),
            Proofs::Jwt(jwts) => jwts
                .iter()
                .map(|jwt| SpruceProof::Jwt {
                    jwt: jwt.to_owned(),
                })
                .collect(),
        };

        let mut spent_nonces: Vec<Nonce> = vec![];
        let credentials = self
            .issue_each(
                claims,
                status_info.as_ref(),
                cred_def_id.as_str(),
                &proofs,
                &mut spent_nonces,
            )
            .await;

        self.invalidate_nonces(&spent_nonces).await;

        credentials
    }

    /// Validates every key proof's `Nonce` first, then issues, rather than interleaving the two.
    ///
    /// A batch is all-or-nothing: one bad key proof fails the whole request. Interleaving meant a
    /// stale `Nonce` on the last proof was only discovered after every earlier proof had already been
    /// signed, spending a KMS operation apiece on credentials the caller never receives. Validation is
    /// the cheap check, so it runs to completion before the expensive one starts.
    ///
    /// Every `Nonce` that validates is recorded in `spent_nonces` as it validates — including when a
    /// later proof fails — so a rejected batch leaves no `Nonce` its sender can retry against.
    #[instrument(level = Level::TRACE, skip(self, spent_nonces), ret())]
    async fn issue_each(
        &self,
        claims: &Claims,
        status_info: Option<&CredentialStatusInfo>,
        cred_def_id: &str,
        proofs: &[SpruceProof],
        spent_nonces: &mut Vec<Nonce>,
    ) -> Result<Vec<CoreProfilesCredentialResponseType>> {
        let mut validated: Vec<(&SpruceProof, Option<Nonce>)> = Vec::with_capacity(proofs.len());

        for proof in proofs {
            let nonce = self.resolve_and_validate_nonce(proof).await?;

            if let Some(nonce) = &nonce {
                spent_nonces.push(nonce.clone());
            }

            validated.push((proof, nonce));
        }

        let mut credentials: Vec<CoreProfilesCredentialResponseType> =
            Vec::with_capacity(validated.len());

        for (proof, nonce) in validated {
            let credential = self
                .single_issuance(claims, status_info, proof, cred_def_id, nonce)
                .await?;

            credentials.push(credential.try_into()?);
        }

        Ok(credentials)
    }

    /// Hands the spent nonces to the [NonceHandler] once, deduplicated — a batch signed over a single
    /// `c_nonce` reports that nonce once, not once per key proof.
    #[instrument(level = Level::TRACE, skip(self, nonces))]
    async fn invalidate_nonces(&self, nonces: &[Nonce]) {
        let Some(nonce_handler) = self.nonce_handler.as_ref() else {
            return;
        };

        let mut seen: HashSet<&str> = HashSet::new();
        let distinct: Vec<Nonce> = nonces
            .iter()
            .filter(|nonce| seen.insert(nonce.secret()))
            .cloned()
            .collect();

        if distinct.is_empty() {
            return;
        }

        if let Err(err) = nonce_handler.invalidate(&distinct).await {
            // The credentials are issued by now; failing the request over a clean-up that did not
            // happen would be worse than a nonce outliving the request that spent it.
            warn!("Failed to invalidate spent nonces: {err}");
        }
    }
}

impl From<&SpruceProof> for EqusSdkProof {
    fn from(value: &SpruceProof) -> EqusSdkProof {
        match value {
            SpruceProof::Jwt { jwt } => EqusSdkProof {
                format: "jwt".to_string(),
                proof: jwt.to_string(),
            },
            SpruceProof::DiVp { di_vp } => EqusSdkProof {
                format: "di_vp".to_string(),
                proof: di_vp.to_string(),
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
    use std::collections::HashMap;
    use std::ops::Add;

    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::utils::http::test::mock_http_req_body;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::claims::Claim;
    use crate::vc::formats::GetDateTimeClaim;
    use crate::vc::formats::json_ld_vc::JsonLdAPI;
    use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
    use crate::vc::oid4vci::Error::Protocol;
    use crate::vc::oid4vci::issuer::TokenValidation::ByJwks;
    use crate::vc::oid4vci::metadata::convert_metadata;
    use crate::vc::oid4vci::tests::fixtures::{
        ACCESS_TOKEN, ACCESS_TOKEN_WITHOUT_SCOPE, AUTH_URL, CRED_DEF_ID, ISSUER_URL, JWKS_URL,
        MockNonceHandler, NONCE, SAMPLE_PROOF_JWT, SCOPE, SampleCredentialRequest,
        SampleIssuerMetadata, TOKEN_INTROSPECT_URL, sample_claims, sample_credential_definition,
        sample_credential_offer,
    };
    use crate::vc::oid4vci::{
        AuthorizationCodeGrant, CredentialLifetime, protocol_error, token_validation,
    };
    use crate::vc::{Credential, HasClaims, VCFormat};
    use api::Issuer;
    use oauth2::http::{Method, StatusCode};
    use oid4vci::credential::CredentialId;
    use openidconnect::JsonWebKeySetUrl;
    use rstest::rstest;
    use serde_json::json;
    use time::OffsetDateTime;

    const CUSTOM_CRED_LIFETIME: i64 = 1024;
    #[tokio::test]
    async fn get_issuer_metadata_returns_correct_data() {
        let issuer = issuer_service(None, None, Some(Box::new(LocalNonceHandler::default()))).await;

        let metadata = issuer.get_issuer_metadata();

        assert_eq!(metadata, SampleIssuerMetadata::with_sdjwtvc_conf());
    }

    #[tokio::test]
    async fn create_credential_offer_returns_correct_data() {
        let issuer = issuer_service(None, None, Some(Box::new(LocalNonceHandler::default()))).await;

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
        let issuer = issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id(),
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
        let issuer = issuer_service(None, None, Some(Box::new(LocalNonceHandler::default()))).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id(),
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
            Some(Box::new(MockNonceHandler::default())),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            CredentialLifetime::Finite(Duration::days(CUSTOM_CRED_LIFETIME)),
            None,
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id(),
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
    async fn batch_credential_issuance_works() {
        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(Box::new(MockNonceHandler::default())),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            CredentialLifetime::Finite(Duration::days(CUSTOM_CRED_LIFETIME)),
            None,
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id_and_multiple_proofs(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        let t = iss_result.unwrap();
        match t.response_kind() {
            ResponseEnum::Immediate { credentials } => {
                assert_eq!(credentials.len(), 3);

                for credential in credentials {
                    assert_eq!(credential.format(), VCFormat::SdJwtVc)
                }
            }
            _ => {
                panic!("Unexpected response kind (Deferred)");
            }
        }
    }

    #[tokio::test]
    #[should_panic(expected = "At most 1 proof of possession(s) are supported")]
    async fn batch_credential_issuance_not_supported() {
        let mut issuer_metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        issuer_metadata = issuer_metadata.set_batch_credential_issuance(None);

        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(Box::new(MockNonceHandler::default())),
            issuer_metadata,
            CredentialLifetime::Finite(Duration::days(CUSTOM_CRED_LIFETIME)),
            None,
        )
        .await;

        issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id_and_multiple_proofs(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "At least one proof of possession must be provided")]
    async fn batch_credential_issuance_fails_when_proofs_are_missed() {
        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(Box::new(MockNonceHandler::default())),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            CredentialLifetime::Finite(Duration::days(CUSTOM_CRED_LIFETIME)),
            None,
        )
        .await;

        issuer
            .issue_credential(
                &SampleCredentialRequest::with_empty_proofs(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "At most 2 proof of possession(s) are supported")]
    async fn batch_credential_issuance_fails_batch_size_limit_exceeded() {
        let mut issuer_metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        issuer_metadata = issuer_metadata
            .set_batch_credential_issuance(Some(BatchCredentialIssuance { batch_size: 2 }));

        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(Box::new(MockNonceHandler::default())),
            issuer_metadata,
            CredentialLifetime::Finite(Duration::days(CUSTOM_CRED_LIFETIME)),
            None,
        )
        .await;

        issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id_and_multiple_proofs(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn default_credential_lifetime_works_for_ldp_json() {
        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(Box::new(MockNonceHandler::default())),
            SampleIssuerMetadata::with_custom_issuer_metadata_for_ldp_vc(),
            CredentialLifetime::Finite(Duration::days(CUSTOM_CRED_LIFETIME)),
            None,
        )
        .await;

        let mut cred_req = SampleCredentialRequest::with_cred_configuration_id();
        cred_req.credential_id = CredentialId::CredentialConfigurationId(
            CredentialConfigurationId::new("LdpVc".to_string()),
        );

        let iss_result = issuer
            .issue_credential(&cred_req, ACCESS_TOKEN, &sample_claims(), None)
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
    async fn credential_lifetime_per_cred_def_id_works() {
        let cred_req = SampleCredentialRequest::with_cred_configuration_id();
        let duration = Duration::days(100);
        let issuer = issuer_service_with_metadata(
            None,
            None,
            Some(Box::new(MockNonceHandler::default())),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            CredentialLifetime::Finite(Duration::days(CUSTOM_CRED_LIFETIME)),
            Some(HashMap::from([(
                CredentialConfigurationId::new(CRED_DEF_ID.to_string()),
                CredentialLifetime::Finite(duration),
            )])),
        )
        .await;

        let claims = match issuer
            .issue_credential(&cred_req, ACCESS_TOKEN, &sample_claims(), None)
            .await
            .unwrap()
            .response_kind()
        {
            ResponseEnum::Immediate { credentials } => {
                let credential: Credential = credentials.first().unwrap().try_into().unwrap();
                credential.parse_claims().unwrap()
            }
            _ => panic!("Expected immediate response kind"),
        };

        let exp = SdJwtAPI::get_date_time_claim(EXP_CLAIM, &claims)
            .unwrap()
            .unix_timestamp();

        let exp_expected = (OffsetDateTime::now_utc() + duration).unix_timestamp();
        //There seems to be a delay of 1second
        assert!(i64::abs(exp - exp_expected) < 3);
    }

    #[tokio::test]
    async fn issue_credential_succeeds_when_time_based_claims_are_provided() {
        let issuer = issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;
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
                &SampleCredentialRequest::with_cred_configuration_id(),
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
        let issuer = issuer_service(None, None, Some(Box::new(LocalNonceHandler::default()))).await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        assert!(matches!(
            iss_result.err().unwrap(),
            Protocol { source } if *source.error_type() == protocol_error::ErrorType::CredentialEndpoint(CredentialEndpointError::InvalidProof)
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
            Some(Box::new(MockNonceHandler::default())),
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn generate_nonce_works_when_nonce_handler_is_provided() {
        let issuer = issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;

        let nonce_resp = issuer.generate_nonce().await.unwrap();

        assert_eq!(nonce_resp.c_nonce().secret(), NONCE);
    }

    #[tokio::test]
    #[should_panic(expected = "Could not generate a nonce. Nonce Handler is not provided")]
    async fn generate_nonce_fails_when_nonce_handler_is_not_provided() {
        let issuer = issuer_service(None, None, None).await;

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
            Some(Box::new(MockNonceHandler::default())),
        )
        .await;

        let iss_result = issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id(),
                ACCESS_TOKEN,
                &sample_claims(),
                None,
            )
            .await;

        assert!(matches!(
            iss_result.err().unwrap(),
            Protocol { source } if *source.error_type() == protocol_error::ErrorType::CredentialEndpoint(CredentialEndpointError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn resolve_cred_def_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None).await;

        let cred_req = SampleCredentialRequest::with_cred_configuration_id();
        let (cred_def_id, cred_def_metadata) = issuer_service.resolve_cred_def(&cred_req).unwrap();

        assert_eq!(
            (CRED_DEF_ID.to_owned(), sample_credential_definition()),
            (cred_def_id, cred_def_metadata)
        )
    }

    #[tokio::test]
    async fn validate_cred_def_ids_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None).await;

        let cred_def_ids = vec![CRED_DEF_ID];
        let validate_res = issuer_service.validate_cred_def_ids(&cred_def_ids);

        validate_res.unwrap();
    }

    #[tokio::test]
    async fn validate_scope_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None).await;
        let scope = Scope::new(SCOPE.to_owned());

        let validate_res = issuer_service.validate_scope(ACCESS_TOKEN, CRED_DEF_ID, &scope);

        validate_res.unwrap()
    }

    #[tokio::test]
    async fn validate_claim_names_succeeds_with_correct_data() {
        let issuer_service = issuer_service(None, None, None).await;

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

    #[tokio::test]
    async fn get_cred_def_metadata_returns_none_on_unknown_cred_configuration_id() {
        let issuer_service =
            issuer_service(None, None, Some(Box::new(LocalNonceHandler::default()))).await;
        let cred_req = sample_sdjwtvc_credential_request_with_cred_conf_id("unknown_cred_conf_id");
        let result = issuer_service.get_cred_def_metadata(&cred_req);
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn validate_token_does_nothing_on_token_validation_being_none() {
        let issuer_service =
            issuer_service(None, None, Some(Box::new(LocalNonceHandler::default()))).await;
        issuer_service.validate_token("").await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Missed credential configuration ids")]
    async fn create_credential_offer_fails_on_empty_cred_def_ids() {
        let issuer_service = issuer_service(None, None, None).await;
        let grants = create_empty_credential_offer_grants();
        issuer_service
            .create_credential_offer(vec![], &grants)
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unknown credential identifier: fake_cred_def_id")]
    async fn create_credential_offer_fails_on_not_matching_cred_def_ids() {
        let issuer_service = issuer_service(None, None, None).await;
        let grants = create_empty_credential_offer_grants();
        issuer_service
            .create_credential_offer(vec![CRED_DEF_ID, "fake_cred_def_id"], &grants)
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "Credential request by providing 'credential_identifier' field is not supported"
    )]
    async fn issue_credential_fails_when_credential_request_provided_by_credential_identifier_field()
     {
        let claims = Claims::new();

        let issuer_service =
            issuer_service(None, None, Some(Box::new(LocalNonceHandler::default()))).await;
        issuer_service
            .issue_credential(
                &SampleCredentialRequest::with_cred_identifier(),
                "fake_token",
                &claims,
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "Credential configuration with 'credential_configuration_id' = unknown_cred_conf_id is not found in the supported credential configurations metadata"
    )]
    async fn issue_credential_fails_on_incorrect_cred_def() {
        let credential_request =
            sample_sdjwtvc_credential_request_with_cred_conf_id("unknown_cred_conf_id");
        let claims = Claims::new();

        let issuer_service =
            issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;
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
        let credential_request = SampleCredentialRequest::with_cred_configuration_id();
        let claims = Claims::new();

        let issuer_service = issuer_service_with_metadata(
            None,
            None,
            None,
            sample_issuer_metadata_without_scope(),
            CredentialLifetime::default(),
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
        let credential_request = SampleCredentialRequest::with_cred_configuration_id();
        let claims = Claims::new();

        let issuer_service =
            issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;
        issuer_service
            .issue_credential(&credential_request, "fake_token", &claims, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "Access token should have scope=\"fake_scope\" for issuing \"SD_JWT_cred_sample\""
    )]
    async fn issue_credential_fails_on_incorrect_scope() {
        let credential_request = SampleCredentialRequest::with_cred_configuration_id();
        let claims = Claims::new();

        let issuer_service = issuer_service_with_metadata(
            None,
            None,
            Some(Box::new(MockNonceHandler::default())),
            sample_issuer_metadata_with_incorrect_scope(),
            CredentialLifetime::default(),
            None,
        )
        .await;
        issuer_service
            .issue_credential(&credential_request, ACCESS_TOKEN, &claims, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Access token does not have \"scope\" field")]
    async fn issue_credential_fails_on_absent_token_scope() {
        let credential_request = SampleCredentialRequest::with_cred_configuration_id();
        let claims = Claims::new();

        let issuer_service =
            issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;
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

        let issuer = issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;
        issuer
            .issue_credential(
                &SampleCredentialRequest::with_cred_configuration_id(),
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

        let issuer = issuer_service(None, None, Some(Box::new(MockNonceHandler::default()))).await;
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
            Some(Box::new(MockNonceHandler::default())),
        )
        .await;
        issuer.validate_token("").await.unwrap();
    }

    async fn issuer_service(
        http_client: Option<MockHttpClient>,
        token_validation: Option<TokenValidation<MockHttpClient>>,
        nonce_handler: Option<Box<dyn NonceHandler>>,
    ) -> IssuerService<impl vc::core::Issuer, impl HttpClient> {
        issuer_service_with_metadata(
            http_client,
            token_validation,
            nonce_handler,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            CredentialLifetime::default(),
            None,
        )
        .await
    }

    async fn issuer_service_with_metadata(
        http_client: Option<MockHttpClient>,
        token_validation: Option<TokenValidation<MockHttpClient>>,
        nonce_handler: Option<Box<dyn NonceHandler>>,
        issuer_metadata: IssuerMetadata,
        cred_lifetime: CredentialLifetime,
        cred_lifetime_per_cred_conf_id: Option<
            HashMap<CredentialConfigurationId, CredentialLifetime>,
        >,
    ) -> IssuerService<impl vc::core::Issuer, impl HttpClient> {
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
            cred_lifetime,
            cred_lifetime_per_cred_conf_id.unwrap_or_default(),
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

    fn sample_sdjwtvc_credential_request_with_cred_conf_id(
        cred_conf_id: &str,
    ) -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_configuration_id":cred_conf_id,
                "proofs":{
                    "jwt": [ SAMPLE_PROOF_JWT ]
                },
                "credential_response_encryption":null
            }
        ))
        .unwrap()
    }

    fn sample_sdjwtvc_credential_request_with_empty_proofs_jwt() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_configuration_id":CRED_DEF_ID,
                "proofs": {
                    "jwt": [""]
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
                "proofs":{
                    "cwt": [ SAMPLE_PROOF_JWT ]
                },
                "credential_response_encryption":null
            }
        ))
        .unwrap()
    }

    fn sample_sdjwtvc_credential_request_without_proof() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_configuration_id":CRED_DEF_ID,
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
                        "credential_metadata": {
                            "claims": [],
                        },
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
                        "credential_metadata": {
                            "claims": [],
                        },
                    }
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
