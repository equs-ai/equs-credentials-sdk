use async_trait::async_trait;
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl,
    ResponseType, Scope,
};
use oid4vci::core::authorization::AuthorizationDetail;
use oid4vci::core::client::Client;
use oid4vci::core::credential_offer::CredentialOffer;
use oid4vci::core::metadata::IssuerMetadata;
use oid4vci::core::profiles::{
    sd_jwt, w3c, CoreProfilesAuthorizationDetails, CoreProfilesMetadata, CoreProfilesOffer,
    CoreProfilesRequest, CoreProfilesResponse,
};
use oid4vci::credential::{ErrorType, ResponseEnum};
use oid4vci::credential_offer::CredentialOfferFormat;
use oid4vci::metadata::AuthorizationMetadata;
use oid4vci::openidconnect::IssuerUrl;
use oid4vci::proof_of_possession::Proof as SpruceProof;
use oid4vci::token;
use snafu::{ensure, ResultExt};
use std::string::ToString;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info, instrument, trace, Level};

use crate::http::HttpClient;
use crate::nonce::{Nonce, NonceData};
use crate::vc;
use crate::vc::core::{CredentialOfferContent, KeyMetadata, Proof as AsdkProof};
use crate::vc::oid4vci::internal_error::{
    DiscoverySnafu, IssuerServiceSnafu, MetadataSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::protocol_error::ProtocolSnafu;
use crate::vc::oid4vci::{
    metadata, CredDefMetadata, CredentialResponseResolved, CredentialResult, TokenResponse,
};
use crate::vc::{oid4vci as api, HasVCFormat};
use crate::vc::{Credential, CredentialMetadata};

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum AuthzOption {
    Scope(String),
    Details(AuthorizationDetail),
}

pub struct HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient,
{
    holder: HL,
    http_client: HC,
    client_id: String,
    issuer_metadata: IssuerMetadata,
    offer_configs: Vec<CredentialOfferFormat<CoreProfilesOffer>>,
    client: Client,
}

impl<HL, HC> HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    pub async fn from_iss_url(
        holder: HL,
        http_client: HC,
        issuer_url: String,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        info!("oid4vci-holder service initialization is started");

        let holder_service = Self::from_iss_url_with_configs(
            holder,
            http_client,
            issuer_url,
            vec![],
            client_id,
            redirect_url,
        )
        .await;

        info!("oid4vci-holder service is initialized");

        holder_service
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    pub async fn from_credential_offer(
        holder: HL,
        http_client: HC,
        offer: &CredentialOffer,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        info!("oid4vci-holder service initialization is started");

        let (iss_url, offer_configs) = match offer {
            CredentialOffer::Value { credential_offer } => {
                let iss_url = credential_offer.credential_issuer.clone();
                let offer_configs = credential_offer.credential_configuration_ids.clone();

                (iss_url, offer_configs)
            }
            // TODO: parse url queries
            CredentialOffer::Reference { .. } => ProtocolSnafu::new(
                ErrorType::InvalidRequest,
                "Resolving credential offer by reference is not supported".to_string(),
            )
            .fail()?,
        };

        let holder_service = Self::from_iss_url_with_configs(
            holder,
            http_client,
            iss_url.to_string(),
            offer_configs,
            client_id,
            redirect_url,
        )
        .await;

        info!("oid4vci-holder service is initialized");

        holder_service
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    async fn from_iss_url_with_configs(
        holder: HL,
        http_client: HC,
        issuer_url: String,
        offer_configs: Vec<CredentialOfferFormat<CoreProfilesOffer>>,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        let issuer_metadata = IssuerMetadata::discover_async(
            IssuerUrl::new(issuer_url.clone()).context(UrlParseSnafu)?,
            |req| http_client.async_call(req),
        )
        .await
        .context(DiscoverySnafu)?;
        debug!(resolved_issuer_metadata = ?issuer_metadata);

        let authz_metadata = AuthorizationMetadata::discover_async(&issuer_metadata, |req| {
            http_client.async_call(req)
        })
        .await
        .context(DiscoverySnafu)?;
        debug!(resolved_authorization_server_metadata = ?authz_metadata);

        Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            offer_configs,
            client_id,
            redirect_url,
        )
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    pub fn from_metadata(
        holder: HL,
        http_client: HC,
        issuer_metadata: IssuerMetadata,
        authz_metadata: AuthorizationMetadata,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        let holder_service = Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            vec![],
            client_id,
            redirect_url,
        );
        info!("oid4vci-holder service is initialized");

        holder_service
    }

    #[instrument(level = Level::TRACE, skip(holder, http_client), err())]
    fn new(
        holder: HL,
        http_client: HC,
        issuer_metadata: IssuerMetadata,
        authz_metadata: AuthorizationMetadata,
        offer_configs: Vec<CredentialOfferFormat<CoreProfilesOffer>>,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        let client = Client::from_issuer_metadata(
            issuer_metadata.clone(),
            authz_metadata,
            ClientId::new(client_id.clone()),
            RedirectUrl::new(redirect_url).context(UrlParseSnafu)?,
        );

        info!("oid4vci-holder service is initialized");

        Ok(Self {
            holder,
            http_client,
            client_id,
            issuer_metadata,
            offer_configs,
            client,
        })
    }
}

#[async_trait]
impl<HL, HC> api::Holder for HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip_all, ret())]
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    #[instrument(level = Level::TRACE, skip(self, authorization_callback), err(), ret())]
    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: impl FnOnce(Url) -> String + Send,
    ) -> Result<TokenResponse> {
        info!("authorization code flow is started");

        let response = self
            .authz_code_flow(
                // TODO: advanced AuthDetail by cred_def_id, scope is enough for MVP
                AuthzOption::Scope(scope),
                authorization_callback,
            )
            .await?;

        info!("authorization code flow is succeeded");

        Ok(response)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> Result<TokenResponse> {
        unimplemented!()
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        nonce: Option<&NonceData>,
        key_metadata: &KeyMetadata,
    ) -> Result<CredentialResponseResolved> {
        info!("requesting a credential flow is started");

        let cred_def = self.resolve_cred_def(cred_def_id)?;

        let req_base = match &cred_def.additional_fields() {
            CoreProfilesMetadata::SDJWTVC(det) => {
                CoreProfilesRequest::SDJWTVC(sd_jwt::Request::new(det.vct().to_owned()))
            }
            CoreProfilesMetadata::LDVC(det) => CoreProfilesRequest::LDVC(w3c::ldp::Request::new(
                det.credentials_definition().to_owned(),
            )),
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!(
                    "Unsupported credential format: {}",
                    cred_def.additional_fields().format()
                ),
            )
            .fail()?,
        };

        trace!(request_profile = ?req_base);

        let supported_proofs = metadata::supported_proofs(&cred_def).context(MetadataSnafu)?;
        let offer = &vc::core::CredentialOffer {
            cred_offer_id: None,
            issuer_id: self.issuer_metadata.credential_issuer().to_string(),
            cred_def_id: cred_def_id.to_owned(),
            content: CredentialOfferContent::SupportedProofs(supported_proofs),
            protocol_data: None,
        };
        trace!(credential_offer = ?offer);

        let nonce = match nonce {
            Some(val) => val,
            None => &self.request_nonce(token.clone(), req_base.clone()).await?,
        };
        trace!(resolved_nonce = ?nonce);

        let req = self
            .holder
            .request_credential(offer, &nonce.value, key_metadata)
            .await
            .context(VCSnafu)?;
        trace!(resolved_request = ?req);

        let credential_request = self
            .client
            .request_credential(token.to_owned(), req_base)
            .set_proof(Some(req.proof.try_into()?));

        let resp = credential_request
            .request_async(|req| self.http_client.async_call(req))
            .await?;

        let cred_result: CredentialResult = (&resp).try_into()?;

        if let CredentialResult::Credential { credential, .. } = &cred_result {
            info!("credential is received");

            self.holder
                .verify_credential(credential)
                .await
                .context(VCSnafu)?;

            info!("credential is verified");
        }

        info!("requesting a credential flow is succeeded");

        Ok(CredentialResponseResolved {
            data: cred_result,
            nonce_data: Self::extract_nonce(&resp),
        })
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<()> {
        info!("storing credential is started");

        let _ = self
            .holder
            .store_credential(credential, credential_metadata)
            .await
            .context(VCSnafu)?;

        info!("credential is stored");

        Ok(())
    }
}

impl<HL, HC> HolderService<HL, HC>
where
    HL: vc::core::Holder,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(self, callback), err(), ret())]
    async fn authz_code_flow(
        &self,
        opt: AuthzOption,
        callback: impl FnOnce(Url) -> String,
    ) -> Result<token::Response> {
        info!("authorization is started");

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let in_csrf = CsrfToken::new_random();
        let push_request = self
            .client
            .pushed_authorization_request::<_, CoreProfilesAuthorizationDetails>(|| in_csrf.clone())
            .map_err(|e| ProtocolSnafu::new(ErrorType::InvalidRequest, e.to_string()).build())?
            .set_pkce_challenge(pkce_challenge);

        let push_request = match opt {
            AuthzOption::Scope(scope) => push_request
                .set_scope(Scope::new(scope))
                .set_response_type(&ResponseType::new("code".into())),
            AuthzOption::Details(detail) => push_request.set_authorization_details(vec![detail]),
        };
        info!("holder is sending auth request");

        let (auth_url, out_csrf) = push_request
            .async_request(|req| self.http_client.async_call(req), None, None)
            .await?;

        ensure!(
            in_csrf.secret() == out_csrf.secret(),
            ProtocolSnafu::new(ErrorType::InvalidRequest, "CSRF failure".to_string()),
        );

        info!("authentication is started");
        let code = callback(auth_url);
        info!("authentication is completed");
        trace!(authorization_code = %code);

        let token_req = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier);
        trace!(code_to_token_request = ?token_req);

        let token = token_req
            .request_async(|req| self.http_client.async_call(req))
            .await
            .map_err(|e| ProtocolSnafu::new(ErrorType::InvalidRequest, e.to_string()).build())?;

        info!("authorization is succeeded");

        Ok(token)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn deferred(
        &self,
        token: AccessToken,
        transaction_id: String,
    ) -> Result<CredentialResult> {
        unimplemented!()
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn request_nonce(
        &self,
        token: AccessToken,
        cred_req: CoreProfilesRequest,
    ) -> Result<NonceData> {
        // TODO: Returning nonce should be optional
        let resp = self
            .client
            .request_credential(token, cred_req)
            .request_async(|req| self.http_client.async_call(req))
            .await
            .map_err(|e| e.into());

        trace!(nonce_response = ?resp);

        match resp {
            Ok(_) => IssuerServiceSnafu {
                details: "Issuer does not provide a nonce",
            }
            .fail()?,

            Err(Error::Protocol { source }) => {
                let nonce = source.nonce().ok_or(
                    IssuerServiceSnafu {
                        details: "Providing PoP without nonce is unsupported",
                    }
                    .build(),
                )?;

                Ok(NonceData {
                    value: nonce.to_owned(),
                    expires_in: source.nonce_expiration().map(|e| e.to_owned()),
                    created: OffsetDateTime::now_utc(),
                })
            }

            Err(error) => Err(error)?,
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn resolve_cred_def(&self, cred_def_id: &str) -> Result<CredDefMetadata> {
        let configs = self.issuer_metadata.credential_configurations_supported();
        debug!(supported_credential_configs = ?configs);

        ensure!(
            configs.contains_key(cred_def_id),
            ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialType,
                format!("Unsupported credential definition ID: {cred_def_id}")
            )
        );

        let data = configs.get(cred_def_id).unwrap();
        debug!(resolved_credential_metadata = ?data);

        Ok(data.to_owned())
    }

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn validate_if_offer_supported(&self) -> Result<()> {
        // TODO: implement validation logic to support limitation for pre-authorized code
        /*
            When the Pre-Authorized Grant Type is used, it is RECOMMENDED
            that the Credential Issuer issues an Access Token
            valid only for the Credentials indicated in the Credential Offer (see Section 4.1).
            The Wallet SHOULD obtain a separate Access Token if it wants to request issuance
            of any Credentials that were not included in the Credential Offer,
            but were discoverable from the Credential Issuer's credential_configurations_supported metadata parameter.
        */
        Ok(())
    }

    #[instrument(level = Level::TRACE, ret())]
    fn extract_nonce(resp: &oid4vci::core::credential::Response) -> Option<NonceData> {
        resp.c_nonce().map(|nonce| NonceData {
            value: Nonce::from_secret(nonce.secret().to_owned()),
            expires_in: resp
                .c_nonce_expires_in()
                .map(|e| Duration::seconds(e.to_owned())),
            created: time::OffsetDateTime::now_utc(),
        })
    }
}

impl TryInto<CredentialResult> for &oid4vci::credential::Response<CoreProfilesResponse> {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<CredentialResult, Self::Error> {
        let result = match self.additional_profile_fields() {
            ResponseEnum::Immediate(resp) => {
                let credential = resp.try_into()?;
                CredentialResult::Credential {
                    credential,
                    notification_id: self.notification_id().map(|v| v.to_owned()),
                }
            }
            ResponseEnum::Deferred { transaction_id } => CredentialResult::Deferred {
                transaction_id: transaction_id.clone().unwrap(),
            },
        };

        Ok(result)
    }
}

impl TryInto<Credential> for &CoreProfilesResponse {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<Credential, Self::Error> {
        let credential = match self {
            CoreProfilesResponse::SDJWTVC(c) => Credential::SdJwt(c.credential().to_owned()),
            CoreProfilesResponse::LDVC(c) => Credential::LdpVc(c.credential().to_owned()),
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!("Unsupported credential format: {}", self.format()),
            )
            .fail()?,
        };
        Ok(credential)
    }
}

impl TryInto<SpruceProof> for AsdkProof {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn try_into(self) -> std::result::Result<SpruceProof, Self::Error> {
        let proof = match self.format.as_str() {
            "jwt" => SpruceProof::JWT {
                jwt: self.proof.to_owned(),
            },
            "cwt" => SpruceProof::CWT {
                cwt: self.proof.to_owned(),
            },
            _ => ProtocolSnafu::new(
                ErrorType::InvalidProof,
                format!("Unsupported proof type: {}", self.format),
            )
            .fail()?,
        };

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::{mock_http_once, mock_http_req_predicate};
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vault::{MockVault, Vault};
    use crate::vc::oid4vci::tests::fixtures::{
        fake_access_token, sample_access_token, sample_authorization_metadata,
        sample_cred_response, sample_credential_definition, sample_nonce, SampleIssuerMetadata,
        ACCESS_TOKEN, AUTH_REDIRECT_URL, AUTH_URL, CRED_DEF_ID, ISSUER_URL, NOTIFICATION_ID,
        REQ_URI_CODE, SCOPE, SD_JWT_CREDS,
    };
    use crate::vc::oid4vci::{CredentialRequest, CredentialResult, Holder};
    use crate::vc::VCFormat;
    use oauth2::http::{Method, StatusCode};
    use rstest::rstest;
    use serde_json::json;

    #[tokio::test]
    async fn holder_requests_access_token_correctly() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::POST,
            par_request_endpoint(),
            json!({
               "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + REQ_URI_CODE,
               "expires_in": 86400,
            }),
            StatusCode::CREATED,
        );

        mock_http_once(
            &mut http_client,
            Method::POST,
            access_token_endpoint(),
            sample_access_token_response(),
            StatusCode::OK,
        );

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let token_response = holder_service
            .authz_code_flow_with_scope(SCOPE.into(), |url| {
                assert!(url.to_string().starts_with(AUTH_URL));
                assert!(url.query().unwrap().contains(REQ_URI_CODE));
                "fake_auth_code".to_string()
            })
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(&token_response).unwrap(),
            sample_access_token_response()
        );
    }

    #[tokio::test]
    async fn holder_requests_nonce_correctly() {
        let mut http_client = MockHttpClient::new();
        let nonce = "nOnCe";

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            json!({
               "error": "invalid_proof",
               "error_description": "Provide PoP",
               "c_nonce": nonce,
               "c_nonce_expires_in": 8600,
            }),
            StatusCode::BAD_REQUEST,
        );

        let token = AccessToken::new(ACCESS_TOKEN.to_owned());
        let cred_req = CoreProfilesRequest::SDJWTVC(sd_jwt::Request::new(CRED_DEF_ID.to_owned()));

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let nonce_to_check = holder_service.request_nonce(token, cred_req).await.unwrap();

        assert_eq!(nonce_to_check.secret(), nonce)
    }

    #[tokio::test]
    async fn holder_resolves_credential_definition_correctly() {
        let http_client = MockHttpClient::new();

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let cred_def_to_check = holder_service.resolve_cred_def(CRED_DEF_ID).unwrap();

        assert_eq!(cred_def_to_check, sample_credential_definition())
    }

    #[tokio::test]
    async fn holder_requests_credentials_correctly() {
        let mut http_client = MockHttpClient::new();

        // validate that CredentialRequest is formed correctly and sent to an Issuer
        mock_http_req_predicate(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            |req_body| {
                serde_json::from_str::<CredentialRequest>(&req_body)
                    .expect("invalid credential request");
                true
            },
            sample_cred_response(),
            StatusCode::OK,
            1.into(),
        );

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let _ = holder
            .request_credential(
                &sample_access_token(),
                CRED_DEF_ID,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await;
    }

    #[tokio::test]
    async fn holder_receives_issued_credential_correctly() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            sample_cred_response(),
            StatusCode::OK,
        );

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let response = holder
            .request_credential(
                &sample_access_token(),
                CRED_DEF_ID,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();

        assert!(matches!(
            response.data,
            CredentialResult::Credential {
                credential: Credential::SdJwt(jwt),
                notification_id: Some(notification_id)
            } if jwt == SD_JWT_CREDS && notification_id == NOTIFICATION_ID
        ));
    }

    #[tokio::test]
    async fn holder_stores_credentials_correctly() {
        let mut vault = MockVault::new();
        vault
            .expect_store_credential()
            .times(1)
            .returning(|arg0, arg2| Ok(String::from("fake_cred_id")));

        let kms = LocalKms::new();

        let holder_service = holder_service_from_issuer_metadata(
            MockHttpClient::new(),
            vault,
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;
        let credential = Credential::SdJwt("fake_sdjwt".to_string());

        let cred_metadata = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            tags: vec![],
        };

        let result = holder_service
            .store_credential(&credential, &cred_metadata)
            .await;

        result.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported credential definition ID")]
    async fn holder_fails_processing_incorrect_cred_def_id() {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder_service = holder_service_from_issuer_metadata(
            MockHttpClient::new(),
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let result = holder_service
            .request_credential(
                &sample_access_token(),
                "unexpected_cred_def_id",
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case(SampleIssuerMetadata::with_jwtvc_conf())]
    #[case(SampleIssuerMetadata::with_jwtldvc_conf())]
    #[case(SampleIssuerMetadata::with_isomdl_conf())]
    #[tokio::test]
    #[should_panic(expected = "Unsupported credential format")]
    async fn holder_fails_on_unsupported_credential_formats(#[case] test_metadata: IssuerMetadata) {
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder_service = holder_service_from_issuer_metadata(
            MockHttpClient::new(),
            InMemVault::new(),
            kms,
            test_metadata,
        )
        .await;

        let result = holder_service
            .request_credential(
                &sample_access_token(),
                SCOPE,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Issuer does not provide a nonce")]
    async fn holder_fails_with_no_nonce_provided() {
        let mut http_client = MockHttpClient::new();

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            json!({}),
            StatusCode::OK,
        );

        let holder_service = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            LocalKms::new(),
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let result = holder_service
            .request_credential(&sample_access_token(), CRED_DEF_ID, None, &key_metadata)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Could not parse the access token")]
    async fn holder_shows_informative_error_display_on_wrong_access_token() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::POST,
            credential_endpoint(),
            json!({
               "error": ErrorType::InvalidToken,
               "error_description": "Could not parse the access token",
               "c_nonce": "n0nce",
               "c_nonce_expires_in": 8600,
            }),
            StatusCode::BAD_REQUEST,
        );

        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let holder = holder_service_from_issuer_metadata(
            http_client,
            InMemVault::new(),
            kms,
            SampleIssuerMetadata::with_sdjwtvc_conf(),
        )
        .await;

        let response = holder
            .request_credential(
                &fake_access_token(),
                CRED_DEF_ID,
                Some(&sample_nonce()),
                &key_metadata,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Resolving credential offer by reference is not supported")]
    async fn holder_fails_on_processing_credential_offer_reference() {
        let holder_service = holder_service_from_credential_offer(
            MockHttpClient::new(),
            InMemVault::new(),
            CredentialOffer::Reference {
                credential_offer_uri: Url::parse("https://example.com").unwrap(),
            },
        )
        .await;
    }

    async fn holder_service_from_issuer_metadata(
        http_client: impl HttpClient,
        vault: impl Vault,
        kms: LocalKms,
        issuer_metadata: IssuerMetadata,
    ) -> HolderService<impl vc::core::Holder, impl HttpClient> {
        let client_id = "fake_client_id";
        let holder_metadata = vc::core::HolderMetadata {
            client_id: client_id.to_owned(),
        };

        let inner = vc::core::HolderService::new(kms, vault, holder_metadata);

        HolderService::from_metadata(
            inner,
            http_client,
            issuer_metadata,
            sample_authorization_metadata(),
            client_id.to_owned(),
            "urn:ietf:wg:oauth:2.0:oob".to_string(),
        )
        .unwrap()
    }

    async fn holder_service_from_credential_offer(
        http_client: impl HttpClient,
        vault: impl Vault,
        offer: CredentialOffer,
    ) -> HolderService<impl vc::core::Holder, impl HttpClient> {
        let client_id = "fake_client_id";
        let holder_metadata = vc::core::HolderMetadata {
            client_id: client_id.to_owned(),
        };

        let inner = vc::core::HolderService::new(LocalKms::new(), vault, holder_metadata);

        HolderService::from_credential_offer(
            inner,
            http_client,
            &offer,
            client_id.to_owned(),
            AUTH_REDIRECT_URL.to_string(),
        )
        .await
        .unwrap()
    }

    fn sample_access_token_response() -> serde_json::Value {
        json!({
            "access_token": ACCESS_TOKEN,
            "token_type": "bearer",
            "expires_in": 86400,
        })
    }

    fn par_request_endpoint() -> Url {
        Url::parse(AUTH_URL).unwrap().join("/par/request").unwrap()
    }
    fn access_token_endpoint() -> Url {
        Url::parse(AUTH_URL).unwrap().join("/token").unwrap()
    }

    fn credential_endpoint() -> Url {
        Url::parse(ISSUER_URL).unwrap().join("/credential").unwrap()
    }
}
