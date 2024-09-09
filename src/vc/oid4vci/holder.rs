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
    sd_jwt, CoreProfilesAuthorizationDetails, CoreProfilesMetadata, CoreProfilesOffer,
    CoreProfilesRequest, CoreProfilesResponse,
};
use oid4vci::credential::{ErrorType, ResponseEnum};
use oid4vci::credential_offer::CredentialOfferFormat;
use oid4vci::metadata::AuthorizationMetadata;
use oid4vci::openidconnect::IssuerUrl;
use oid4vci::proof_of_possession::KeyProofType;
use oid4vci::proof_of_possession::Proof as SpruceProof;
use oid4vci::token;
use snafu::{ensure, ResultExt};
use std::string::ToString;
use tracing::{debug, info, instrument, trace, Level};

use crate::http::HttpClient;
use crate::vc;
use crate::vc::core::Proof as AsdkProof;
use crate::vc::oid4vci::internal_error::{
    DiscoverySnafu, IssuerServiceSnafu, RequestSnafu, UrlParseSnafu, VCSnafu,
};
use crate::vc::oid4vci::protocol_error::ProtocolSnafu;
use crate::vc::oid4vci::{
    CredentialResponseResolved, CredentialResult, Nonce, NonceData, ProtocolError, TokenResponse,
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
    #[instrument(
        level = Level::TRACE,
        skip(holder, http_client),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip(holder, http_client),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip(holder, http_client),
    )]
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
            |req| HC::static_async(req),
        )
        .await
        .context(DiscoverySnafu)?;
        debug!(resolved_issuer_metadata = ?issuer_metadata);

        let authz_metadata =
            AuthorizationMetadata::discover_async(&issuer_metadata, |req| HC::static_async(req))
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

    #[instrument(
        level = Level::TRACE,
        skip(holder, http_client),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip(holder, http_client),
    )]
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
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(level = Level::DEBUG),
    )]
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, authorization_callback),
        err(),
        ret(level = Level::TRACE),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> Result<TokenResponse> {
        unimplemented!()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        nonce: Option<Nonce>,
    ) -> Result<CredentialResponseResolved> {
        info!("requesting a credential flow is started");

        let cred_def = self.resolve_cred_def(cred_def_id)?;

        let req_base = match &cred_def {
            CoreProfilesMetadata::SDJWTVC(det) => {
                CoreProfilesRequest::SDJWTVC(sd_jwt::Request::new(det.vct().to_owned()))
            }
            _ => ProtocolSnafu::new(
                ErrorType::UnsupportedCredentialFormat,
                format!("Unsupported credential format: {}", cred_def.format()),
            )
            .fail()?,
        };
        trace!(request_profile = ?req_base);

        let offer = &vc::core::CredentialOffer {
            issuer_id: self.issuer_metadata.credential_issuer().to_string(),
            cred_offer_id: None,
            cred_def_id: Some(cred_def_id.to_owned()),
            supported_proofs: self.resolve_supported_proofs(cred_def_id),
            cred_def: None,
            protocol_data: None,
        };

        let nonce = match nonce {
            Some(val) => val.secret().to_owned(),
            None => self.request_nonce(token.clone(), req_base.clone()).await?,
        };
        trace!(resolved_nonce = %nonce);

        let req = self
            .holder
            .request_credential(offer, &nonce)
            .await
            .context(VCSnafu)?;
        trace!(resolved_request = ?req);

        let credential_request = self
            .client
            .request_credential(token.to_owned(), req_base)
            .set_proof(Some(req.proof.try_into()?));

        let resp = credential_request
            .request_async(|req| self.http_client.async_call(req))
            .await
            .context(RequestSnafu)?;

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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
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
    #[instrument(
        level = Level::TRACE,
        skip(self, callback),
        err(),
        ret(level = Level::TRACE),
    )]
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

        let (auth_url, out_csrf) = push_request
            .async_request(|req| self.http_client.async_call(req), None, None)
            .await
            .context(RequestSnafu)?;

        ensure!(
            in_csrf.secret() == out_csrf.secret(),
            ProtocolSnafu::new(ErrorType::InvalidRequest, "CSRF failure".to_string()),
        );

        let code = callback(auth_url);
        trace!(authorization_code = %code);

        let token_req = self
            .client
            .exchange_code(AuthorizationCode::new(sanitize(code)))
            .set_pkce_verifier(pkce_verifier);
        trace!(code_to_token_request = ?token_req);

        let token = token_req
            .request_async(|req| self.http_client.async_call(req))
            .await
            .map_err(|e| ProtocolSnafu::new(ErrorType::InvalidRequest, e.to_string()).build())?;

        info!("authorization is succeeded");

        Ok(token)
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
    async fn deferred(
        &self,
        token: AccessToken,
        transaction_id: String,
    ) -> Result<CredentialResult> {
        unimplemented!()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn request_nonce(
        &self,
        token: AccessToken,
        cred_req: CoreProfilesRequest,
    ) -> Result<String> {
        // TODO: Returning nonce should be optional
        let resp = self
            .client
            .request_credential(token, cred_req)
            .request_async(|req| self.http_client.async_call(req))
            .await;

        trace!(nonce_response = ?resp);

        let nonce = match resp {
            Ok(_) => IssuerServiceSnafu {
                details: "Issuer does not provide a nonce",
            }
            .fail(),
            Err(err) => {
                let protocol_error: ProtocolError = err.try_into().context(RequestSnafu)?;
                protocol_error
                    .nonce()
                    .ok_or(
                        IssuerServiceSnafu {
                            details: "Providing PoP without nonce is unsupported",
                        }
                        .build(),
                    )
                    .cloned()
            }
        }?;

        Ok(nonce.secret().to_string())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
    fn resolve_cred_def(&self, cred_def_id: &str) -> Result<CoreProfilesMetadata> {
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

        Ok(data.additional_fields().to_owned())
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE),
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(level = Level::DEBUG),
    )]
    fn resolve_supported_proofs(&self, cred_def_id: &str) -> Option<Vec<String>> {
        // TODO: delegate to the low-level facade after extending low-level IssuerMetadata
        let configs = self.issuer_metadata.credential_configurations_supported();
        debug!(supported_credential_configs = ?configs);

        let supported: Vec<KeyProofType> = configs
            .get(cred_def_id)
            .and_then(|cd| cd.proof_types_supported())
            .map(|pm| pm.clone().into_keys().collect())
            .unwrap_or(vec![KeyProofType::Jwt]);
        debug!(supported_proof_types = ?supported);

        let proofs = supported
            .into_iter()
            .map(|k| match k {
                KeyProofType::Jwt => "jwt",
                KeyProofType::Cwt => "cwt",
            })
            .map(ToOwned::to_owned)
            .collect();

        Some(proofs)
    }

    fn extract_nonce(resp: &oid4vci::core::credential::Response) -> Option<NonceData> {
        resp.c_nonce().map(|nonce| NonceData {
            nonce: nonce.to_owned(),
            expires_in: resp.c_nonce_expires_in().cloned(),
            created: Some(time::OffsetDateTime::now_utc()),
        })
    }
}

fn sanitize(s: String) -> String {
    s.replace('\n', "")
}

impl TryInto<CredentialResult> for &oid4vci::credential::Response<CoreProfilesResponse> {
    type Error = Error;

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE)
    )]
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

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE)
    )]
    fn try_into(self) -> std::result::Result<Credential, Self::Error> {
        let credential = match self {
            CoreProfilesResponse::SDJWTVC(c) => Credential::SdJwt(c.credential().to_owned()),
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

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE)
    )]
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
