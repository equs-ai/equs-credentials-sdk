use std::string::ToString;

use oauth2::{AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, ResponseType, Scope, url};
use oauth2::url::Url;
use oid4vci::{openidconnect, token};
use oid4vci::core::authorization::AuthorizationDetail;
use oid4vci::core::client::Client;
use oid4vci::core::credential;
use oid4vci::core::credential_offer::CredentialOffer;
use oid4vci::core::metadata::IssuerMetadata;
use oid4vci::core::profiles::{CoreProfilesAuthorizationDetails, CoreProfilesMetadata, CoreProfilesOffer, CoreProfilesRequest, CoreProfilesResponse, sd_jwt};
use oid4vci::credential::{RequestError, ResponseEnum};
use oid4vci::credential_offer::CredentialOfferFormat;
use oid4vci::metadata::AuthorizationMetadata;
use oid4vci::openidconnect::IssuerUrl;
use oid4vci::proof_of_possession::{KeyProofType, Proof};

use crate::core_::vc;
use crate::core_::vc::{Credential, CredentialMetadata};
use crate::exchange::oid4vc::oid4vci::CredentialResult;
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::{Holder, ProofOfPossession};
use crate::impls::http::HttpClient;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    // oid4vci
    #[error(transparent)]
    Request(#[from] RequestError<reqwest::Error>),
    #[error(transparent)]
    Client(#[from] oid4vci::client::Error),

    // openid connect/ouath
    #[error(transparent)]
    Discovery(#[from] openidconnect::DiscoveryError<reqwest::Error>),
    #[error(transparent)]
    Token(#[from] oauth2::RequestTokenError<reqwest::Error, token::Error>),

    // Low-level
    #[error(transparent)]
    VC(#[from] facade_low_level::Error),

    #[error("proof not supported")]
    ProofNotSupported,
    #[error("format not supported")]
    FormatNotSupported,
    #[error("CSRF failure")]
    CsrfFailure,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("nonce missed")]
    NonceMissed,
    #[error("not supported")]
    NotSupported,
    #[error("cred def not found: {0}")]
    CredDefNotFound(String),

    // Common
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

pub type AccessToken = oauth2::AccessToken;

pub enum AuthzOption {
    Scope(String),
    Details(AuthorizationDetail),
}

pub struct Oid4VciHolder<HC, HL>
where
    HC: HttpClient,
{
    client_id: String,
    iss_url: String,
    issuer_metadata: IssuerMetadata,
    offer_configs: Vec<CredentialOfferFormat<CoreProfilesOffer>>,
    client: Client,
    holder: HL,
    http_client: HC,
}

impl<HC, HL> Oid4VciHolder<HC, HL>
where
    HC: HttpClient,
    HL: Holder,
{
    pub async fn from_iss_url(
        holder: HL,
        http_client: HC,
        iss_url: String,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        Self::from_iss_url_with_configs(
            holder,
            http_client,
            iss_url,
            vec![],
            client_id,
            redirect_url,
        ).await
    }

    pub async fn from_credential_offer(
        holder: HL,
        offer: &CredentialOffer,
        http_client: HC,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        let (iss_url, offer_configs) = match offer {
            CredentialOffer::Value { credential_offer } => {
                let iss_url = credential_offer.credential_issuer.clone();
                let offer_configs = credential_offer.credential_configuration_ids.clone();

                (iss_url, offer_configs)
            }
            // TODO: parse url queries
            CredentialOffer::Reference { .. } => Err(Error::NotSupported)?,
        };

        Self::from_iss_url_with_configs(
            holder,
            http_client,
            iss_url.to_string(),
            offer_configs,
            client_id,
            redirect_url,
        ).await
    }

    async fn from_iss_url_with_configs(
        holder: HL,
        http_client: HC,
        iss_url: String,
        offer_configs: Vec<CredentialOfferFormat<CoreProfilesOffer>>,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        let issuer_metadata = IssuerMetadata::discover_async(
            IssuerUrl::new(iss_url.clone())?,
            |req| HC::static_async(req),
        ).await?;

        let authz_metadata = AuthorizationMetadata::discover_async(
            &issuer_metadata,
            |req| HC::static_async(req),
        ).await?;

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

    pub fn from_metadata(
        holder: HL,
        http_client: HC,
        issuer_metadata: IssuerMetadata,
        authz_metadata: AuthorizationMetadata,
        client_id: String,
        redirect_url: String,
    ) -> Result<Self> {
        Self::new(
            holder,
            http_client,
            issuer_metadata,
            authz_metadata,
            vec![],
            client_id,
            redirect_url,
        )
    }

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
            RedirectUrl::new(redirect_url)?,
        );

        Ok(Self {
            client_id,
            iss_url: issuer_metadata.credential_issuer().to_string(),
            issuer_metadata,
            offer_configs,
            client,
            holder,
            http_client,
        })
    }
}

impl<HC, HL> Oid4VciHolder<HC, HL>
where
    HC: HttpClient,
    HL: Holder,
{
    pub fn get_issuer_metadata(&self) -> IssuerMetadata { self.issuer_metadata.clone() }

    pub async fn pre_authorized_flow(&self,
                                     pre_authorized_code: String,
                                     tx_code: String,
                                     opt: Option<AuthzOption>,
    ) -> Result<token::Response> {
        unimplemented!()
    }

    pub async fn authz_code_flow(&self,
                                 opt: AuthzOption,
                                 callback: impl FnOnce(Url) -> String,
    ) -> Result<token::Response> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let in_csrf = CsrfToken::new_random();
        let push_request = self.client
            .pushed_authorization_request::<_, CoreProfilesAuthorizationDetails>(|| in_csrf.clone())?
            .set_pkce_challenge(pkce_challenge);

        let push_request = match opt {
            AuthzOption::Scope(scope) => push_request
                .set_scope(Scope::new(scope))
                .set_response_type(&ResponseType::new("code".into())),
            AuthzOption::Details(detail) => push_request
                .set_authorization_details(vec![detail]),
        };

        let (auth_url, out_csrf) = push_request
            .async_request(|req| self.http_client.async_call(req), None, None)
            .await?;

        if !(in_csrf.secret() == out_csrf.secret()) {
            return Err(Error::CsrfFailure);
        }

        let code = callback(auth_url);

        let token_req = self.client
            .exchange_code(AuthorizationCode::new(sanitize(code)))
            .set_pkce_verifier(pkce_verifier);

        let token = token_req
            .request_async(|req| self.http_client.async_call(req))
            .await?;

        Ok(token)
    }

    pub async fn request_credential(&self,
                                    token: &AccessToken,
                                    cred_def_id: &str,
                                    nonce: Option<String>,
    ) -> Result<CredentialResult> {
        let cred_def = self.resolve_cred_def(cred_def_id)?;

        let req_base = match &cred_def {
            CoreProfilesMetadata::SDJWTVC(det) => {
                CoreProfilesRequest::SDJWTVC(sd_jwt::Request::new().set_vct(det.vct().map(|x| x.to_owned())))
            }
            _ => Err(Error::FormatNotSupported)?,
        };

        let offer = &facade_low_level::CredentialOffer {
            issuer_id: self.iss_url.clone(),
            cred_offer_id: None,
            cred_def_id: Some(cred_def_id.to_owned()),
            supported_proofs: self.resolve_supported_proofs(&cred_def_id),
            cred_def: None,
            protocol_data: None,
        };


        let nonce = match nonce {
            Some(val) => val,
            None => self.request_nonce(token.clone(), req_base.clone()).await?
        };

        let req = self.holder.request_credential(offer, &nonce).await?;

        let credential_request = self.client
            .request_credential(token.to_owned(), req_base)
            .set_proof(Some(req.proof.try_into()?));

        let resp = credential_request
            .request_async(|req| self.http_client.async_call(req))
            .await?;

        Self::resolve_response(&resp)
    }

    async fn deferred(&self,
                      token: AccessToken,
                      transaction_id: String,
    ) -> Result<CredentialResult> {
        unimplemented!()
    }

    pub async fn store_credential(
        &mut self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<()> {
        let _ = self.holder.store_credential(credential, credential_metadata).await?;

        Ok(())
    }

    async fn request_nonce(
        &self,
        token: AccessToken,
        req_base: CoreProfilesRequest,
    ) -> Result<String> {
        let resp = self.client
            .request_credential(token, req_base)
            .request_async(|req| self.http_client.async_call(req))
            .await;

        let nonce = match resp {
            Err(RequestError::ProofVerification(body)) => body.c_nonce.ok_or(Error::NonceMissed)?,
            _ => Err(Error::NonceMissed)?
        };

        Ok(nonce.secret().to_string())
    }

    fn resolve_cred_def(&self, cred_def_id: &str) -> Result<CoreProfilesMetadata> {
        let configs = self.issuer_metadata.credential_configurations_supported();

        if !configs.contains_key(cred_def_id) {
            return Err(Error::FormatNotSupported);
        }

        let data = configs.get(cred_def_id).unwrap();

        Ok(data.additional_fields().to_owned())
    }

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

    fn resolve_supported_proofs(&self, cred_def_id: &str) -> Option<Vec<String>> {
        // TODO: delegate to the low-level facade after extending low-level IssuerMetadata
        let configs = self.issuer_metadata.credential_configurations_supported();

        let supported: Vec<KeyProofType> = configs.get(cred_def_id)
            .map(|cd| cd.proof_types_supported())
            .flatten()
            .map(|pm| pm.clone().into_keys().collect())
            .unwrap_or(vec![KeyProofType::Jwt]);

        let proofs = supported.into_iter().map(|k| {
            match k {
                KeyProofType::Jwt => "jwt",
                KeyProofType::Cwt => "cwt"
            }
        }).map(ToOwned::to_owned).collect();

        Some(proofs)
    }

    fn resolve_response(response: &credential::Response) -> Result<CredentialResult> {
        let result = match response.additional_profile_fields() {
            ResponseEnum::Immediate(resp) => {
                let credential = Self::resolve_response_format(resp)?;
                CredentialResult::Credential { credential, notification_id: None }
            }
            ResponseEnum::Deferred { transaction_id } => {
                CredentialResult::Deferred { transaction_id: transaction_id.clone().unwrap() }
            }
        };

        Ok(result)
    }

    fn resolve_response_format(resp: &CoreProfilesResponse) -> Result<vc::Credential> {
        let credential = match resp {
            CoreProfilesResponse::SDJWTVC(c) => vc::Credential::SdJwt(c.credential().to_owned()),
            _ => Err(Error::FormatNotSupported)?,
        };

        Ok(credential)
    }
}

fn sanitize(s: String) -> String {
    s.replace("\n", "")
}

impl TryInto<Proof> for ProofOfPossession {
    type Error = Error;

    fn try_into(self) -> std::result::Result<Proof, Self::Error> {
        let proof = match self {
            ProofOfPossession { ref format, proof } if format == "jwt" => Proof::JWT { jwt: proof.to_owned() },
            ProofOfPossession { ref format, proof } if format == "cwt" => Proof::CWT { cwt: proof.to_owned() },
            _ => Err(Error::ProofNotSupported)?,
        };
        Ok(proof)
    }
}