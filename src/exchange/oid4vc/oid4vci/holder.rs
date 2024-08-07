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
use crate::exchange::oid4vc::oid4vci::CredentialResult;
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::{Holder, ProofOfPossession};
use crate::impls;
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

pub struct Oid4VciHolder {
    client_id: String,
    iss_url: String,
    issuer_metadata: IssuerMetadata,
    offer_configs: Vec<CredentialOfferFormat<CoreProfilesOffer>>,
    client: Client,
    pub holder: Box<dyn Holder>,
    http_client: HttpClient,
}

impl Oid4VciHolder {
    pub async fn from_iss_url(
        holder: impl Holder + 'static,
        http_client: HttpClient,
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
        holder: impl Holder + 'static,
        offer: &CredentialOffer,
        http_client: HttpClient,
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
        holder: impl Holder + 'static,
        http_client: HttpClient,
        iss_url: String,
        offer_configs: Vec<CredentialOfferFormat<CoreProfilesOffer>>,
        client_id: String,
        redirect_url: String, // urn:ietf:wg:oauth:2.0:oob
    ) -> Result<Self> {
        let issuer_metadata = IssuerMetadata::discover_async(
            IssuerUrl::new(iss_url.clone())?,
            impls::http::async_request,
        ).await?;

        let authz_metadata = AuthorizationMetadata::discover_async(
            &issuer_metadata,
            impls::http::async_request,
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
        holder: impl Holder + 'static,
        http_client: HttpClient,
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
        holder: impl Holder + 'static,
        http_client: HttpClient,
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
            holder: Box::new(holder),
            http_client,
        })
    }
}

impl Oid4VciHolder {
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
           return Err(Error::FormatNotSupported)
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oauth2::TokenResponse;
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::core::profiles::{CoreProfilesAuthorizationDetails, sd_jwt};
    use oid4vci::metadata::AuthorizationMetadata;
    use serde_json::json;

    use crate::core_::{kms, vc};
    use crate::core_::crypto::Key;
    use crate::core_::did::DIDURL;
    use crate::core_::kms::Kms;
    use crate::exchange::oid4vc::oid4vci::holder::{AuthzOption, Oid4VciHolder};
    use crate::facade::facade_low_level;
    use crate::facade::facade_low_level::{HolderMetadata, HolderService, KeyMetadata};
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::http::HttpClient;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::vault::inmem::InMemVault;

    // FIXTURES
    const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ";
    const CREDENTIAL: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiTTZqdURxUHFOMXJHdVlxcm9CNG9VNVB1bWItMW15VlZ3bGQzcjJ2NWdCSSIsInpsTEczNXoyekFCRXl2SElTdVhLZGFHa1FQOWhrSGs2V055ZVJaclc0cjQiXSwidmN0IjoiU0RfSldUX2NyZWQiLCJ0eXBlIjpbIlNEX0pXVF9jcmVkIl0sImRvYiI6IjA5LzA5LzE5ODkiLCJzdWIiOiJkaWQ6a2V5OnpEbmFleEM5RE55dVZ3M2p5a3V5WW1KZkJCU1pxWnZoNDZaZGdLbUxwemRjNWdKQVciLCJuYmYiOjE3MjI1NTgzMzAsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZVd2dER6R29TRVY1N2FIeFJVWDdkZUFVQjhvTHNTQmIyRE1Ua3V1NjZOYVY2IiwiaWF0IjoxNzIyNTU4MzMwLCJleHAiOjE3NTQwOTQzMzAsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIxLXRZN2lfbW9MdUh6THljUlR3UUZBa0xoUXNvUFdxdXJvNEUwUnllYTBNIiwieSI6IjE5czVrQkpKTktXQmJIQXJyZzQ2RW56V1NBOGMwSm1VRWEwQ0lKa25zUnMifX19.Q675XX4fvAdZQcfZtdxQbzlN2l3q_jHV_ysDRgeD1HsSHVeZLHOuTn7G7JGxXTswmSkaDFljYF2yMeZWCwovrQ~WyIwWFNHek82d3p0cWUwM0VwVG8tTjJnIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJhTklXY0FfQWNmb19Hd0t1R3ZrZjZnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~";
    const CRED_DEF_ID: &str = "SD_JWT_cred";

    #[tokio::test]
    async fn e2e() {
        let mut iss_server = mockito::Server::new_async().await;
        let iss_url = iss_server.url();

        let mut authz_server = mockito::Server::new_async().await;
        let authz_url = authz_server.url();

        let issuer_metadata = sample_issuer_metadata(&iss_url, &authz_url);
        let authorization_metadata = sample_authorization_metadata(&authz_url);

        let iss_metadata_mock = iss_server
            .mock("GET", "/.well-known/openid-credential-issuer")
            .with_status(200)
            .with_body(serde_json::to_string(&issuer_metadata).unwrap())
            .create();

        let authz_metadata_mock = authz_server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_body(serde_json::to_string(&authorization_metadata).unwrap())
            .create();

        let req_uri_code = vc::Nonce::new_random();
        let par_req_mock = authz_server
            .mock("POST", "/par/request")
            .with_status(201)
            .with_body(json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + req_uri_code.secret(),
                "expires_in": 86400,
            }).to_string())
            .create();

        let authz_code = vc::Nonce::new_random();
        let token_mock = authz_server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded("code".to_owned(), authz_code.secret().to_owned()))
            .with_status(200)
            .with_body(json!({
                  "access_token": ACCESS_TOKEN,
                  "token_type": "bearer",
                  "expires_in": 86400,
                  "authorization_details": [
                        {
                            "type": "openid_credential",
                            "format": "vc+sd-jwt",
                            "vct": CRED_DEF_ID,
                        }
                  ]
            }).to_string())
            .create();

        let nonce = vc::Nonce::new_random();

        // Holder created
        let holder = oid4vci_holder(iss_url).await;

        // Authorization
        let token_response = holder.authz_code_flow(
            AuthzOption::Scope(CRED_DEF_ID.to_string()),
            |url| {
                println!("Url {}", url);

                assert!(url.to_string().starts_with(&authz_url));
                assert!(url.query().unwrap().contains(req_uri_code.secret()));

                authz_code.secret().to_owned()
            },
        ).await;
        assert!(token_response.is_ok());

        let token = token_response.unwrap().clone();
        let details = &token.extra_fields().authorization_details.clone().unwrap();

        // Choose the particular cred to issue
        let detail = details.get(0).unwrap();
        let cred_def_id = match &detail.addition_profile_fields {
            CoreProfilesAuthorizationDetails::SDJWTVC(det) => {
                match det {
                    sd_jwt::AuthorizationDetails { credential_configuration_id: Some(id), .. } => id,
                    sd_jwt::AuthorizationDetails { vct: Some(id), .. } => id,
                    _ => panic!()
                }
            }
            _ => panic!(),
        };

        // nonce was received with token
        {
            let nonce = vc::Nonce::new_random();

            let authorization = format!("Bearer {}", ACCESS_TOKEN);
            let credential_mock = iss_server
                .mock("POST", "/credential")
                .match_header("Authorization", authorization.as_str())
                .match_body(mockito::Matcher::PartialJson(json!({
                    "format": "vc+sd-jwt",
                    "vct": CRED_DEF_ID,
                })))
                .with_status(200)
                .with_body(json!({
                    // TODO: format is not defined in the oid4vci spec - fix the response parsing in oid4vci-rs lib
                    "format": "vc+sd-jwt",
                    "credential": CREDENTIAL,
                    "c_nonce": "fGFF7UkhLa",
                    "c_nonce_expires_in": 86400
                }).to_string())
                .create();

            // Credential requested
            let result = holder.request_credential(
                token.access_token(),
                cred_def_id,
                Some(nonce.secret().clone()),
            ).await;

            println!("Cred result: {:?}", result.unwrap())
        }

        // nonce will be re-requested via `/credential`
        {
            let nonce = vc::Nonce::new_random();

            let authorization = format!("Bearer {}", ACCESS_TOKEN);

            let credential_mock_2 = iss_server
                .mock("POST", "/credential")
                .match_header("Authorization", authorization.as_str())
                .match_body(mockito::Matcher::Regex("proof".to_string()))
                .with_status(200)
                .with_body(json!({
                    "format": "vc+sd-jwt",
                    "credential": CREDENTIAL,
                    "c_nonce": "fGFF7UkhLa",
                    "c_nonce_expires_in": 86400
                }).to_string())
                .create();

            let credential_mock_1 = iss_server
                .mock("POST", "/credential")
                .match_header("Authorization", authorization.as_str())
                .match_body(mockito::Matcher::PartialJson(json!({
                    "format": "vc+sd-jwt",
                    "vct": CRED_DEF_ID,
                })))
                .with_status(400)
                .with_body(json!({
                    "error": "invalid_proof",
                    "error_description": "Proof required",
                    "c_nonce": "fGFF7UkhLa",
                    "c_nonce_expires_in": 86400
                }).to_string())
                .create();

            let result = holder.request_credential(
                token.access_token(),
                cred_def_id,
                None,
            ).await;

            println!("Cred result: {:?}", result.unwrap())
        }
    }

    async fn oid4vci_holder(iss_url: String) -> Oid4VciHolder
    {
        let inner = holder().await;
        let holder = Oid4VciHolder::from_iss_url(
            inner,
            HttpClient::new(false, true).unwrap(),
            iss_url,
            "wallet-dev".to_string(),
            "urn:ietf:wg:oauth:2.0:oob".to_string(),
        ).await;

        holder.unwrap()
    }

    async fn holder() -> impl facade_low_level::Holder {
        // Initialization
        println!("Holder creating...");

        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();
        let vault = InMemVault::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(&kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        HolderService::new(kms, vault, HolderMetadata {
            client_id: "wallet-dev".into(),
            key_metadata: KeyMetadata {
                did_url: did_url.to_string(),
                kid: kid.clone(),
            },
        })
    }

    fn sample_issuer_metadata(iss_url: &str, authz_url: &str) -> IssuerMetadata {
        let metadata = serde_json::from_value(json!(
            {
              "credential_issuer": iss_url,
              "authorization_servers": [authz_url],
              "credential_endpoint": iss_url.to_owned()+"/credential",
              "credential_configurations_supported": {
                "SD_JWT_cred": {
                  "format": "vc+sd-jwt",
                  "scope": "SD_JWT_cred",
                  "cryptographic_binding_methods_supported": [
                    "jwk"
                  ],
                  "credential_signing_alg_values_supported": [
                    "ES256"
                  ],
                  "proof_types_supported": {
                    "jwt": {
                      "proof_signing_alg_values_supported": [
                        "ES256"
                      ]
                    }
                  },
                  "vct": "SD_JWT_cred",
                  "credential_definition": {
                      "type": "SD_JWT_cred",
                      "claims": {
                        "given_name": {},
                        "family_name": {}
                      }
                    }
                }
              }
            }
        ));

        metadata.unwrap()
    }

    fn sample_authorization_metadata(authz_url: &str) -> AuthorizationMetadata {
        let metadata = serde_json::from_value(json!(
            {
                "issuer": authz_url,
                "authorization_endpoint": authz_url.to_owned()+"/auth",
                "token_endpoint": authz_url.to_owned()+"/token",
                "introspection_endpoint": authz_url.to_owned()+"/introspect",
                "jwks_uri": authz_url.to_owned()+"/cert",
                "grant_types_supported": [
                    "authorization_code",
                ],
                "response_types_supported": [
                    "code",
                    "token",
                ],
                "subject_types_supported": [
                    "public",
                ],
                "id_token_signing_alg_values_supported": [
                    "ES256",
                ],
                "pushed_authorization_request_endpoint": authz_url.to_owned()+"/par/request",
            }
        ));

        metadata.unwrap()
    }
}