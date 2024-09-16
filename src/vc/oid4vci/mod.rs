pub(crate) mod api;
pub(crate) mod holder;
pub(crate) mod issuer;
mod metadata;
mod token_validation;

mod builder;
mod internal_error;
mod protocol_error;

#[cfg(test)]
pub(crate) mod tests;

pub use builder::Error as BuilderError;
pub use builder::HolderBuilder;
pub use builder::IssuerBuilder;
pub use builder::IssuerDiscovery;
pub use internal_error::InternalError;
pub use protocol_error::ProtocolError;

pub use api::*;

#[cfg(test)]
pub mod e2e_tests {
    use futures::executor;
    use oauth2::http::{Method, StatusCode};
    use oauth2::{HttpRequest, HttpResponse, TokenResponse};
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::credential_offer::AuthorizationCodeGrant;
    use oid4vci::metadata::AuthorizationMetadata;
    use oid4vci::openidconnect::Nonce;
    use serde_json::json;
    use url::Url;

    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::{mock_http, mock_http_fn, mock_http_once};
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vci::{
        issuer, CredentialOffer, CredentialOfferGrants, CredentialOfferParams, Holder,
        HolderBuilder, IssuanceSession, Issuer, IssuerBuilder, IssuerDiscovery,
    };

    // FIXTURES
    const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA";
    const SCOPE: &str = "SD_JWT_cred";

    #[tokio::test]
    async fn e2e() {
        // Setting up mocks and fixtures
        let iss_url_str = "https://issuer-backend.com";
        let authz_url_str = "https://authz-backend.com";

        let issuer_metadata = sample_issuer_metadata(iss_url_str, authz_url_str);
        let authorization_metadata = sample_authorization_metadata(authz_url_str);

        let mut http_mock = MockHttpClient::new();
        let mut http_mock_iss = MockHttpClient::new();

        let iss_url = Url::parse(iss_url_str).unwrap();
        let authz_url = Url::parse(authz_url_str).unwrap();

        mock_http(
            &mut http_mock,
            Method::GET,
            iss_url
                .join("/.well-known/openid-credential-issuer")
                .unwrap(),
            issuer_metadata.clone(),
            StatusCode::OK,
            1.into(),
        );

        mock_http(
            &mut http_mock,
            Method::GET,
            authz_url.join("/.well-known/openid-configuration").unwrap(),
            authorization_metadata.clone(),
            StatusCode::OK,
            1.into(),
        );

        let authz_code = Nonce::new_random();
        let req_uri_code = Nonce::new_random();

        mock_http_once(
            &mut http_mock,
            Method::POST,
            authz_url.join("/par/request").unwrap(),
            json!({
               "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + req_uri_code.clone().secret(),
               "expires_in": 86400,
            }),
            StatusCode::CREATED,
        );

        mock_http_once(
            &mut http_mock,
            Method::POST,
            authz_url.join("/token").unwrap(),
            json!({
                "access_token": ACCESS_TOKEN,
                "token_type": "bearer",
                "expires_in": 86400,
            }),
            StatusCode::OK,
        );

        mock_http(
            &mut http_mock_iss,
            Method::POST,
            authz_url.join("/token/introspect").unwrap(),
            json!({
                  "active": true,
            }),
            StatusCode::OK,
            3.into(),
        );

        // 1. Creating issuer from issuer metadata
        let introspect_ep = authz_url.join("/token/introspect").unwrap();
        let issuer = oid4vci_issuer(issuer_metadata.clone(), http_mock_iss, introspect_ep).await;

        // 2. Creating offer
        let (offer, _) = issuer
            .create_credential_offer(
                vec!["SD_JWT_cred_1", "SD_JWT_cred_2"],
                &CredentialOfferGrants {
                    authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
                    pre_authorized_code: None,
                },
            )
            .unwrap();

        let mut session = IssuanceSession::default();
        mock_http_fn(
            &mut http_mock,
            Method::POST,
            iss_url.join("/credential").unwrap(),
            move |req| {
                // 6.2 Issuer will issue credentials
                let fut = credential_endpoint(&issuer, req, &mut session);
                let result = executor::block_on(fut);
                Ok(result)
            },
            3.into(),
        );

        // 3.1 Creating holder from offer
        let holder = oid4vci_holder(offer, http_mock).await;

        // 4. Holder has issuer metadata
        assert_eq!(&holder.get_issuer_metadata(), &issuer_metadata);

        // 5. Holder authorizes
        let token_response = holder
            .authz_code_flow_with_scope(SCOPE.into(), |url| {
                println!("Url {}", url);

                assert!(url.to_string().starts_with(&authz_url.to_string()));
                assert!(url.query().unwrap().contains(req_uri_code.secret()));

                authz_code.secret().to_owned()
            })
            .await
            .unwrap();

        println!("Token response {:?}", token_response);

        // 6.1 Holder requests SD_JWT_cred_1 credentials
        let response = holder
            .request_credential(token_response.access_token(), "SD_JWT_cred_1", None)
            .await
            .unwrap();

        println!("Credential 1: {:?}", response.data);

        // Extra check that subsequent nonce returned
        let nonce_data = response.nonce_data;
        assert!(nonce_data.is_some());

        // 6.2 Holder requests SD_JWT_cred_2 credentials with the same token
        let response = holder
            .request_credential(
                token_response.access_token(),
                "SD_JWT_cred_2",
                nonce_data.map(|d| d.nonce),
            )
            .await
            .unwrap();

        println!("Credential 2: {:?}", response.data);
    }

    async fn credential_endpoint(
        issuer: &impl Issuer,
        req: HttpRequest,
        session: &mut IssuanceSession,
    ) -> HttpResponse {
        let cred_req = serde_json::from_slice(req.body.as_slice()).unwrap();
        let token = req.headers.get("Authorization").unwrap();
        let token = token
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap()
            .to_string();

        let claims = json!( {
            "given_name": "John",
            "family_name": "Doe",
            "dob": "09/09/1989",
        });

        let result = issuer
            .issue_credential(&cred_req, &token, &claims, session)
            .await;

        match result {
            Ok(cred_resp) => HttpResponse {
                status_code: StatusCode::OK,
                headers: Default::default(),
                body: serde_json::to_vec(&cred_resp).unwrap(),
            },
            Err(issuer::Error::Protocol { source }) => HttpResponse {
                status_code: StatusCode::BAD_REQUEST,
                headers: Default::default(),
                body: serde_json::to_vec(&source).unwrap(),
            },
            _ => panic!(),
        }
    }

    async fn oid4vci_holder(
        credential_offer: CredentialOfferParams,
        http_client: MockHttpClient,
    ) -> impl Holder + Sized {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        HolderBuilder::new(
            kms,
            vault,
            key_metadata,
            "wallet-dev".to_string(),
            IssuerDiscovery::Offer(CredentialOffer::Value { credential_offer }),
        )
        .with_http_client(http_client)
        .build()
        .await
        .unwrap()
    }

    async fn oid4vci_issuer(
        metadata: IssuerMetadata,
        http_client: MockHttpClient,
        introspect_ep: Url,
    ) -> impl Issuer + Sized {
        let kms = LocalKms::new();

        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        IssuerBuilder::new(kms, metadata, key_metadata)
            .with_http_client(http_client)
            .token_validation_introspect(introspect_ep, None)
            .build()
            .await
            .unwrap()
    }

    fn sample_issuer_metadata(iss_url: &str, authz_url: &str) -> IssuerMetadata {
        let metadata = serde_json::from_value(json!(
            {
              "credential_issuer": iss_url,
              "authorization_servers": [authz_url],
              "credential_endpoint": iss_url.to_owned()+"/credential",
              "credential_configurations_supported": {
                "SD_JWT_cred_1": {
                  "format": "vc+sd-jwt",
                  "scope": SCOPE.to_owned(),
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
                  "vct": "SD_JWT_cred_1",
                  "credential_definition": {
                      "type": "SD_JWT_cred",
                      "claims": {
                        "given_name": {},
                        "family_name": {},
                        "dob": {}
                      }
                    }
                },
                "SD_JWT_cred_2": {
                  "format": "vc+sd-jwt",
                  "scope": SCOPE.to_owned(),
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
                  "vct": "SD_JWT_cred_2",
                  "credential_definition": {
                      "type": "SD_JWT_cred",
                      "claims": {
                        "given_name": {},
                        "family_name": {},
                        "dob": {}
                      }
                    }
                },
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
                "introspection_endpoint": authz_url.to_owned()+"/protocol/openid-connect/token/introspect",
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
