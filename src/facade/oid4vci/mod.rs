pub mod holder;
pub mod issuer;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures::executor;
    use oauth2::{HttpRequest, HttpResponse};
    use oauth2::http::{HeaderValue, Method, StatusCode};
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::credential_offer::AuthorizationCodeGrant;
    use oid4vci::metadata::AuthorizationMetadata;
    use serde_json::json;
    use url::Url;

    use crate::core_::{kms, vc};
    use crate::core_::crypto::Key;
    use crate::core_::did::DIDURL;
    use crate::core_::kms::Kms;
    use crate::exchange::oid4vc::oid4vci::{CredentialOffer, CredentialOfferGrants, CredentialOfferParameters, issuer};
    use crate::exchange::oid4vc::oid4vci::holder::Oid4VciHolder;
    use crate::facade::{facade_low_level, facade_oid4vc};
    use crate::facade::facade_low_level::{HolderMetadata, KeyMetadata};
    use crate::facade::facade_oid4vc::HolderVci;
    use crate::facade::facade_oid4vc::Issuer;
    use crate::facade::oid4vci::holder::HolderService;
    use crate::facade::oid4vci::issuer::IssuerService;
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::http::{mock_http, mock_http_fn, mock_static_ctx, MockHttpClient};
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::storage::inmem::InMemStorage;
    use crate::impls::vault::inmem::InMemVault;

    // FIXTURES
    const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ";
    const CRED_DEF_ID: &str = "SD_JWT_cred";

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

        let ctx = MockHttpClient::static_async_context();
        mock_static_ctx(
            &ctx,
            Method::GET,
            iss_url.join("/.well-known/openid-credential-issuer").unwrap(),
            issuer_metadata.clone(),
            StatusCode::OK,
        );

        mock_static_ctx(
            &ctx,
            Method::GET,
            authz_url.join("/.well-known/openid-configuration").unwrap(),
            authorization_metadata.clone(),
            StatusCode::OK,
        );

        let authz_code = vc::Nonce::new_random();
        let req_uri_code = vc::Nonce::new_random();

        mock_http(
            &mut http_mock,
            Method::POST,
            authz_url.join("/par/request").unwrap(),
            json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + req_uri_code.clone().secret(),
                "expires_in": 86400,
             }),
            StatusCode::CREATED,
        );

        mock_http(
            &mut http_mock,
            Method::POST,
            authz_url.join("/token").unwrap(),
            json!({
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
            }),
            StatusCode::OK,
        );

        mock_http(
            &mut http_mock_iss,
            Method::POST,
            authz_url.join("/protocol/openid-connect/token/introspect").unwrap(),
            json!({
                  "active": true,
            }),
            StatusCode::OK,
        );

        // 1. Creating issuer from issuer metadata
        let mut issuer = oid4vci_issuer(issuer_metadata.clone(), http_mock_iss).await;

        // 2. Creating offer
        let (offer, _) = issuer.create_credential_offer(
            vec![CRED_DEF_ID],
            &CredentialOfferGrants {
                authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
                pre_authorized_code: None,
            },
        ).unwrap();

        mock_http_fn(
            &mut http_mock,
            Method::POST,
            iss_url.join("/credential").unwrap(),
            move |req| {
                // 6.2 Issuer will issue credentials
                let fut = credential_endpoint(&mut issuer, req);
                let result = executor::block_on(fut);
                Ok(result)
            },
            2.into(),
        );

        // 3.1 Creating holder from offer
        let holder = oid4vci_holder(offer, http_mock).await;

        // 4. Holder has issuer metadata
        assert_eq!(&holder.get_issuer_metadata(), &issuer_metadata);

        // 5. Holder authorizes
        let token_response = holder.authz_code_flow_with_scope(
            CRED_DEF_ID.into(),
            |url| {
                println!("Url {}", url);

                assert!(url.to_string().starts_with(&authz_url.to_string()));
                assert!(url.query().unwrap().contains(req_uri_code.secret()));

                authz_code.secret().to_owned()
            },
        ).await.unwrap();

        println!("Token response {:?}", token_response);

        // 6.1 Holder requests credentials
        let credential = holder.request_credential(
            &token_response.clone(),
            CRED_DEF_ID,
        ).await.unwrap();

        println!("Credential: {:?}", credential);
    }

    async fn credential_endpoint(issuer: &mut impl facade_oid4vc::Issuer, req: HttpRequest) -> HttpResponse {
        let cred_req = serde_json::from_slice(req.body.as_slice()).unwrap();
        let token = req.headers.get("Authorization").unwrap();
        let token = token.to_str().unwrap()
            .strip_prefix("Bearer ").unwrap()
            .to_string();

        let claims = json!( {
                        "vct": "SD_JWT_cred",
                        "type": ["SD_JWT_cred"],
                        "given_name": "John",
                        "family_name": "Doe",
                        "dob": "09/09/1989",
                    });

        let result = issuer.issue_credential(
            &cred_req,
            &token,
            &claims,
        ).await;

        let response = match result {
            Ok(cred_resp) => HttpResponse {
                status_code: StatusCode::OK,
                headers: Default::default(),
                body: serde_json::to_vec(&cred_resp).unwrap(),
            },
            Err(facade_oid4vc::Error::Issuer(issuer::Error::ProofVerification(b))) => HttpResponse {
                status_code: StatusCode::BAD_REQUEST,
                headers: Default::default(),
                body: serde_json::to_vec(&b).unwrap(),
            },
            _ => panic!(),
        };

        response
    }

    async fn oid4vci_holder(credential_offer: CredentialOfferParameters, http_client: MockHttpClient) -> impl facade_oid4vc::HolderVci {
        let inner = holder().await;
        let holder = Oid4VciHolder::from_credential_offer(
            inner,
            &CredentialOffer::Value { credential_offer },
            http_client,
            "wallet-dev".to_string(),
            "urn:ietf:wg:oauth:2.0:oob".to_string(),
        ).await;

        HolderService::new(holder.unwrap())
    }

    async fn oid4vci_issuer(metadata: IssuerMetadata, http_client: MockHttpClient) -> impl facade_oid4vc::Issuer + Sized {
        println!("Issuer creating...");

        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        let storage = InMemStorage::new();
        let iss = IssuerService::from_issuer_metadata(
            kms,
            storage,
            http_client,
            metadata,
            did_url.to_string(),
            kid,
            Some(HeaderValue::from_static("issuer_authz")),
            true,
        );

        iss
    }

    async fn holder() -> impl facade_low_level::Holder {
        // Initialization
        println!("Holder creating...");

        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();
        let vault = InMemVault::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        facade_low_level::HolderService::new(kms, vault, HolderMetadata {
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