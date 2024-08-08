pub mod holder;
pub mod issuer;

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    use futures::executor;
    use mockito::{Request, ServerGuard};
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::core::profiles::CoreProfilesOffer;
    use oid4vci::credential_offer::{AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrants, CredentialOfferParameters};
    use oid4vci::metadata::AuthorizationMetadata;
    use serde_json::json;
    use url::Url;

    use crate::core_::{kms, vc};
    use crate::core_::crypto::Key;
    use crate::core_::did::DIDURL;
    use crate::core_::kms::Kms;
    use crate::core_::vc::Nonce;
    use crate::exchange::oid4vc::oid4vci::holder::Oid4VciHolder;
    use crate::exchange::oid4vc::oid4vci::issuer;
    use crate::facade::{facade_low_level, facade_oid4vc};
    use crate::facade::facade_low_level::{HolderMetadata, KeyMetadata};
    use crate::facade::facade_oid4vc::HolderVci;
    use crate::facade::facade_oid4vc::Issuer;
    use crate::facade::oid4vci::holder::HolderService;
    use crate::facade::oid4vci::issuer::IssuerService;
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::http::HttpClient;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::storage::inmem::InMemStorage;
    use crate::impls::vault::inmem::InMemVault;

    // FIXTURES
    const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ";
    const CRED_DEF_ID: &str = "SD_JWT_cred";

    #[tokio::test]
    async fn e2e() {

        // Creating mock servers
        let mut iss_server = mockito::Server::new_async().await;
        let iss_url = iss_server.url();

        let mut authz_server = mockito::Server::new_async().await;
        let authz_url = authz_server.url();

        let issuer_metadata = sample_issuer_metadata(&iss_url, &authz_url);
        let authorization_metadata = sample_authorization_metadata(&authz_url);

        // 1. Creating issuer from issuer metadata
        let issuer = oid4vci_issuer(issuer_metadata.clone()).await;
        let iss_mutex = Arc::new(Mutex::new(issuer));

        // Creating mocks
        let _ = mock_issuer_metadata(&mut iss_server, &iss_mutex).await;
        let _ = mock_authorization_metadata(&mut authz_server, &authorization_metadata).await;

        let (_, req_uri_code) = mock_par_request(&mut authz_server).await;
        let (_, authz_code) = mock_token(&mut authz_server).await;

        // 2. Creating offer
        let (offer, _) = iss_mutex.lock().unwrap().create_credential_offer(
            vec![CRED_DEF_ID],
            &CredentialOfferGrants {
                authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
                pre_authorized_code: None,
            },
        ).unwrap();

        // 3.1 Creating holder from offer
        let holder = oid4vci_holder(offer).await;

        // 4. Holder has issuer metadata
        assert_eq!(&holder.get_issuer_metadata(), &issuer_metadata);

        // 5. Holder authorizes
        // Authorization callback
        let callback = |url: Url| {
            println!("Url {}", url);

            assert!(url.to_string().starts_with(&authz_url));
            assert!(url.query().unwrap().contains(req_uri_code.secret()));

            authz_code.secret().to_owned()
        };
        let res = holder.authz_code_flow_with_scope(
            CRED_DEF_ID.to_string(),
            callback,
        ).await;
        assert!(res.is_ok());

        let token_response = res.unwrap().clone();

        // 6.2. Wraps the issue credential method
        let _ = mock_credential(&mut iss_server, iss_mutex).await;

        // 6.1 Holder requests credentials
        let result = holder.request_credential(
            &token_response,
            CRED_DEF_ID,
        ).await;

        println!("Cred result: {:?}", result.unwrap())
    }

    async fn mock_issuer_metadata(iss_server: &mut ServerGuard, issuer: &Arc<Mutex<IssuerService>>) -> mockito::Mock {
        let mock = iss_server
            .mock("GET", "/.well-known/openid-credential-issuer")
            .with_status(200)
            .with_body(serde_json::to_string(&issuer.lock().unwrap().get_issuer_metadata()).unwrap())
            .create();

        mock
    }

    async fn mock_authorization_metadata(authz_server: &mut ServerGuard, authorization_metadata: &AuthorizationMetadata) -> mockito::Mock {
        let mock = authz_server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_body(serde_json::to_string(authorization_metadata).unwrap())
            .create();

        mock
    }

    async fn mock_par_request(authz_server: &mut ServerGuard) -> (mockito::Mock, Nonce) {
        let req_uri_code = vc::Nonce::new_random();
        let mock = authz_server
            .mock("POST", "/par/request")
            .with_status(201)
            .with_body(json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + req_uri_code.secret(),
                "expires_in": 86400,
            }).to_string())
            .create();

        (mock, req_uri_code)
    }

    async fn mock_token(authz_server: &mut ServerGuard) -> (mockito::Mock, Nonce) {
        let authz_code = vc::Nonce::new_random();
        let mock = authz_server
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

        (mock, authz_code)
    }

    async fn mock_credential(iss_server: &mut ServerGuard, iss_mutex: Arc<Mutex<IssuerService>>) -> (mockito::Mock, mockito::Mock) {
        let authorization = format!("Bearer {}", ACCESS_TOKEN);

        let iss_endpoint = move |request: &Request| {
            let vec = request.body().unwrap();
            let req = serde_json::from_slice(vec.as_slice()).unwrap();
            let token = request.header("Authorization");
            let token = token.get(0).unwrap().to_str().unwrap().to_string();

            let claims = json!( {
                        "vct": "SD_JWT_cred",
                        "type": ["SD_JWT_cred"],
                        "given_name": "John",
                        "family_name": "Doe",
                        "dob": "09/09/1989",
                    });

            let mut issuer = iss_mutex.lock().unwrap();
            let future = issuer.issue_credential(
                &req,
                &token,
                &claims,
            );

            let result = executor::block_on(future);

            let out_vec = match result {
                Ok(resp) => serde_json::to_vec(&resp).unwrap(),
                Err(facade_oid4vc::Error::Issuer(issuer::Error::ProofVerification(b))) => serde_json::to_vec(&b).unwrap(),
                _ => panic!(),
            };
            out_vec
        };

        let credential_mock_1 = iss_server
            .mock("POST", "/credential")
            .match_header("Authorization", authorization.as_str())
            .match_body(mockito::Matcher::Regex("proof".to_string()))
            .with_status(200)
            .with_body_from_request(iss_endpoint.clone())
            .create();

        let credential_mock_2 = iss_server
            .mock("POST", "/credential")
            .match_header("Authorization", authorization.as_str())
            .match_body(mockito::Matcher::PartialJson(json!({
                    "format": "vc+sd-jwt",
                    "vct": CRED_DEF_ID,
                })))
            .with_status(401)
            .with_body_from_request(iss_endpoint.clone())
            .create();

        (credential_mock_1, credential_mock_2)
    }

    async fn oid4vci_issuer(metadata: IssuerMetadata) -> IssuerService {
        println!("Issuer creating...");

        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(&kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        let storage = InMemStorage::new();
        let iss = IssuerService::from_issuer_metadata(
            kms,
            storage,
            HttpClient::new(false, true).unwrap(),
            metadata,
            did_url.to_string(),
            kid,
            None,
        );

        iss
    }

    async fn oid4vci_holder(credential_offer: CredentialOfferParameters<CoreProfilesOffer>) -> impl HolderVci {
        let inner = holder().await;
        let holder = Oid4VciHolder::from_credential_offer(
            inner,
            &CredentialOffer::Value { credential_offer },
            HttpClient::new(false, true).unwrap(),
            "wallet-dev".to_string(),
            "urn:ietf:wg:oauth:2.0:oob".to_string(),
        ).await;

        HolderService::new(holder.unwrap())
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
                "introspection_endpoint": authz_url.to_owned()+"/token/introspect",
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