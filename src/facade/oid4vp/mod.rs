pub mod holder;
pub mod verifier;

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use mockito::Server;
    use serde_json::{json, Map, Value as Json};
    use ssi::did::DIDURL;
    use tokio::sync::Mutex;
    use url::{form_urlencoded, Url};

    use crate::core_::{crypto, kms, vc};
    use crate::core_::crypto::Alg;
    use crate::core_::did::DID;
    use crate::core_::vault::Vault;
    use crate::core_::vc::{API, CredentialMetadata, VCFormat};
    use crate::exchange::oid4vc::oid4vp::{
        AuthorizationResponse, AuthorizationUrlType,
        PresentationSubmission,
    };
    use crate::exchange::oid4vc::oid4vp::test_utils::{
        create_test_presentation_definition, generate_did_key,
        generate_did_key_and_vm,
    };
    use crate::facade::facade_low_level;
    use crate::facade::facade_low_level::KeyMetadata;
    use crate::facade::facade_oid4vc::{AuthorizationResponseMetadata, HolderVp, Verifier};
    use crate::facade::oid4vp::holder::HolderService;
    use crate::facade::oid4vp::verifier::VerifierService;
    use crate::impls::did::UniversalResolver;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::storage::inmem::InMemStorage;
    use crate::impls::vault::inmem::InMemVault;
    use crate::impls::vc::sd_jwt_vc::{SdJwtAPI, VCMetadata};

    #[tokio::test]
    async fn execute_oid4vp_flow() {
        println!("7. Store Credential");
        let mut holder_kms = LocalKms::new();
        let (holder_kid, holder_kh, holder_did, holder_vm) =
            generate_did_key_and_vm(&mut holder_kms, &UniversalResolver::new()).await;
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let mut holder_vault = InMemVault::new();

        let (vc, vc_meta) = create_sample_vc(&holder_did_url, holder_kh).await;
        holder_vault.store_credential(vc, &vc_meta)
            .await
            .unwrap();

        // Create Holder and Verifier
        let holder = holder(holder_did, holder_vm, holder_kid, holder_kms, holder_vault).await;

        let mut verifier = verifier().await;

        // Generate mocks
        let mut verifier_server = Server::new_async().await;
        let verifier_base_url = verifier_server.url();

        println!("8.1 Verifier: Create Authorization Request");
        // TODO: We should not use a test constant for Presentation Definition here,
        //  we need to build a new one (as every Verifier will build it).
        let presentation_definition = create_test_presentation_definition();
        let nonce = "n0NcE";
        let response_uri: Url = format!("{}/auth", &verifier_base_url).parse().unwrap();
        let auth_request = verifier
            .create_authorization_request(&presentation_definition, nonce, response_uri)
            .await
            .unwrap();

        let request_uri: Url = format!("{}/req-object", &verifier_base_url)
            .parse()
            .unwrap();
        let by_value = auth_request.as_url(AuthorizationUrlType::Value).unwrap();
        let by_reference = auth_request
            .as_url(AuthorizationUrlType::Reference(
                format!("{}/req-object", &verifier_base_url)
                    .parse()
                    .unwrap(),
            ))
            .unwrap();

        println!("Request object passed by value: {}", by_value);
        println!("Request object passed by reference: {}", by_reference);

        mock_request_uri_endpoint(&mut verifier_server, &auth_request.request_object_jwt);
        let response_mutex = mock_response_uri_endpoint(&mut verifier_server);


        println!("8.2 Holder: Get Authorization Request");
        let request_object = holder
            .get_authorization_request(by_reference.as_str())
            .await
            .unwrap();

        println!("Authorization Request: {:?}", &request_object);

        println!("9. Present Credential Auto");
        holder
            .present_credentials_auto(&request_object, &AuthorizationResponseMetadata {})
            .await
            .unwrap();

        println!("10. Verify Presentation");
        let auth_response = response_mutex.lock().await.clone().unwrap();

        let claims = verifier
            .verify_presentation(&auth_response)
            .await
            .unwrap();

        println!("Presentation Claims: {}", claims);

        assert_eq!(
            claims["Identity-1"]["vct"],
            json!("https://credentials.example.com/identity_credential")
        );
        assert_eq!(claims["Identity-1"]["name"], json!("John"));
    }

    fn mock_request_uri_endpoint(verifier_server: &mut Server, request_object_jwt: &str) {
        verifier_server
            .mock("GET", "/req-object")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body(request_object_jwt)
            .create();
    }

    fn mock_response_uri_endpoint(
        verifier_server: &mut Server,
    ) -> Arc<Mutex<Option<AuthorizationResponse>>> {
        let authorization_response = Arc::new(Mutex::new(None));

        let response_clone = Arc::clone(&authorization_response);

        verifier_server
            .mock("POST", "/auth")
            .with_body_from_request(move |request| {
                let mut json_map = Map::new();
                for (key, value) in form_urlencoded::parse(&request.body().unwrap()) {
                    // Try to parse the value as JSON, fall back to treating it as a plain string
                    let json_value: Json =
                        serde_json::from_str(&value).unwrap_or(Json::String(value.to_string()));
                    json_map.insert(key.to_string(), json_value);
                }

                let vp_token = json_map.get("vp_token").unwrap().clone();
                let presentation_submission: PresentationSubmission = serde_json::from_value(
                    json_map.get("presentation_submission").unwrap().clone(),
                )
                    .unwrap();

                let mut locked_response = response_clone.try_lock().unwrap();
                *locked_response = Some(AuthorizationResponse {
                    vp_token,
                    presentation_submission,
                });

                vec![]
            })
            .create();

        authorization_response
    }

    async fn verifier() -> impl Verifier {
        let mut verifier_kms = LocalKms::new();
        let (verifier_kid, verifier_key_handle, verifier_did, verifier_vm_id) =
            generate_did_key_and_vm(&mut verifier_kms, &UniversalResolver::new()).await;
        println!("Verifier DID: {}", verifier_did);

        let verifier_storage = InMemStorage::<String, Json>::new();
        let verifier_service = VerifierService::new(
            verifier_did,
            KeyMetadata {
                did_url: verifier_vm_id,
                kid: verifier_kid,
            },
            verifier_kms,
            verifier_storage,
        );

        verifier_service
    }

    async fn holder(holder_did: DID, holder_vm: String, holder_kid: kms::KeyID, kms: LocalKms, vault: InMemVault) -> impl HolderVp {
        let metadata = facade_low_level::HolderMetadata {
            client_id: holder_did.to_owned(),
            key_metadata: KeyMetadata { did_url: holder_vm, kid: holder_kid },
        };
        let inner = facade_low_level::HolderService::new(kms, vault, metadata);

        let http_client = reqwest::Client::new();
        HolderService::new(
            inner,
            UniversalResolver::new(),
            None,
            http_client,
        )
    }

    async fn create_sample_vc(holder_did_url: &DIDURL, holder_kh: impl crypto::Key) -> (vc::Credential, CredentialMetadata) {
        // Generate Issuer DID and Key
        let mut issuer_kms = LocalKms::new();
        let (issuer_kid, issuer_kh, issuer_did) = generate_did_key(&mut issuer_kms).await;
        println!("Issuer DID: {}", issuer_did);

        let credential_id = "Identity-1";
        let claims = json!( {
            "vct": "https://credentials.example.com/identity_credential",
            "name": "John",
            "surname": "Doe",
            "address": "221B Baker Street",
            "date": "09/09/1989",
        });

        let issuer_did_url = DIDURL::from_str(&issuer_did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(&claims),
            (&issuer_did_url, issuer_kh),
            (&holder_did_url, holder_kh),
            VCMetadata {
                lifetime: time::Duration::days(365),
                disclosures: vec!["$.name".to_owned(), "$.surname".to_owned(), "$.address".to_owned()],
            },
        )
            .await
            .unwrap();

        println!("Credential: {}", vc);

        let vc_meta = CredentialMetadata {
            id: credential_id.to_string(),
            format: VCFormat::SdJwtVc,
            alg: Alg::ES256,
        };

        (vc::Credential::SdJwt(vc), vc_meta)
    }
}
