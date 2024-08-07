pub mod holder;
pub mod verifier;

#[cfg(test)]
mod tests {
    use crate::core_::crypto::Alg;
    use crate::core_::vault::Vault;
    use crate::core_::vc::{Credential, CredentialMetadata, VCFormat, API};
    use crate::exchange::oid4vc::oid4vp::test_utils::{
        create_test_presentation_definition, generate_did_key,
        generate_did_key_and_vm,
    };
    use crate::exchange::oid4vc::oid4vp::{
        AuthorizationResponse, AuthorizationUrlType,
        PresentationSubmission,
    };
    use crate::facade::facade_low_level::KeyMetadata;
    use crate::facade::facade_oid4vc::{AuthorizationResponseMetadata, HolderVp, Verifier};
    use crate::facade::oid4vp::holder::HolderService;
    use crate::facade::oid4vp::verifier::VerifierService;
    use crate::impls::did::UniversalResolver;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::storage::inmem::InMemStorage;
    use crate::impls::vault::inmem::InMemVault;
    use crate::impls::vc::sd_jwt_vc::{SdJwtAPI, VCMetadata};
    use mockito::Server;
    use serde_json::{json, Map, Value as Json};
    use ssi::did::DIDURL;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use url::{form_urlencoded, Url};

    #[tokio::test]
    async fn execute_oid4vp_flow() {
        let did_resolver = UniversalResolver::new();

        // Generate Issuer DID and Key
        let mut issuer_kms = LocalKms::new();
        let (issuer_kid, issuer_key_handle, issuer_did) = generate_did_key(&mut issuer_kms).await;
        println!("Issuer DID: {}", issuer_did);

        // Generate Holder DID and Key
        let mut holder_kms = LocalKms::new();
        let (holder_kid, holder_key_handle, holder_did, holder_vm) =
            generate_did_key_and_vm(&mut holder_kms, &did_resolver).await;
        println!("Holder DID: {}", holder_did);

        // Generate Verifier DID and Key
        let mut verifier_kms = LocalKms::new();
        let (verifier_kid, verifier_key_handle, verifier_did, verifier_vm_id) =
            generate_did_key_and_vm(&mut verifier_kms, &did_resolver).await;
        println!("Verifier DID: {}", verifier_did);

        println!("7. Store Credential");
        let mut holder_vault = InMemVault::new();
        let credential_id = "Identity-1";
        let claims = json!( {
            "vct": "https://credentials.example.com/identity_credential",
            "name": "John",
            "surname": "Doe",
            "address": "221B Baker Street",
            "date": "09/09/1989",
        });

        let issuer_did_url = DIDURL::from_str(&issuer_did).unwrap();
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(&claims),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            VCMetadata {
                lifetime: time::Duration::days(365),
                disclosures: vec!["$.name", "$.surname", "$.address"],
            },
        )
        .await
        .unwrap();

        println!("Credential: {}", vc);

        holder_vault
            .store_credential(
                Credential::SdJwt(vc),
                &CredentialMetadata {
                    id: credential_id.to_string(),
                    format: VCFormat::SdJwtVc,
                    alg: Alg::ES256,
                },
            )
            .await
            .unwrap();

        // Setup Verifier Service
        let mut verifier_server = Server::new_async().await;
        let verifier_base_url = verifier_server.url();
        let verifier_storage = InMemStorage::<String, Json>::new();
        let mut verifier_service = VerifierService::new(
            verifier_did,
            KeyMetadata {
                did_url: verifier_vm_id,
                kid: verifier_kid,
            },
            verifier_kms,
            verifier_storage,
        );

        println!("8.1 Verifier: Create Authorization Request");
        // TODO: We should not use a test constant for Presentation Definition here,
        //  we need to build a new one (as every Verifier will build it).
        let presentation_definition = create_test_presentation_definition();
        let nonce = "n0NcE";
        let response_uri: Url = format!("{}/auth", &verifier_base_url).parse().unwrap();
        let auth_request = verifier_service
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

        // Setup Holder Service
        let http_client = reqwest::Client::new();
        let holder_service = HolderService::new(
            holder_did.to_owned(),
            None,
            holder_vm,
            holder_kid,
            holder_kms,
            holder_vault,
            http_client,
        );

        println!("8.2 Holder: Get Authorization Request");
        let request_object = holder_service
            .get_authorization_request(by_reference.as_str())
            .await
            .unwrap();

        println!("Authorization Request: {:?}", &request_object);

        println!("9. Present Credential Auto");
        holder_service
            .present_credentials_auto(&request_object, &AuthorizationResponseMetadata {})
            .await
            .unwrap();

        println!("10. Verify Presentation");
        let auth_response = response_mutex.lock().await.clone().unwrap();

        let claims = verifier_service
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
}
