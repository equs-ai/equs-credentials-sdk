use agent_sdk::vc::oid4vp::Url;
use shared::vp::AuthRequestQuery;

pub enum IssuerDiscoveryMode {
    #[allow(dead_code)] // not used when "noninteractive" feature is on
    Url,
    CredentialOffer,
}

pub enum PresentationFlow {
    CrossDevice,
    SameDevice,
}

pub enum CredentialSelectionMode {
    Auto,
    #[allow(dead_code)] // not used when "noninteractive" feature is on
    ManualSelection,
}

fn map_to_verifier_request_uri_url(query: AuthRequestQuery) -> Url {
    let query = serde_urlencoded::to_string(query).unwrap();
    let mut verifier_url = String::from("http://localhost:8098/request_uri?");
    verifier_url += query.as_str();
    Url::parse(verifier_url.as_str()).unwrap()
}

#[cfg(not(feature = "noninteractive"))]
pub mod cli {
    use crate::user_input::{
        CredentialSelectionMode, IssuerDiscoveryMode, PresentationFlow,
        map_to_verifier_request_uri_url,
    };
    use agent_sdk::vc::oid4vci::AuthzFlow;
    use agent_sdk::vc::oid4vp::{ResponseMode, ResponseType, Url};
    use shared::vp::{AuthRequestQuery, PresentationQueryType};
    use std::collections::HashMap;
    use std::io;

    pub async fn ask_issuer_discovery_mode() -> IssuerDiscoveryMode {
        println!(
            "Please enter number to initialize holder from:\n 1 - Issuer URL\n 2 - By resolving a credential Offer"
        );

        loop {
            let input = input_from_console("Failed to read holder initialization mode");
            match input.as_str() {
                "1" => return IssuerDiscoveryMode::Url,
                "2" => return IssuerDiscoveryMode::CredentialOffer,
                _ => println!("Invalid input, please retry"),
            }
        }
    }

    pub async fn ask_issuer_url() -> String {
        println!("Enter issuer URL");
        input_from_console("Failed to read issuer URL")
    }

    pub async fn ask_offer() -> String {
        println!("Please select and enter the Credential offer Uri from:");
        println!(
            "- Offer with authorization code grant: http://localhost:8088/create_credential_offer_uri_auth_code_grant"
        );
        println!(
            "- Offer with pre-authorized code grant: http://localhost:8088/create_credential_offer_uri_pre_auth_code_grant"
        );

        input_from_console("Failed to read the value of the Credential offer")
    }

    pub async fn ask_auth_code_by_flow(flow: AuthzFlow) -> String {
        match flow {
            AuthzFlow::Authorize(url) => {
                println!(
                    "Authorization URL. Authenticate with user \"tneal\" and password \"password\""
                );
                println!("{}", url);

                print!("Please enter an authorization code: ");
                input_from_console("Failed to read authorization code")
            }
            AuthzFlow::Preauthorized => {
                println!("If you have a transaction code from the Issuer, please enter 'y'");
                let input = input_from_console("Failed to read input");

                match input.as_str() {
                    "y" => {
                        print!("Please enter a transaction code: ");
                        input_from_console("Failed to read transaction code")
                    }
                    _ => {
                        // When "oid4vc/issuer" web service is used as the Issuer, we just mock dummy transaction code.
                        // agent-sdk does not handle the generation and validation of transaction code
                        "tx_code".to_string()
                    }
                }
            }
        }
    }

    pub async fn ask_revocation_confirmation() -> bool {
        println!("Revoke SD-JWT credential? y/n");
        loop {
            let input = input_from_console("Failed to read input");
            match input.as_str() {
                "y" => return true,
                "n" => return false,
                _ => println!("Invalid input, please retry"),
            }
        }
    }

    pub async fn ask_presentation_flow() -> PresentationFlow {
        println!(
            "Please enter the number to execute presentation flow:\n 1 - Cross Device\n 2 - Same device"
        );
        loop {
            let input = input_from_console("Failed to read selected presentation flow");
            match input.as_str() {
                "1" => return PresentationFlow::CrossDevice,
                "2" => return PresentationFlow::SameDevice,
                _ => println!("Invalid input, please retry"),
            }
        }
    }

    pub async fn ask_presentation_flow_request_uri() -> Url {
        let auth_request = map_to_verifier_request_uri_url(ask_presentation_auth_request().await);
        println!("Open verifier request_uri URL: {}", auth_request);
        println!("Then enter the request URI here:");
        let input = input_from_console("Failed to get the flow request URI");
        input
            .parse()
            .expect(format!("Incorrect URI: {input}").as_str())
    }

    pub async fn ask_presentation_auth_request() -> AuthRequestQuery {
        let query_type = ask_presentation_flow_query_type().await;
        let response_type = ask_presentation_flow_response_type();
        let response_mode = ask_presentation_flow_response_mode();

        AuthRequestQuery {
            response_type,
            response_mode,
            query_type,
        }
    }

    pub async fn ask_presentation_flow_query_type() -> PresentationQueryType {
        println!("Please enter 1 or 2 to select a query type:\n1. DCQL\n2. PresentationDefinition");
        loop {
            let input = input_from_console("Failed to get presentation flow");
            match input.as_str() {
                "1" => return PresentationQueryType::DCQL,
                "2" => return PresentationQueryType::PresentationDefinition,
                _ => println!("Invalid input, please retry"),
            };
        }
    }

    fn ask_presentation_flow_response_type() -> ResponseType {
        println!(
            "Please enter 1 or 2 to select a response type:\n1. vp_token\n2. vp_token id_token"
        );
        loop {
            let input = input_from_console("Failed to get presentation flow");
            match input.as_str() {
                "1" => return ResponseType::VpToken,
                "2" => return ResponseType::VpTokenIdToken,
                _ => println!("Invalid input, please retry"),
            };
        }
    }

    fn ask_presentation_flow_response_mode() -> ResponseMode {
        println!(
            "Please enter number 1-4 to select a response mode:\n1. direct_post\n2. direct_post.jwt\n3. fragment\n4. fragment.jwt"
        );
        loop {
            let input = input_from_console("Failed to get presentation flow");
            match input.as_str() {
                "1" => return ResponseMode::DirectPost,
                "2" => return ResponseMode::DirectPostJwt,
                "3" => return ResponseMode::Fragment,
                "4" => return ResponseMode::FragmentJwt,
                _ => println!("Invalid input, please retry"),
            };
        }
    }

    pub async fn ask_presentation_credential_selection_mode() -> CredentialSelectionMode {
        println!(
            "Please enter number to send presentation by:\n 1 - Auto\n 2 - Selecting from the credential list"
        );
        loop {
            let input = input_from_console("Failed to read selected presentation flow");
            match input.as_str() {
                "1" => return CredentialSelectionMode::Auto,
                "2" => return CredentialSelectionMode::ManualSelection,
                _ => println!("Invalid input, please retry"),
            }
        }
    }

    pub async fn ask_credential_selection() -> String {
        println!(
            "Please enter the selected credential by splitting \"id\" and selected \"index\" with \"=\" : for example: \"Identity-1=0,Identity-2=1,...\"`"
        );

        input_from_console("Failed to read the selected credential")
    }

    pub async fn ask_presentation_claims_exclusion_confirmation() -> bool {
        println!("Do you want to add claims to exclude?: y/n");
        loop {
            let input = input_from_console("Failed to read input");
            match input.as_str() {
                "y" => return true,
                "n" => return false,
                _ => println!("Invalid input, please retry"),
            }
        }
    }

    pub async fn ask_presentation_claims_to_exclude() -> HashMap<String, Vec<String>> {
        println!("Enter id of input descriptor: ");
        let id = input_from_console("Failed to read presentation mode");
        println!("Enter claim names to exclude (use space \" \" to split multiple entries): ");
        let claims = input_from_console("Failed to read presentation mode");
        let claims: Vec<String> = claims.split(' ').map(|s| s.to_string()).collect();
        let mut map = HashMap::new();
        map.insert(id, claims);
        map
    }

    pub async fn ask_auth_code_by_url(url: Url) -> Result<String, io::Error> {
        println!("Authorization URL. Authenticate with user \"tneal\" and password \"password\"");
        println!("{}", url);

        print!("Please enter an authorization code: ");
        let code = input_from_console("Failed to read auth code");

        Ok(code)
    }

    pub async fn ask_restart_after_revocation() -> bool {
        println!("Restart flow? y/n");
        loop {
            let input = input_from_console("Failed to read input");
            match input.as_str() {
                "y" => return true,
                "n" => return false,
                _ => println!("Invalid input, please retry"),
            }
        }
    }

    fn input_from_console(err_msg: &str) -> String {
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect(err_msg);

        input.trim().to_owned()
    }
}

#[cfg(feature = "noninteractive")]
pub mod auto {
    use crate::user_input::auto::CredentialOfferType::{Authorization, PreAuthorized};
    use crate::user_input::{
        CredentialSelectionMode, IssuerDiscoveryMode, PresentationFlow,
        map_to_verifier_request_uri_url,
    };
    use agent_sdk::vc::oid4vci::AuthzFlow;
    use agent_sdk::vc::oid4vp::{ResponseMode, ResponseType, Url};
    use shared::vp::{AuthRequestQuery, PresentationQueryType};
    use std::collections::HashMap;
    use std::io;

    pub async fn ask_issuer_discovery_mode() -> IssuerDiscoveryMode {
        IssuerDiscoveryMode::CredentialOffer
    }

    pub async fn ask_issuer_url() -> String {
        println!("Enter issuer URL");
        "http://localhost:8088".to_owned()
    }

    enum CredentialOfferType {
        Authorization,
        PreAuthorized,
    }

    impl CredentialOfferType {
        fn from_env() -> CredentialOfferType {
            match std::env::var("CREDENTIAL_OFFER_TYPE")
                .unwrap_or("PREAUTHORIZED".to_owned())
                .to_uppercase()
                .as_str()
            {
                "AUTHORIZATION" => Authorization,
                "PREAUTHORIZED" => PreAuthorized,
                _ => panic!(
                    "CREDENTIAL_OFFER_TYPE env var must be either AUTHORIZATION or PREAUTHORIZED"
                ),
            }
        }
    }

    pub async fn ask_offer() -> String {
        // Right now CredentialOfferType::PreAuthorized is supported only
        match CredentialOfferType::from_env() {
            Authorization => {
                reqwest::get("http://localhost:8088/create_credential_offer_uri_auth_code_grant")
                    .await
                    .expect("Couldn't get credential offer URI")
                    .text()
                    .await
                    .expect("Couldn't parse credential offer URI")
            }
            PreAuthorized => reqwest::get(
                "http://localhost:8088/create_credential_offer_uri_pre_auth_code_grant",
            )
            .await
            .expect("Couldn't get credential offer URI")
            .text()
            .await
            .expect("Couldn't parse credential offer URI"),
        }
    }

    pub async fn ask_auth_code_by_flow(_: AuthzFlow) -> String {
        "dummy".to_owned()
    }

    pub async fn ask_revocation_confirmation() -> bool {
        false
    }

    pub async fn ask_restart_after_revocation() -> bool {
        false
    }

    impl PresentationFlow {
        pub fn from_env() -> PresentationFlow {
            match std::env::var("PRESENTATION_FLOW")
                .unwrap_or("SAME_DEVICE".to_owned())
                .to_uppercase()
                .as_str()
            {
                "SAME_DEVICE" => PresentationFlow::SameDevice,
                "CROSS_DEVICE" => PresentationFlow::CrossDevice,
                _ => panic!("PRESENTATION_FLOW env var must be either SAME_DEVICE or CROSS_DEVICE"),
            }
        }
    }

    pub async fn ask_presentation_flow() -> PresentationFlow {
        PresentationFlow::from_env()
    }

    pub async fn ask_presentation_auth_request() -> AuthRequestQuery {
        let query_type = ask_presentation_flow_query_type().await;
        let response_type = presentation_flow_response_type_from_env();
        let response_mode = presentation_flow_response_mode_from_env();

        AuthRequestQuery {
            response_type,
            response_mode,
            query_type,
        }
    }

    pub async fn ask_presentation_flow_query_type() -> PresentationQueryType {
        match std::env::var("PRESENTATION_QUERY")
            .unwrap_or("DCQL".to_owned())
            .to_uppercase()
            .as_str()
        {
            "DCQL" => PresentationQueryType::DCQL,
            "DEFINITION" => PresentationQueryType::PresentationDefinition,
            _ => panic!("PRESENTATION_QUERY env var must be either DCQL or DEFINITION"),
        }
    }

    fn presentation_flow_response_type_from_env() -> ResponseType {
        match std::env::var("PRESENTATION_RESPONSE_TYPE")
            .unwrap_or("VP_TOKEN_ID_TOKEN".to_owned())
            .to_uppercase()
            .as_str()
        {
            "VP_TOKEN_ID_TOKEN" => ResponseType::VpTokenIdToken,
            "VP_TOKEN" => ResponseType::VpToken,
            _ => panic!(
                "PRESENTATION_RESPONSE_TYPE env var must be either VP_TOKEN_ID_TOKEN or VP_TOKEN"
            ),
        }
    }

    fn presentation_flow_response_mode_from_env() -> ResponseMode {
        match std::env::var("PRESENTATION_RESPONSE_MODE")
            .unwrap_or("DIRECT_POST_JWT".to_owned())
            .to_uppercase()
            .as_str()
        {
            "DIRECT_POST" => ResponseMode::DirectPost,
            "DIRECT_POST_JWT" => ResponseMode::DirectPostJwt,
            "FRAGMENT" => ResponseMode::Fragment,
            "FRAGMENT_JWT" => ResponseMode::FragmentJwt,
            _ => panic!(
                "PRESENTATION_RESPONSE_MODE env var must be one of DIRECT_POST, DIRECT_POST_JWT, FRAGMENT, FRAGMENT_JWT"
            ),
        }
    }

    pub async fn ask_presentation_flow_request_uri() -> Url {
        let verifier_url = map_to_verifier_request_uri_url(ask_presentation_auth_request().await);
        let url = reqwest::get(verifier_url)
            .await
            .expect("Couldn't access verifier")
            .text()
            .await
            .expect("Couldn't parse presentation flow URI");
        Url::parse(&url).expect("Couldn't parse presentation flow URI")
    }

    pub async fn ask_presentation_credential_selection_mode() -> CredentialSelectionMode {
        CredentialSelectionMode::Auto
    }

    pub async fn ask_credential_selection() -> String {
        unreachable!("Automated demo is not expected to ask for credential selection");
    }

    pub async fn ask_presentation_claims_exclusion_confirmation() -> bool {
        false
    }

    pub async fn ask_presentation_claims_to_exclude() -> HashMap<String, Vec<String>> {
        unreachable!("Automated demo is not expected to ask for presentation claims for exclusion");
    }

    pub async fn ask_auth_code_by_url(_: Url) -> Result<String, io::Error> {
        unreachable!()
    }
}
