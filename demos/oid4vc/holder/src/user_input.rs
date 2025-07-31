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

pub enum ResolvedPresentationQueryType {
    Dcql,
    PresentationDefinition,
}

#[cfg(not(feature = "noninteractive"))]
pub mod cli {
    use crate::user_input::{
        CredentialSelectionMode, IssuerDiscoveryMode, PresentationFlow,
        ResolvedPresentationQueryType,
    };
    use agent_sdk::vc::oid4vci::AuthzFlow;
    use agent_sdk::vc::oid4vp::Url;
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
        println!("Please enter the presentation flow request URI type from the following:");
        println!(
            "- If you  want to use DCQL flow, go to http://localhost:8098/request_uri/dcql and enter request URI from there"
        );
        println!(
            "- If you want to use PresentationDefinition flow, go to http://localhost:8098/request_uri and enter request URI from there"
        );
        println!("Enter the request URI here:");
        let input = input_from_console("Failed to get the flow request URI");
        input
            .parse()
            .expect(format!("Incorrect URI: {input}").as_str())
    }

    pub async fn ask_presentation_flow_query_type() -> ResolvedPresentationQueryType {
        println!(
            "Please enter the flow type:\n1. Use DCQL flow\n2. Use PresentationDefinition flow"
        );
        loop {
            let input = input_from_console("Failed to get presentation flow");
            match input.as_str() {
                "1" => return ResolvedPresentationQueryType::Dcql,
                "2" => return ResolvedPresentationQueryType::PresentationDefinition,
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
        ResolvedPresentationQueryType,
    };
    use agent_sdk::vc::oid4vci::AuthzFlow;
    use agent_sdk::vc::oid4vp::Url;
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

    impl ResolvedPresentationQueryType {
        pub fn from_env() -> ResolvedPresentationQueryType {
            match std::env::var("PRESENTATION_QUERY")
                .unwrap_or("DCQL".to_owned())
                .to_uppercase()
                .as_str()
            {
                "DCQL" => ResolvedPresentationQueryType::Dcql,
                "DEFINITION" => ResolvedPresentationQueryType::PresentationDefinition,
                _ => panic!("PRESENTATION_QUERY env var must be either DCQL or DEFINITION"),
            }
        }
    }

    pub async fn ask_presentation_flow_request_uri() -> Url {
        let url = match ResolvedPresentationQueryType::from_env() {
            ResolvedPresentationQueryType::Dcql => {
                reqwest::get("http://localhost:8098/request_uri/dcql")
                    .await
                    .expect("Couldn't get presentation flow")
                    .text()
                    .await
                    .expect("Couldn't parse presentation flow URI")
            }
            ResolvedPresentationQueryType::PresentationDefinition => {
                reqwest::get("http://localhost:8098/request_uri")
                    .await
                    .expect("Couldn't get presentation flow")
                    .text()
                    .await
                    .expect("Couldn't parse presentation flow URI")
            }
        };
        Url::parse(&url).expect("Couldn't parse presentation flow URI")
    }

    pub async fn ask_presentation_flow_query_type() -> ResolvedPresentationQueryType {
        ResolvedPresentationQueryType::from_env()
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
