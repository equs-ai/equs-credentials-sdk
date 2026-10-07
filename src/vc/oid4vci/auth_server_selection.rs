//! Picks the authorization server a holder uses, from the issuer metadata and an offer's grants.
//!
//! Both grants follow one rule: the server an offer names is used only when the issuer metadata
//! lists it (OID4VCI 1.0 §4.1.1).

use crate::http::HttpClient;
use crate::vc::oid4vci::internal_error::HolderServiceSnafu;
use crate::vc::oid4vci::metadata::MetadataDiscovery;
use crate::vc::oid4vci::{AuthorizationMetadata, CredentialOfferGrants, Error, IssuerMetadata};
use oid4vci::metadata::authorization_server::GrantType;
use oid4vci::types::IssuerUrl;
use tracing::{debug, warn};

/// The grant the holder will use, and the authorization server an offer names for it.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum AuthServerHint {
    PreAuthorized(Option<IssuerUrl>),
    AuthorizationCode(Option<IssuerUrl>),
}

impl AuthServerHint {
    /// A pre-authorized grant wins when an offer carries both, as the holder redeems it first.
    /// An offer without grants leaves the holder to run the authorization code grant.
    pub(super) fn from_grants(grants: Option<&CredentialOfferGrants>) -> Self {
        let Some(grants) = grants else {
            return Self::AuthorizationCode(None);
        };

        if let Some(grant) = &grants.pre_authorized_code {
            return Self::PreAuthorized(grant.authorization_server().cloned());
        }

        match &grants.authorization_code {
            Some(grant) => Self::AuthorizationCode(grant.authorization_server().cloned()),
            None => Self::AuthorizationCode(None),
        }
    }

    fn offered(&self) -> Option<&IssuerUrl> {
        match self {
            Self::PreAuthorized(offered) | Self::AuthorizationCode(offered) => offered.as_ref(),
        }
    }
}

/// Where the holder takes its authorization server metadata from.
#[derive(Debug, PartialEq)]
pub(super) enum AuthServerChoice {
    Issuer,
    Server(IssuerUrl),
    Servers(Vec<IssuerUrl>),
}

pub(super) fn select_authorization_server(
    issuer_metadata: &IssuerMetadata,
    hint: &AuthServerHint,
) -> AuthServerChoice {
    let Some(servers) = listed_servers(issuer_metadata) else {
        if let Some(offered) = hint.offered() {
            warn!(
                authorization_server = %offered.as_str(),
                "ignoring the offered authorization server: the issuer metadata lists none"
            );
        }
        return AuthServerChoice::Issuer;
    };

    if let Some(offered) = hint.offered() {
        if let Some(server) = listed_offered_server(issuer_metadata, offered) {
            debug!(
                authorization_server = %server.as_str(),
                "using the authorization server named by the offer"
            );
            return AuthServerChoice::Server(server);
        }
        warn!(
            authorization_server = %offered.as_str(),
            advertised = ?servers,
            "ignoring the offered authorization server: the issuer metadata does not list it"
        );
    }

    match hint {
        AuthServerHint::AuthorizationCode(_) if servers.len() > 1 => {
            AuthServerChoice::Servers(servers.to_vec())
        }
        _ => AuthServerChoice::Server(servers[0].clone()),
    }
}

/// The listed server equal to the one an offer names, or `None` when the issuer metadata does not
/// list it. The returned URL always comes from the metadata, never the offer.
pub(super) fn listed_offered_server(
    issuer_metadata: &IssuerMetadata,
    offered: &IssuerUrl,
) -> Option<IssuerUrl> {
    listed_servers(issuer_metadata)?
        .iter()
        .find(|server| *server == offered)
        .cloned()
}

fn listed_servers(issuer_metadata: &IssuerMetadata) -> Option<&[IssuerUrl]> {
    issuer_metadata
        .authorization_servers()
        .map(Vec::as_slice)
        .filter(|servers| !servers.is_empty())
}

fn supports_authorization_code(metadata: &AuthorizationMetadata) -> bool {
    metadata
        .grant_types_supported()
        .0
        .contains(&GrantType::AuthorizationCode)
        && metadata.authorization_endpoint().is_some()
        && metadata.pushed_authorization_request_endpoint().is_some()
}

/// Discovers the advertised servers in order and returns the first that supports the authorization
/// code flow. A server whose metadata cannot be fetched is skipped. When none supports it, the first
/// discovered server is used.
pub(super) async fn discover_first_supporting_authorization_code<HC: HttpClient>(
    http_client: &HC,
    servers: &[IssuerUrl],
) -> Result<AuthorizationMetadata, Error> {
    let mut first_discovered: Option<AuthorizationMetadata> = None;
    let mut last_error: Option<Error> = None;

    for server in servers {
        let metadata = match MetadataDiscovery::discover_metadata::<_, AuthorizationMetadata>(
            http_client,
            server,
        )
        .await
        {
            Ok(metadata) => metadata,
            Err(e) => {
                warn!(
                    authorization_server = %server.as_str(),
                    error = ?e,
                    "could not discover the authorization server metadata, trying the next one"
                );
                last_error = Some(e.into());
                continue;
            }
        };

        if supports_authorization_code(&metadata) {
            debug!(
                authorization_server = %server.as_str(),
                "using the first advertised authorization server supporting the authorization code flow"
            );
            return Ok(metadata);
        }

        debug!(
            authorization_server = %server.as_str(),
            "skipping an authorization server that cannot serve the authorization code flow"
        );
        first_discovered.get_or_insert(metadata);
    }

    if let Some(metadata) = first_discovered {
        warn!(
            advertised = ?servers,
            "no advertised authorization server supports the authorization code flow, using the first discovered one"
        );
        return Ok(metadata);
    }

    // Selection only asks for this with at least two servers, so every one of them failed
    Err(last_error.unwrap_or_else(|| {
        HolderServiceSnafu {
            details: "the issuer advertises no authorization server",
        }
        .build()
        .into()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vc::oid4vci::tests::fixtures::{AUTH_URL, SECOND_AUTH_URL, SampleIssuerMetadata};
    use crate::vc::oid4vci::{AuthorizationCodeGrant, PreAuthorizedCode, PreAuthorizedCodeGrant};
    use rstest::rstest;
    use serde_json::json;

    /// What `select_authorization_server` returned, in a form a test case can spell out
    const BY_CAPABILITY: &str = "first supporting the authorization code flow";
    const ISSUER_ITSELF: &str = "the issuer itself";
    const UNLISTED_AUTH_URL: &str = "https://attacker-authz.com";

    #[rstest]
    #[case::offered_among_several(json!([AUTH_URL, SECOND_AUTH_URL]), Some(SECOND_AUTH_URL), SECOND_AUTH_URL)]
    #[case::offered_is_the_first_of_several(json!([AUTH_URL, SECOND_AUTH_URL]), Some(AUTH_URL), AUTH_URL)]
    #[case::offered_is_the_only_one(json!([SECOND_AUTH_URL]), Some(SECOND_AUTH_URL), SECOND_AUTH_URL)]
    #[case::offered_differs_from_the_only_one(json!([AUTH_URL]), Some(SECOND_AUTH_URL), AUTH_URL)]
    #[case::none_offered_and_only_one_listed(json!([SECOND_AUTH_URL]), None, SECOND_AUTH_URL)]
    #[case::offered_is_not_listed(json!([AUTH_URL, SECOND_AUTH_URL]), Some(UNLISTED_AUTH_URL), BY_CAPABILITY)]
    #[case::offered_differs_by_a_trailing_slash(json!([AUTH_URL, SECOND_AUTH_URL]), Some("https://second-authz-backend.com/"), BY_CAPABILITY)]
    #[case::none_offered(json!([AUTH_URL, SECOND_AUTH_URL]), None, BY_CAPABILITY)]
    #[case::metadata_lists_none(serde_json::Value::Null, Some(SECOND_AUTH_URL), ISSUER_ITSELF)]
    #[case::metadata_lists_an_empty_array(json!([]), Some(SECOND_AUTH_URL), ISSUER_ITSELF)]
    fn authorization_code_grant_selects_the_server_to_discover(
        #[case] advertised: serde_json::Value,
        #[case] offered: Option<&str>,
        #[case] expected: &str,
    ) {
        let selected = select_authorization_server(
            &issuer_metadata_listing(advertised),
            &AuthServerHint::AuthorizationCode(offered.map(issuer_url)),
        );

        assert_eq!(describe(&selected), expected);
    }

    #[rstest]
    #[case::offered_among_several(json!([AUTH_URL, SECOND_AUTH_URL]), Some(SECOND_AUTH_URL), SECOND_AUTH_URL)]
    #[case::offered_is_not_listed(json!([AUTH_URL, SECOND_AUTH_URL]), Some(UNLISTED_AUTH_URL), AUTH_URL)]
    #[case::none_offered(json!([AUTH_URL, SECOND_AUTH_URL]), None, AUTH_URL)]
    #[case::offered_differs_from_the_only_one(json!([AUTH_URL]), Some(SECOND_AUTH_URL), AUTH_URL)]
    #[case::metadata_lists_none(serde_json::Value::Null, Some(SECOND_AUTH_URL), ISSUER_ITSELF)]
    fn pre_authorized_grant_selects_the_server_to_discover(
        #[case] advertised: serde_json::Value,
        #[case] offered: Option<&str>,
        #[case] expected: &str,
    ) {
        let selected = select_authorization_server(
            &issuer_metadata_listing(advertised),
            &AuthServerHint::PreAuthorized(offered.map(issuer_url)),
        );

        assert_eq!(describe(&selected), expected);
    }

    #[rstest]
    #[case::listed(json!([AUTH_URL, SECOND_AUTH_URL]), SECOND_AUTH_URL, Some(SECOND_AUTH_URL))]
    #[case::not_listed(json!([AUTH_URL, SECOND_AUTH_URL]), UNLISTED_AUTH_URL, None)]
    #[case::differs_by_a_trailing_slash(json!([AUTH_URL]), "https://authz-backend.com/", None)]
    #[case::metadata_lists_none(serde_json::Value::Null, AUTH_URL, None)]
    fn honours_an_offered_server_only_when_the_issuer_lists_it(
        #[case] advertised: serde_json::Value,
        #[case] offered: &str,
        #[case] expected: Option<&str>,
    ) {
        let listed =
            listed_offered_server(&issuer_metadata_listing(advertised), &issuer_url(offered));

        assert_eq!(listed, expected.map(issuer_url));
    }

    #[rstest]
    #[case::no_grants(None, AuthServerHint::AuthorizationCode(None))]
    #[case::neither_grant(Some(grants(None, None)), AuthServerHint::AuthorizationCode(None))]
    #[case::authorization_code_naming_a_server(
        Some(grants(Some(Some(SECOND_AUTH_URL)), None)),
        AuthServerHint::AuthorizationCode(Some(issuer_url(SECOND_AUTH_URL)))
    )]
    #[case::pre_authorized_naming_a_server(
        Some(grants(None, Some(Some(SECOND_AUTH_URL)))),
        AuthServerHint::PreAuthorized(Some(issuer_url(SECOND_AUTH_URL)))
    )]
    #[case::both_grants_prefer_the_pre_authorized_one(
        Some(grants(Some(Some(SECOND_AUTH_URL)), Some(None))),
        AuthServerHint::PreAuthorized(None)
    )]
    fn derives_the_hint_from_the_offer_grants(
        #[case] grants: Option<CredentialOfferGrants>,
        #[case] expected: AuthServerHint,
    ) {
        assert_eq!(AuthServerHint::from_grants(grants.as_ref()), expected);
    }

    fn describe(choice: &AuthServerChoice) -> String {
        match choice {
            AuthServerChoice::Issuer => ISSUER_ITSELF.to_string(),
            AuthServerChoice::Server(server) => server.as_str().to_string(),
            AuthServerChoice::Servers(servers) => {
                // Capability selection must try every listed server, in the listed order
                let listed = [AUTH_URL, SECOND_AUTH_URL].map(issuer_url);
                assert_eq!(servers.as_slice(), listed.as_slice());
                BY_CAPABILITY.to_string()
            }
        }
    }

    fn issuer_metadata_listing(advertised: serde_json::Value) -> IssuerMetadata {
        let mut metadata = serde_json::to_value(SampleIssuerMetadata::with_sdjwtvc_conf()).unwrap();
        if advertised.is_null() {
            metadata
                .as_object_mut()
                .unwrap()
                .remove("authorization_servers");
        } else {
            metadata["authorization_servers"] = advertised;
        }
        serde_json::from_value(metadata).unwrap()
    }

    fn issuer_url(url: &str) -> IssuerUrl {
        IssuerUrl::new(url.to_string()).unwrap()
    }

    /// Each present grant is given as the server it names, if any
    fn grants(
        authorization_code: Option<Option<&str>>,
        pre_authorized_code: Option<Option<&str>>,
    ) -> CredentialOfferGrants {
        let authorization_code = authorization_code.map(|server| {
            AuthorizationCodeGrant::new(None, None).set_authorization_server(server.map(issuer_url))
        });
        let pre_authorized_code = pre_authorized_code.map(|server| {
            PreAuthorizedCodeGrant::new(PreAuthorizedCode::new("pre_auth_code".to_string()))
                .set_authorization_server(server.map(issuer_url))
        });
        CredentialOfferGrants::new(authorization_code, pre_authorized_code)
    }
}
