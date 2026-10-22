use crate::http::HttpClient;
use crate::utils::certificate_validator::SharedCertificateValidator;
use crate::utils::one_core_http::OneCoreHttpClientAdapter;
use crate::vc::trust::issuer::TrustAnchor;
use common_macros::DebugError;
use one_core::config::core_config::KeyAlgorithmType;
use one_core::proto::certificate_validator::CertificateValidator;
use one_core::proto::clock::DefaultClock;
use one_core::proto::http_client::HttpClient as OneCoreHttpClient;
use one_core::proto::http_client::reqwest_client::ReqwestClient;
use one_core::provider::key_algorithm::{
    KeyAlgorithm, ecdsa::Ecdsa, eddsa::Eddsa, provider::KeyAlgorithmProviderImpl,
};
use one_core::provider::trust_list_subscriber::export::{
    ExportPolicy, LoteContentType, TrustListExporter,
};
use one_core::provider::trust_list_subscriber::fetch::{FetchError, FetchLimits};
use snafu::{Location, Snafu};
use std::sync::Arc;
use std::time::Duration;
use tracing::{Level, info, instrument};
use url::Url;

pub use one_core::provider::trust_list_subscriber::export::{
    AnchorRole, ExcludedService, TrustListAnchor, TrustListExport, TrustListKind,
};
pub use one_core::provider::trust_list_subscriber::fetch::{SkipReason, SkippedMember};

/// Largest accepted [ExportOptions::leeway]; more would defeat the expiry checks.
pub const MAX_LEEWAY: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(DebugError, Snafu)]
#[non_exhaustive]
pub enum TrustListError {
    /// The location is not an `https` URL.
    #[snafu(display("trust_list_invalid_url: {details}"))]
    InvalidUrl {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    /// An option or the list kind is out of range.
    #[snafu(display("trust_list_invalid_options: {details}"))]
    InvalidOptions {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    /// The export failed for `reason`.
    #[snafu(display("trust_list_{}: {details}", reason.as_str()))]
    Export {
        reason: ExportFailure,
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl TrustListError {
    /// Stable machine-readable code, `trust_list_<reason>`, e.g. `trust_list_signer_not_trusted`.
    pub fn code(&self) -> String {
        match self {
            Self::InvalidUrl { .. } => "trust_list_invalid_url".to_string(),
            Self::InvalidOptions { .. } => "trust_list_invalid_options".to_string(),
            Self::Export { reason, .. } => format!("trust_list_{}", reason.as_str()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportFailure {
    Unreachable,
    SizeLimit,
    PointerLimit,
    InvalidDocument,
    InvalidSignature,
    UnsupportedAlgorithm,
    /// The root's signer neither equals nor chains to a supplied trust anchor.
    SignerNotTrusted,
    Expired,
    /// The list has no `NextUpdate`.
    Closed,
    /// No trust anchors were supplied and an unpinned root was not allowed.
    UnpinnedNotAllowed,
    /// The root was not authenticated within [ExportOptions::deadline].
    Deadline,
    /// The HTTP client could not be set up (e.g. its TLS configuration).
    HttpClient,
}

impl ExportFailure {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::SizeLimit => "size_limit",
            Self::PointerLimit => "pointer_limit",
            Self::InvalidDocument => "invalid_document",
            Self::InvalidSignature => "invalid_signature",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::SignerNotTrusted => "signer_not_trusted",
            Self::Expired => "expired",
            Self::Closed => "closed",
            Self::UnpinnedNotAllowed => "unpinned_not_allowed",
            Self::Deadline => "deadline",
            Self::HttpClient => "http_client",
        }
    }
}

impl From<&FetchError> for ExportFailure {
    fn from(error: &FetchError) -> Self {
        match error {
            FetchError::Unreachable(_) | FetchError::Http(_) => Self::Unreachable,
            FetchError::SizeLimit(_) => Self::SizeLimit,
            FetchError::PointerLimit(_) => Self::PointerLimit,
            FetchError::InvalidDocument(_) => Self::InvalidDocument,
            FetchError::InvalidSignature(_) => Self::InvalidSignature,
            FetchError::UnsupportedAlgorithm(_) => Self::UnsupportedAlgorithm,
            FetchError::SignerNotTrusted => Self::SignerNotTrusted,
            FetchError::Expired => Self::Expired,
            FetchError::Closed => Self::Closed,
            FetchError::UnpinnedNotAllowed => Self::UnpinnedNotAllowed,
            FetchError::Deadline => Self::Deadline,
        }
    }
}

/// The list kind named `lotl_119612` or `lote_119602`.
pub fn trust_list_kind(name: &str) -> Result<TrustListKind, TrustListError> {
    match name {
        "lotl_119612" => Ok(TrustListKind::Lotl119612),
        "lote_119602" => Ok(TrustListKind::Lote119602),
        other => InvalidOptionsSnafu {
            details: format!(
                "unknown trust list kind `{other}`, expected `lotl_119612` or `lote_119602`"
            ),
        }
        .fail(),
    }
}

/// The name of an anchor role, e.g. `pid_provider`.
pub fn anchor_role_name(role: AnchorRole) -> &'static str {
    match role {
        AnchorRole::PidProvider => "pid_provider",
        AnchorRole::QeaaProvider => "qeaa_provider",
        AnchorRole::PubEaaProvider => "pub_eaa_provider",
        AnchorRole::EaaProvider => "eaa_provider",
        AnchorRole::WalletProvider => "wallet_provider",
        AnchorRole::WrpAcProvider => "wrp_ac_provider",
        AnchorRole::WrpRcProvider => "wrp_rc_provider",
        AnchorRole::Registrar => "registrar",
    }
}

/// A verifier anchor whose `source_ref` is the granting list.
impl From<&TrustListAnchor> for TrustAnchor {
    fn from(anchor: &TrustListAnchor) -> Self {
        Self {
            pem: anchor.pem.clone(),
            source_ref: Some(anchor.source_url.clone()),
            role: anchor.role.map(|role| anchor_role_name(role).to_string()),
            service_type: anchor.service_type.clone(),
        }
    }
}

/// Format of a root LoTE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LoteRepresentation {
    #[default]
    Jwt,
    Xml,
}

/// How a trust list export is authenticated and bounded.
#[derive(Clone, Debug)]
pub struct ExportOptions {
    /// PEMs the root signer must equal or chain to. Required unless `allow_unpinned_root`.
    pub trust_anchors: Vec<String>,
    /// Accept the root's embedded signer (development and tests only); marks the export `unpinned`.
    pub allow_unpinned_root: bool,
    /// Clock tolerance for `NextUpdate` and signing times; at most [MAX_LEEWAY].
    pub leeway: Duration,
    pub lote_representation: LoteRepresentation,
    /// Maximum `PointersToOtherLoTE` depth per LoTE. `Some(0)` follows none; `None` is bounded only
    /// by `max_pointers`.
    pub max_pointer_depth: Option<usize>,
    /// Maximum size of each document, in bytes; more than zero.
    pub max_document_bytes: Option<usize>,
    /// Maximum pointers followed in the whole export.
    pub max_pointers: Option<usize>,
    /// Deadline for the whole export. A late root fails it; late members are skipped (`deadline`).
    pub deadline: Option<Duration>,
    /// Time to fetch and authenticate one member list.
    pub document_timeout: Option<Duration>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            trust_anchors: vec![],
            allow_unpinned_root: false,
            leeway: Duration::from_secs(300),
            lote_representation: LoteRepresentation::Jwt,
            max_pointer_depth: Some(5),
            max_document_bytes: None,
            max_pointers: None,
            deadline: None,
            document_timeout: None,
        }
    }
}

/// Fetches and authenticates the list at `url` and its members, and returns the anchors they
/// grant. Failed members are listed in `skipped_members`.
#[instrument(level = Level::TRACE, skip(options), err())]
pub async fn export_trust_list(
    url: &str,
    kind: TrustListKind,
    options: &ExportOptions,
) -> Result<TrustListExport, TrustListError> {
    let (url, policy) = validate(url, options)?;
    let client = ReqwestClient::hardened(policy.limits.max_document_bytes).map_err(|e| {
        ExportSnafu {
            reason: ExportFailure::HttpClient,
            details: e.to_string(),
        }
        .build()
    })?;
    export(Arc::new(client), &url, kind, &policy).await
}

/// [export_trust_list] with a custom client, which must refuse redirects and bound response sizes.
#[instrument(level = Level::TRACE, skip(http_client, options), err())]
pub async fn export_trust_list_with_client(
    http_client: Arc<dyn HttpClient>,
    url: &str,
    kind: TrustListKind,
    options: &ExportOptions,
) -> Result<TrustListExport, TrustListError> {
    let (url, policy) = validate(url, options)?;
    let client = OneCoreHttpClientAdapter::new(http_client);
    export(Arc::new(client), &url, kind, &policy).await
}

/// Validates the root location and `options`.
fn validate(url: &str, options: &ExportOptions) -> Result<(Url, ExportPolicy), TrustListError> {
    let url = Url::parse(url).map_err(|e| {
        InvalidUrlSnafu {
            details: e.to_string(),
        }
        .build()
    })?;
    if url.scheme() != "https" {
        return InvalidUrlSnafu {
            details: format!("scheme `{}` is not allowed, only `https`", url.scheme()),
        }
        .fail();
    }
    let invalid = |details: &str| {
        InvalidOptionsSnafu {
            details: details.to_string(),
        }
        .build()
    };
    if options.leeway > MAX_LEEWAY {
        return Err(invalid("leeway exceeds 24 hours"));
    }
    if options.max_document_bytes == Some(0) {
        return Err(invalid("max_document_bytes must be more than zero"));
    }
    if options
        .document_timeout
        .is_some_and(|document_timeout| document_timeout.is_zero())
    {
        return Err(invalid("document_timeout must be more than zero"));
    }
    if options.deadline.is_some_and(|deadline| deadline.is_zero()) {
        return Err(invalid("deadline must be more than zero"));
    }

    let defaults = FetchLimits::default();
    let policy = ExportPolicy {
        trust_anchors: options.trust_anchors.clone(),
        allow_unpinned_root: options.allow_unpinned_root,
        leeway: time::Duration::try_from(options.leeway)
            .map_err(|_| invalid("leeway is out of range"))?,
        limits: FetchLimits {
            max_document_bytes: options
                .max_document_bytes
                .unwrap_or(defaults.max_document_bytes),
            max_pointers: options.max_pointers.unwrap_or(defaults.max_pointers),
            allow_http: false,
            deadline: options.deadline.unwrap_or(defaults.deadline),
            document_timeout: options
                .document_timeout
                .unwrap_or(defaults.document_timeout),
        },
        lote_content_type: match options.lote_representation {
            LoteRepresentation::Jwt => LoteContentType::Jwt,
            LoteRepresentation::Xml => LoteContentType::Xml,
        },
        max_pointer_depth: options.max_pointer_depth,
    };
    Ok((url, policy))
}

async fn export(
    client: Arc<dyn OneCoreHttpClient>,
    url: &Url,
    kind: TrustListKind,
    policy: &ExportPolicy,
) -> Result<TrustListExport, TrustListError> {
    let certificate_validator: Arc<dyn CertificateValidator> =
        Arc::new(SharedCertificateValidator::get());
    let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(
        std::collections::HashMap::from_iter([
            (
                KeyAlgorithmType::Eddsa,
                Arc::new(Eddsa) as Arc<dyn KeyAlgorithm>,
            ),
            (
                KeyAlgorithmType::Ecdsa,
                Arc::new(Ecdsa) as Arc<dyn KeyAlgorithm>,
            ),
        ]),
        Default::default(),
    ));
    let exporter = TrustListExporter::new(
        Arc::new(DefaultClock),
        client,
        key_algorithm_provider,
        certificate_validator,
    );

    let export = exporter.export(url, kind, policy).await.map_err(|error| {
        ExportSnafu {
            reason: ExportFailure::from(&error),
            details: error.to_string(),
        }
        .build()
    })?;
    info!(
        anchors = export.anchors.len(),
        skipped = export.skipped_members.len(),
        unpinned = export.unpinned,
        "trust list exported"
    );
    Ok(export)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HeaderName, HeaderValue, HttpResponse, MockHttpClient};
    use serde_json::json;

    const LOTE_URL: &str = "https://lote.example.com/pid-providers.jwt";
    const PID_LOTE_TYPE: &str = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";
    const NOT_A_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";

    /// A signed PID providers LoTE JWT: returns the token, the signer PEM and the listed PEM.
    fn pid_lote(overrides: serde_json::Value) -> (String, String, String) {
        let certificate = |cn: &str, key: &test_fixtures::JWK| {
            test_fixtures::x509(
                &json!({
                    "subject": [["CN", cn]],
                    "not_before": "2026-01-01", "not_after": "2046-01-01",
                    "key_usages": ["digital_signature"]
                }),
                key,
                None,
            )
        };
        let signer_key = test_fixtures::JWK::generate_p256();
        let signer = certificate("LoTE Scheme Operator", &signer_key);
        let listed = certificate("PID Provider", &test_fixtures::JWK::generate_p256());
        let mut spec = json!({
            "lote_type": PID_LOTE_TYPE,
            "entities": [{ "name": "Test PID Provider", "certificates": [listed] }]
        });
        for (name, value) in overrides.as_object().into_iter().flatten() {
            spec[name] = value.clone();
        }
        let token = test_fixtures::lote(&spec, &signer, &signer_key);
        (token, signer, listed)
    }

    /// Serves `body` as `content_type` at every location.
    fn serving(body: String, content_type: &'static str) -> Arc<MockHttpClient> {
        let mut http_client = MockHttpClient::new();
        http_client.expect_async_call().returning(move |_| {
            let mut response = HttpResponse::new(body.clone().into_bytes());
            response.headers_mut().insert(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static(content_type),
            );
            Ok(response)
        });
        Arc::new(http_client)
    }

    fn pinned_to(signer: &str) -> ExportOptions {
        ExportOptions {
            trust_anchors: vec![signer.to_string()],
            ..Default::default()
        }
    }

    async fn export_lote(
        http_client: Arc<MockHttpClient>,
        options: &ExportOptions,
    ) -> Result<TrustListExport, TrustListError> {
        export_trust_list_with_client(http_client, LOTE_URL, TrustListKind::Lote119602, options)
            .await
    }

    #[tokio::test]
    async fn lote_pinned_to_its_signer_exports_its_listed_certificates() {
        let (lote, signer, listed) = pid_lote(json!({ "sequence_number": 7 }));

        let export = export_lote(serving(lote, "application/jwt"), &pinned_to(&signer))
            .await
            .unwrap();

        assert!(!export.unpinned);
        assert_eq!(export.sequence_number, 7);
        // a LoTE exported directly is the root: its anchors' NextUpdate is the root's
        assert!(
            export
                .anchors
                .iter()
                .all(|anchor| anchor.source_next_update == export.next_update)
        );
        assert_eq!(export.anchors.len(), 1);
        let anchor = TrustAnchor::from(&export.anchors[0]);
        assert_eq!(anchor.pem.trim(), listed.trim());
        assert_eq!(anchor.source_ref.as_deref(), Some(LOTE_URL));
        assert_eq!(anchor.role.as_deref(), Some("pid_provider"));
    }

    #[tokio::test]
    async fn lote_in_the_eu_format_is_exported() {
        // the LoTE in a `LoTE` member, `typ: JOSE+JSON`, and services without a status
        let (lote, signer, listed) = pid_lote(json!({ "eu_format": true }));

        let export = export_lote(serving(lote, "application/jwt"), &pinned_to(&signer))
            .await
            .unwrap();

        assert_eq!(export.anchors.len(), 1);
        let anchor = TrustAnchor::from(&export.anchors[0]);
        assert_eq!(anchor.pem.trim(), listed.trim());
        assert_eq!(anchor.role.as_deref(), Some("pid_provider"));
    }

    #[tokio::test]
    async fn lote_signed_by_another_key_than_the_pinned_one_is_refused() {
        let (lote, _, _) = pid_lote(json!({}));
        let (_, other_signer, _) = pid_lote(json!({}));

        let error = export_lote(serving(lote, "application/jwt"), &pinned_to(&other_signer))
            .await
            .unwrap_err();

        assert_eq!(error.code(), "trust_list_signer_not_trusted", "{error}");
    }

    #[tokio::test]
    async fn unpinned_root_is_exported_when_allowed_and_is_marked() {
        let (lote, _, _) = pid_lote(json!({}));

        let export = export_lote(
            serving(lote, "application/jwt"),
            &ExportOptions {
                allow_unpinned_root: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(export.unpinned);
        assert_eq!(export.anchors.len(), 1);
    }

    #[tokio::test]
    async fn export_without_anchors_is_refused_before_fetching() {
        let error = export_lote(Arc::new(MockHttpClient::new()), &ExportOptions::default())
            .await
            .unwrap_err();

        assert_eq!(error.code(), "trust_list_unpinned_not_allowed");
    }

    #[tokio::test]
    async fn expired_lote_is_refused() {
        let (lote, signer, _) = pid_lote(json!({ "next_update": "2026-02-01T00:00:00Z" }));

        let error = export_lote(serving(lote, "application/jwt"), &pinned_to(&signer))
            .await
            .unwrap_err();

        assert_eq!(error.code(), "trust_list_expired", "{error}");
    }

    #[tokio::test]
    async fn lote_just_past_its_next_update_is_accepted_within_the_leeway() {
        let next_update = (time::OffsetDateTime::now_utc() - time::Duration::hours(1))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let (lote, signer, _) = pid_lote(json!({ "next_update": next_update }));

        let export = export_lote(
            serving(lote, "application/jwt"),
            &ExportOptions {
                leeway: Duration::from_secs(2 * 60 * 60),
                ..pinned_to(&signer)
            },
        )
        .await
        .unwrap();

        assert_eq!(export.anchors.len(), 1);
    }

    #[tokio::test]
    async fn oversized_root_is_refused() {
        let (lote, signer, _) = pid_lote(json!({}));

        let error = export_lote(
            serving(lote, "application/jwt"),
            &ExportOptions {
                max_document_bytes: Some(64),
                ..pinned_to(&signer)
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), "trust_list_size_limit", "{error}");
    }

    #[rstest::rstest]
    #[case::wrong_media_type("text/plain", LoteRepresentation::Jwt)]
    #[case::jwt_where_xml_is_expected("application/jwt", LoteRepresentation::Xml)]
    #[tokio::test]
    async fn lote_of_another_representation_is_refused(
        #[case] content_type: &'static str,
        #[case] lote_representation: LoteRepresentation,
    ) {
        let (lote, signer, _) = pid_lote(json!({}));

        let error = export_lote(
            serving(lote, content_type),
            &ExportOptions {
                lote_representation,
                ..pinned_to(&signer)
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), "trust_list_invalid_document", "{error}");
    }

    #[tokio::test]
    async fn lotl_kind_reads_the_root_as_a_list_of_trusted_lists() {
        let (lote, signer, _) = pid_lote(json!({}));

        // a LoTE JWT is not a TS 119 612 XML list
        let error = export_trust_list_with_client(
            serving(lote, "application/vnd.etsi.tsl+xml"),
            "https://lotl.example.com/eu-lotl.xml",
            TrustListKind::Lotl119612,
            &pinned_to(&signer),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), "trust_list_invalid_document", "{error}");
    }

    #[tokio::test]
    async fn unreachable_root_has_a_stable_code_and_keeps_its_cause() {
        let mut http_client = MockHttpClient::new();
        http_client.expect_async_call().returning(|_| {
            Err(crate::http::HttpSnafu {
                details: "connection refused",
            }
            .build())
        });

        let error = export_lote(Arc::new(http_client), &pinned_to(NOT_A_CERTIFICATE))
            .await
            .unwrap_err();

        assert_eq!(error.code(), "trust_list_unreachable", "{error}");
        assert!(error.to_string().contains("connection refused"), "{error}");
    }

    #[rstest::rstest]
    #[case::not_a_url("not a url")]
    #[case::http_root("http://lote.example.com/list.jwt")]
    #[tokio::test]
    async fn root_location_must_be_an_https_url(#[case] url: &str) {
        let error = export_trust_list_with_client(
            Arc::new(MockHttpClient::new()),
            url,
            TrustListKind::Lote119602,
            &pinned_to(NOT_A_CERTIFICATE),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), "trust_list_invalid_url");
    }

    #[rstest::rstest]
    #[case::leeway_over_a_day(ExportOptions {
        leeway: MAX_LEEWAY + Duration::from_secs(1),
        ..Default::default()
    })]
    #[case::empty_document_limit(ExportOptions {
        max_document_bytes: Some(0),
        ..Default::default()
    })]
    #[case::zero_deadline(ExportOptions { deadline: Some(Duration::ZERO), ..Default::default() })]
    #[case::zero_document_timeout(ExportOptions {
        document_timeout: Some(Duration::ZERO),
        ..Default::default()
    })]
    #[tokio::test]
    async fn out_of_range_options_are_refused(#[case] options: ExportOptions) {
        let options = ExportOptions {
            trust_anchors: vec![NOT_A_CERTIFICATE.to_string()],
            ..options
        };

        let error = export_lote(Arc::new(MockHttpClient::new()), &options)
            .await
            .unwrap_err();

        assert_eq!(error.code(), "trust_list_invalid_options");
    }

    #[test]
    fn options_reach_the_one_core_policy() {
        let (_, policy) = validate(
            LOTE_URL,
            &ExportOptions {
                trust_anchors: vec!["anchor".to_string()],
                allow_unpinned_root: true,
                leeway: Duration::from_secs(60),
                lote_representation: LoteRepresentation::Xml,
                max_pointer_depth: Some(2),
                max_document_bytes: Some(1024),
                max_pointers: Some(3),
                deadline: Some(Duration::from_secs(9)),
                document_timeout: Some(Duration::from_secs(4)),
            },
        )
        .unwrap();

        assert_eq!(policy.trust_anchors, ["anchor"]);
        assert!(policy.allow_unpinned_root);
        assert_eq!(policy.leeway, time::Duration::seconds(60));
        assert!(matches!(policy.lote_content_type, LoteContentType::Xml));
        assert_eq!(policy.max_pointer_depth, Some(2));
        assert_eq!(policy.limits.max_document_bytes, 1024);
        assert_eq!(policy.limits.max_pointers, 3);
        assert_eq!(policy.limits.deadline, Duration::from_secs(9));
        assert_eq!(policy.limits.document_timeout, Duration::from_secs(4));
        assert!(!policy.limits.allow_http);
    }

    #[test]
    fn unset_limits_take_one_core_defaults() {
        let (_, policy) = validate(LOTE_URL, &ExportOptions::default()).unwrap();

        let defaults = FetchLimits::default();
        assert_eq!(
            policy.limits.max_document_bytes,
            defaults.max_document_bytes
        );
        assert_eq!(policy.limits.max_pointers, defaults.max_pointers);
        assert_eq!(policy.limits.deadline, defaults.deadline);
        assert_eq!(policy.limits.document_timeout, defaults.document_timeout);
        assert_eq!(policy.max_pointer_depth, Some(5));
    }

    #[test]
    fn every_fetch_error_has_its_own_code() {
        let errors = [
            FetchError::Unreachable(String::new()),
            FetchError::SizeLimit(0),
            FetchError::PointerLimit(String::new()),
            FetchError::InvalidDocument(String::new()),
            FetchError::InvalidSignature(String::new()),
            FetchError::UnsupportedAlgorithm(String::new()),
            FetchError::SignerNotTrusted,
            FetchError::Expired,
            FetchError::Closed,
            FetchError::UnpinnedNotAllowed,
            FetchError::Deadline,
        ];

        let codes: Vec<_> = errors
            .iter()
            .map(|error| ExportFailure::from(error).as_str())
            .collect();

        assert_eq!(
            codes,
            [
                "unreachable",
                "size_limit",
                "pointer_limit",
                "invalid_document",
                "invalid_signature",
                "unsupported_algorithm",
                "signer_not_trusted",
                "expired",
                "closed",
                "unpinned_not_allowed",
                "deadline",
            ]
        );
    }

    #[rstest::rstest]
    #[case("lotl_119612", TrustListKind::Lotl119612)]
    #[case("lote_119602", TrustListKind::Lote119602)]
    fn kind_names_parse(#[case] name: &str, #[case] kind: TrustListKind) {
        assert_eq!(trust_list_kind(name).unwrap(), kind);
    }

    #[rstest::rstest]
    #[case("lotl119612")]
    #[case("LOTL_119612")]
    #[case("")]
    fn unknown_kind_names_are_refused(#[case] name: &str) {
        assert_eq!(
            trust_list_kind(name).unwrap_err().code(),
            "trust_list_invalid_options"
        );
    }

    #[test]
    fn skip_reasons_serialize_as_the_names_the_wrappers_list() {
        let reasons = [
            SkipReason::SignerMismatch,
            SkipReason::InvalidSignature,
            SkipReason::UnsupportedAlgorithm,
            SkipReason::Expired,
            SkipReason::Closed,
            SkipReason::Unreachable,
            SkipReason::InvalidDocument,
            SkipReason::SizeLimit,
            SkipReason::PointerLimit,
            SkipReason::Deadline,
        ];

        assert_eq!(
            serde_json::to_value(reasons).unwrap(),
            json!([
                "signer_mismatch",
                "invalid_signature",
                "unsupported_algorithm",
                "expired",
                "closed",
                "unreachable",
                "invalid_document",
                "size_limit",
                "pointer_limit",
                "deadline"
            ])
        );
    }

    #[test]
    fn anchor_role_names_match_their_serialized_form() {
        for role in [
            AnchorRole::PidProvider,
            AnchorRole::QeaaProvider,
            AnchorRole::PubEaaProvider,
            AnchorRole::EaaProvider,
            AnchorRole::WalletProvider,
            AnchorRole::WrpAcProvider,
            AnchorRole::WrpRcProvider,
            AnchorRole::Registrar,
        ] {
            assert_eq!(
                serde_json::to_value(role).unwrap(),
                json!(anchor_role_name(role))
            );
        }
    }
}
