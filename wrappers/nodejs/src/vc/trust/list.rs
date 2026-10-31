use crate::error::EncodableError;
use crate::http::JsHttpClient;
use crate::utils::serde_str;
use equs_sdk::vc::trust::list::{
    ExportFailure, ExportOptions, LoteRepresentation, SkippedMember, TrustListAnchor,
    TrustListError, TrustListExport, anchor_role_name, export_trust_list as sdk_export_trust_list,
    export_trust_list_with_client, trust_list_kind,
};
use napi::{Error, Result, Status};
use napi_derive::napi;
use std::sync::Arc;
use std::time::Duration;
use strum_macros::Display;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// How a trust list export is authenticated and bounded.
#[napi(object, js_name = "TrustListExportOptions")]
pub struct JsTrustListExportOptions {
    /// PEMs the root signer must equal or chain to. Required unless `allowUnpinnedRoot`.
    pub trust_anchors: Option<Vec<String>>,
    /// Accept the root's embedded signer (development and tests only); marks the export `unpinned`.
    pub allow_unpinned_root: Option<bool>,
    /// Clock tolerance for `NextUpdate` and signing times, at most 86400. Defaults to 300.
    pub leeway_seconds: Option<u32>,
    /// Format of a root LoTE. Defaults to `jwt`.
    #[napi(ts_type = "'jwt' | 'xml' | undefined")]
    pub lote_representation: Option<String>,
    /// Maximum `PointersToOtherLoTE` depth per LoTE; 0 follows none. Defaults to 5.
    pub max_pointer_depth: Option<u32>,
    /// Maximum size of each document in bytes, more than 0.
    pub max_document_bytes: Option<u32>,
    /// Maximum pointers followed in the whole export; 0 follows none.
    pub max_pointers: Option<u32>,
    /// Deadline for the whole export, more than 0. A late root fails it; late members are skipped
    /// as `deadline`.
    pub deadline_seconds: Option<u32>,
    /// Time for one member list, more than 0; a slower member is skipped as `unreachable`.
    /// Defaults to 30.
    pub document_timeout_seconds: Option<u32>,
}

/// A certificate a trust list grants trust to.
#[napi(object, js_name = "TrustListAnchor")]
pub struct JsTrustListAnchor {
    pub pem: String,
    /// Subject Key Identifier, colon-separated lower-case hex.
    pub ski: Option<String>,
    /// RFC 3339.
    pub not_after: String,
    pub entity_name: Option<String>,
    #[napi(
        ts_type = "'pid_provider' | 'qeaa_provider' | 'pub_eaa_provider' | 'eaa_provider' | 'wallet_provider' | 'wrp_ac_provider' | 'wrp_rc_provider' | 'registrar' | undefined"
    )]
    pub role: Option<String>,
    /// Type of the granting service; pass it as a `TrustAnchor`'s `serviceType`.
    pub service_type: Option<String>,
    pub service_status: Option<String>,
    /// The granting list; pass it as a `TrustAnchor`'s `sourceRef`.
    pub source_url: String,
    /// `NextUpdate` of that list, RFC 3339.
    pub source_next_update: String,
}

/// A member list that was not used.
#[napi(object, js_name = "SkippedTrustListMember")]
pub struct JsSkippedMember {
    pub url: String,
    #[napi(
        ts_type = "'signer_mismatch' | 'invalid_signature' | 'unsupported_algorithm' | 'expired' | 'closed' | 'unreachable' | 'invalid_document' | 'size_limit' | 'pointer_limit' | 'deadline'"
    )]
    pub reason: String,
}

/// A LoTE service that granted no anchor because of its status.
#[napi(object, js_name = "ExcludedTrustListService")]
pub struct JsExcludedService {
    /// The list that names the service.
    pub source_url: String,
    pub entity_name: Option<String>,
    pub service_type: Option<String>,
    /// Absent when the list requires an explicit status and the service has none.
    pub service_status: Option<String>,
}

/// The anchors a trust list grants.
#[napi(object, js_name = "TrustListExport")]
pub struct JsTrustListExport {
    pub anchors: Vec<JsTrustListAnchor>,
    /// Sequence number of the root list (exact up to 2^53).
    pub sequence_number: i64,
    /// Issue date of the root list, RFC 3339.
    pub issued_at: String,
    /// `NextUpdate` of the root list, RFC 3339. An anchor is stale at the earlier of this and its
    /// `sourceNextUpdate`.
    pub next_update: String,
    pub skipped_members: Vec<JsSkippedMember>,
    /// LoTE services left out for their status.
    pub excluded_services: Vec<JsExcludedService>,
    /// The root was accepted on its own embedded signer.
    pub unpinned: bool,
}

/// Why {@link exportTrustList} failed: the `code` of its `EqusSdkError`. The message starts with
/// the snake_case form, e.g. `trust_list_signer_not_trusted`.
#[napi(string_enum, js_name = "TrustListError")]
#[derive(Display)]
pub enum JsTrustListError {
    InvalidUrl,
    InvalidOptions,
    Unreachable,
    SizeLimit,
    PointerLimit,
    InvalidDocument,
    InvalidSignature,
    UnsupportedAlgorithm,
    SignerNotTrusted,
    Expired,
    Closed,
    UnpinnedNotAllowed,
    Deadline,
    HttpClient,
    Other,
}

/// Fetches the ETSI trust list at `url`, authenticates it and its members against pinned signers,
/// and returns the certificates they grant. Nothing is cached: store the anchors and pass them to
/// {@link OID4VPVerifierBuilder.addTrustAnchor}.
///
/// Lists are fetched over `https` without redirects, within `maxDocumentBytes`. Failed members
/// are listed in `skippedMembers`; a failing root throws an `EqusSdkError` with a
/// {@link TrustListError} code.
///
/// @param {string} url - `https` location of the root list.
/// @param {'lotl_119612' | 'lote_119602'} kind - an ETSI TS 119 612 LoTL or a TS 119 602 LoTE.
/// @param {TrustListExportOptions} [options] - signer pinning and limits.
/// @param {HttpClient} [httpClient] - replaces the built-in client; must refuse redirects and
/// bound response sizes.
///
/// @returns {TrustListExport}
#[napi]
pub async fn export_trust_list(
    url: String,
    #[napi(ts_arg_type = "'lotl_119612' | 'lote_119602'")] kind: String,
    options: Option<JsTrustListExportOptions>,
    http_client: Option<JsHttpClient>,
) -> Result<JsTrustListExport> {
    let kind = trust_list_kind(&kind).map_err(into_napi_error)?;
    let options = match options {
        Some(options) => options.try_into()?,
        None => ExportOptions::default(),
    };

    let export = match http_client {
        Some(http_client) => {
            export_trust_list_with_client(Arc::new(http_client), &url, kind, &options).await
        }
        None => sdk_export_trust_list(&url, kind, &options).await,
    }
    .map_err(into_napi_error)?;

    export.try_into()
}

fn error_code(error: &TrustListError) -> JsTrustListError {
    match error {
        TrustListError::InvalidUrl { .. } => JsTrustListError::InvalidUrl,
        TrustListError::InvalidOptions { .. } => JsTrustListError::InvalidOptions,
        TrustListError::Export { reason, .. } => match reason {
            ExportFailure::Unreachable => JsTrustListError::Unreachable,
            ExportFailure::SizeLimit => JsTrustListError::SizeLimit,
            ExportFailure::PointerLimit => JsTrustListError::PointerLimit,
            ExportFailure::InvalidDocument => JsTrustListError::InvalidDocument,
            ExportFailure::InvalidSignature => JsTrustListError::InvalidSignature,
            ExportFailure::UnsupportedAlgorithm => JsTrustListError::UnsupportedAlgorithm,
            ExportFailure::SignerNotTrusted => JsTrustListError::SignerNotTrusted,
            ExportFailure::Expired => JsTrustListError::Expired,
            ExportFailure::Closed => JsTrustListError::Closed,
            ExportFailure::UnpinnedNotAllowed => JsTrustListError::UnpinnedNotAllowed,
            ExportFailure::Deadline => JsTrustListError::Deadline,
            ExportFailure::HttpClient => JsTrustListError::HttpClient,
            _ => JsTrustListError::Other,
        },
        _ => JsTrustListError::Other,
    }
}

fn into_napi_error(error: TrustListError) -> Error {
    Error::from_reason(
        EncodableError::new(error_code(&error).to_string(), error.to_string()).encode(),
    )
}

impl TryFrom<JsTrustListExportOptions> for ExportOptions {
    type Error = Error;

    fn try_from(value: JsTrustListExportOptions) -> Result<Self> {
        let defaults = ExportOptions::default();
        let lote_representation = match value.lote_representation.as_deref() {
            None | Some("jwt") => LoteRepresentation::Jwt,
            Some("xml") => LoteRepresentation::Xml,
            Some(other) => {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("unknown LoTE representation `{other}`, expected `jwt` or `xml`"),
                ));
            }
        };
        Ok(Self {
            trust_anchors: value.trust_anchors.unwrap_or_default(),
            allow_unpinned_root: value.allow_unpinned_root.unwrap_or(false),
            leeway: value
                .leeway_seconds
                .map(|s| Duration::from_secs(s.into()))
                .unwrap_or(defaults.leeway),
            lote_representation,
            max_pointer_depth: value
                .max_pointer_depth
                .map(|d| d as usize)
                .or(defaults.max_pointer_depth),
            max_document_bytes: value.max_document_bytes.map(|b| b as usize),
            max_pointers: value.max_pointers.map(|p| p as usize),
            deadline: value
                .deadline_seconds
                .map(|s| Duration::from_secs(s.into())),
            document_timeout: value
                .document_timeout_seconds
                .map(|s| Duration::from_secs(s.into())),
        })
    }
}

fn rfc3339(value: OffsetDateTime) -> Result<String> {
    value
        .format(&Rfc3339)
        .map_err(|e| Error::from_reason(format!("could not format date: {e}")))
}

impl TryFrom<TrustListAnchor> for JsTrustListAnchor {
    type Error = Error;

    fn try_from(value: TrustListAnchor) -> Result<Self> {
        Ok(Self {
            pem: value.pem,
            ski: value.ski,
            not_after: rfc3339(value.not_after)?,
            entity_name: value.entity_name,
            role: value.role.map(|role| anchor_role_name(role).to_string()),
            service_type: value.service_type,
            service_status: value.service_status,
            source_url: value.source_url,
            source_next_update: rfc3339(value.source_next_update)?,
        })
    }
}

impl TryFrom<SkippedMember> for JsSkippedMember {
    type Error = Error;

    fn try_from(value: SkippedMember) -> Result<Self> {
        Ok(Self {
            url: value.url,
            reason: serde_str(value.reason)?,
        })
    }
}

impl TryFrom<TrustListExport> for JsTrustListExport {
    type Error = Error;

    fn try_from(value: TrustListExport) -> Result<Self> {
        Ok(Self {
            anchors: value
                .anchors
                .into_iter()
                .map(JsTrustListAnchor::try_from)
                .collect::<Result<_>>()?,
            sequence_number: i64::try_from(value.sequence_number)
                .map_err(|e| Error::from_reason(format!("sequence number: {e}")))?,
            issued_at: rfc3339(value.issued_at)?,
            next_update: rfc3339(value.next_update)?,
            skipped_members: value
                .skipped_members
                .into_iter()
                .map(JsSkippedMember::try_from)
                .collect::<Result<_>>()?,
            excluded_services: value
                .excluded_services
                .into_iter()
                .map(|service| JsExcludedService {
                    source_url: service.source_url,
                    entity_name: service.entity_name,
                    service_type: service.service_type,
                    service_status: service.service_status,
                })
                .collect(),
            unpinned: value.unpinned,
        })
    }
}
