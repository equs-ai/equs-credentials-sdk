use crate::utils::serde_str;
use crate::vc::oid4vp::builder::JsTrustAnchor;
use equs_sdk::vc::trust::issuer::TrustAnchor;
use equs_sdk::vc::trust::trusted_authorities::derive_trusted_authority_akis as sdk_derive_trusted_authority_akis;
use napi::Result;
use napi_derive::napi;

/// An anchor that contributed no `aki` value.
#[napi(object, js_name = "SkippedTrustedAuthorityAnchor")]
pub struct JsSkippedTrustedAuthorityAnchor {
    pub source_ref: Option<String>,
    #[napi(ts_type = "'unparseable' | 'no_key_identifier'")]
    pub reason: String,
}

/// The `aki` values to request in DCQL `trusted_authorities`.
#[napi(object, js_name = "TrustedAuthorityAkis")]
pub struct JsTrustedAuthorityAkis {
    /// base64url Key Identifiers without padding, deduplicated and sorted.
    pub values: Vec<String>,
    pub skipped: Vec<JsSkippedTrustedAuthorityAnchor>,
}

/// The `aki` values (OpenID4VP 1.0 §6.1.1.1) for the issuer anchors in `anchors`: a CA's SKI, or a
/// non-CA certificate's own AKI. Non-issuing anchors are left out; anchors lacking the identifier
/// are listed in `skipped`.
#[napi(js_name = "deriveTrustedAuthorityAkis")]
pub fn derive_trusted_authority_akis(
    anchors: Vec<JsTrustAnchor>,
) -> Result<JsTrustedAuthorityAkis> {
    let anchors: Vec<TrustAnchor> = anchors
        .into_iter()
        .map(|anchor| TrustAnchor {
            pem: anchor.pem,
            source_ref: anchor.source_ref,
            role: anchor.role,
            service_type: anchor.service_type,
        })
        .collect();
    let derived = sdk_derive_trusted_authority_akis(&anchors);
    Ok(JsTrustedAuthorityAkis {
        values: derived
            .values
            .iter()
            .map(|value| value.as_base64url().to_string())
            .collect(),
        skipped: derived
            .skipped
            .into_iter()
            .map(|skipped| {
                Ok(JsSkippedTrustedAuthorityAnchor {
                    source_ref: skipped.source_ref,
                    reason: serde_str(skipped.reason)?,
                })
            })
            .collect::<Result<_>>()?,
    })
}
