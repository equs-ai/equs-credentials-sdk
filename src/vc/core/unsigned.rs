//! Unsigned credential representations produced by [PrepareCredential] and consumed
//! by [SignCredential].
//!
//! [PrepareCredential]: crate::vc::core::PrepareCredential
//! [SignCredential]: crate::vc::core::SignCredential

use crate::crypto::JWK;
use crate::vc::formats::json_ld_vc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssi::JsonPointerBuf;
use std::collections::HashMap;

/// Selective-disclosure strategy for SD-JWT issuance.
///
/// Captures the decision currently embedded in `SdJwtAPI::create_vc`: an empty disclosure
/// list maps to [DisclosureStrategy::AllLevels] (every nested claim is independently
/// disclosable), otherwise to [DisclosureStrategy::Custom] with explicit JSON-path
/// selectors.
///
/// Encoding this explicitly prevents every `SignCredential` impl from having to re-derive
/// the empty-collapse and the `ALWAYS_REVEALED_CLAIMS` filter and silently diverging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisclosureStrategy {
    /// Every claim at every nesting level is independently disclosable.
    AllLevels,
    /// Only the listed JSON paths (e.g. `"$.name"`) are selectively disclosable.
    /// Paths referencing always-revealed claims (iss, nbf, exp, cnf, vct, status) are
    /// expected to have been filtered out by `PrepareCredential`.
    Custom(Vec<String>),
}

/// SD-JWT variant of an unsigned credential.
///
/// Carries fully-prepared claims and the disclosure context. SD-JWT-internal fields
/// (`_sd`, `_sd_alg`, `cnf`) are added by `SDJWTIssuer` during [crate::vc::core::SignCredential].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedSdJwtCredential {
    /// Fully prepared claims as a JSON object — standard fields (`vct`, `iss`, `sub`,
    /// `iat`, `nbf`, `exp`, `status`) are already set by `PrepareCredential`.
    pub claims: Map<String, Value>,
    /// Selective-disclosure strategy.
    pub disclosure_strategy: DisclosureStrategy,
    /// Holder's public key for `cnf` key-binding. Always present in this revision —
    /// optional binding is a non-goal.
    pub holder_key: JWK,
    /// Extra JWT header parameters (`typ`, `kid`) computed from the issuer DID URL.
    pub extra_headers: HashMap<String, String>,
    /// Routing hint identifying which issuer key the unsigned credential expects to be
    /// signed with. KMS-backed signers use it as a lookup key; single-key signers SHOULD
    /// validate it against their configured identity.
    pub issuer_key_id: String,
}

/// LDP/JSON-LD variant of an unsigned credential.
///
/// Wraps the unsigned `AnySpecializedJsonCredential` plus the signing context. The
/// proof object is added by the Protocol suite during [crate::vc::core::SignCredential].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedLdpCredential {
    /// Unsigned JSON-LD credential. V1 or V2 depending on the context set.
    pub unsigned_vc: json_ld_vc::Credential,
    /// Issuer DID URL used as the verification method id in the proof options.
    pub issuer_did_url: String,
    /// Routing hint (see [UnsignedSdJwtCredential::issuer_key_id]).
    pub issuer_key_id: String,
    /// JSON Pointer paths for mandatory disclosure (BBS+ selective disclosure).
    pub mandatory_claims: Option<Vec<JsonPointerBuf>>,
}

/// Format-tagged union of unsigned credentials produced by `PrepareCredential`.
///
/// Serialised with serde's default externally-tagged shape — `{ "SdJwt": { ... } }` /
/// `{ "Ldp": { ... } }` — matching the existing `Credential` enum's convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnsignedCredential {
    SdJwt(UnsignedSdJwtCredential),
    Ldp(UnsignedLdpCredential),
}
