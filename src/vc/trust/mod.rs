//! Issuer trust: the anchors credential issuers are trusted under, where they come from, and how a
//! presented credential's issuer is checked against them. Protocol-neutral.

/// Evaluates a presented credential's issuer against trust anchors, per credential category.
pub mod issuer;
/// Exports the anchors an ETSI trust list (TS 119 612 LoTL, TS 119 602 LoTE) grants.
#[cfg(not(target_arch = "wasm32"))]
pub mod list;
/// DCQL `trusted_authorities`: `aki` values for issuer anchors, and matching chains against them.
pub mod trusted_authorities;
