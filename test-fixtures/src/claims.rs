//! Shared claim defaults.
//!
//! Every builder starts from these so that two fixtures of different kinds line
//! up by default — the same audience, the same issuer, the same clock — and a
//! test only has to name the claim it actually cares about.

use equs_sdk::{Duration, OffsetDateTime};

/// Default `aud` — the verifier or issuer a fixture is addressed to.
pub const DEFAULT_AUDIENCE: &str = "https://verifier.example";

/// Default issuer identifier for kinds that carry an `iss` a verifier compares.
pub const DEFAULT_ISSUER: &str = "https://issuer.example";

/// Default client identifier for OID4VP request objects and `id_token`s.
pub const DEFAULT_CLIENT_ID: &str = "https://verifier.example";

/// Default `vct` for SD-JWT VC fixtures.
pub const DEFAULT_VCT: &str = "https://issuer.example/credential-schema";

/// Default `nonce`, used wherever a kind binds to one.
pub const DEFAULT_NONCE: &str = "fixture-nonce";

/// Default token lifetime.
pub const DEFAULT_LIFETIME: Duration = Duration::minutes(5);

/// Current time as a Unix timestamp, the form every one of these JWT kinds uses.
#[must_use]
pub fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// A Unix timestamp `offset` away from now; negative offsets are in the past.
#[must_use]
pub fn from_now(offset: Duration) -> i64 {
    (OffsetDateTime::now_utc() + offset).unix_timestamp()
}
