//! JWT and JWE test fixtures for the EQUS Credentials SDK.
//!
//! One builder per JWT kind the SDK handles, plus a JWE builder. Each mints a
//! valid token at test runtime with sane defaults and per-test overrides,
//! rather than reading a committed static string: a signature-bound fixture
//! cannot be edited without re-signing it, and the SDK's mdoc fixtures already
//! show what that costs.
//!
//! # Signing
//!
//! Every builder signs through the SDK's [`equs_sdk::crypto::Signer`] trait,
//! backed by a [`equs_sdk::inmem::kms::LocalKms`] key handle. No builder touches
//! raw key material, so a fixture exercises the same signing path as production
//! and a regression in the signing stack fails these fixtures rather than
//! hiding behind a pre-baked string.
//!
//! Where the SDK exposes a constructor for a kind — SD-JWT VC, the key-binding
//! JWT, the delegation grant, the status list token, the JWE — the builder
//! calls it. The remaining kinds are built inline inside private SDK modules
//! (`vc::pop` is private, `vc::formats` is `pub(crate)`), so those claim sets
//! are assembled here and signed through the same [`keys::FixtureKey`].
//!
//! # Example
//!
//! ```no_run
//! use equs_sdk::inmem::kms::LocalKms;
//! use equs_sdk::kms::KeyType;
//! use test_fixtures::{keys::FixtureKey, pop::ProofOfPossession};
//!
//! # async fn example() -> test_fixtures::Result<()> {
//! let kms = LocalKms::new();
//! let key = FixtureKey::create(&kms, KeyType::Ed25519).await?;
//!
//! let jwt = ProofOfPossession::builder(&key)
//!     .audience("https://issuer.example")
//!     .nonce("c-nonce")
//!     .build()
//!     .await?;
//! # let _ = jwt;
//! # Ok(())
//! # }
//! ```
//!
//! # Scope
//!
//! Positive fixtures only. Malformed-token generation stays in the error-path
//! tests that need it; what this crate offers instead is a valid token with one
//! claim moved, which is what a verifier's rejection paths actually take.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod claims;
pub mod error;
pub mod http;
pub mod id_token;
pub mod jwe;
pub mod jws;
pub mod kb_jwt;
pub mod keys;
pub mod pop;
pub mod request_object;
pub mod sd_jwt_vc;
pub mod status_list;
pub mod vp_token;

#[cfg(feature = "delegate-sd-jwt")]
pub mod dsd_jwt;

pub use error::{Error, Result};
pub use keys::FixtureKey;

/// The SDK this crate builds fixtures against.
///
/// Re-exported for one caller: the SDK's own `src/` unit tests. Building the
/// SDK's test target compiles `equs_sdk` twice — once as the library this crate
/// links, once as the `cfg(test)` crate under test — and the two sets of types
/// do not unify. A unit test therefore constructs a builder's inputs through
/// this re-export and carries only the resulting token string back across the
/// boundary.
pub use equs_sdk;
