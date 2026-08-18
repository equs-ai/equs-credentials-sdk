pub type X509Client = openid4vp::verifier::client::X509Client;
pub type X509Variant = openid4vp::verifier::client::X509Variant;

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::{X509Client, X509Variant};
    use crate::kms::KeyHandle;
    use crate::vc::oid4vp::ClientId;
    use crate::vc::oid4vp::internal_error::X509Snafu;
    use crate::vc::oid4vp::verifier::Result;
    use snafu::ensure;
    use tracing::{Level, instrument};

    /// An X.509 certificate, as carried in the request JWT `x5c` header.
    pub use x509_cert::Certificate;

    /// Derives the `client_id` a Verifier holding `chain` must be configured with:
    /// the leaf's Subject Alternative Name for [`X509Variant::SanDns`], the leaf's
    /// hash for [`X509Variant::Hash`].
    ///
    /// An `x509_hash` `client_id` cannot be written by hand, and request generation
    /// rejects any `client_id` the chain does not derive, so this is the supported
    /// way to obtain one. It goes through the same upstream derivation the request
    /// path uses, so the two cannot drift apart.
    ///
    /// # Errors
    ///
    /// [`crate::vc::oid4vp::InternalError::X509`] - if `chain` is empty, or the leaf
    /// does not yield a `client_id` for `variant` (e.g. no DNS SAN entry for
    /// `x509_san_dns`).
    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    pub fn client_id_from_x509_chain(
        chain: &[Certificate],
        variant: X509Variant,
    ) -> Result<ClientId> {
        Ok(X509Client::client_id(chain, variant).map_err(|e| {
            X509Snafu {
                details: format!("cannot derive a client_id from the certificate chain: {e}"),
            }
            .build()
        })?)
    }

    /// Checks that `leaf` certifies the public key of `key`, i.e. that a request
    /// object signed with `key` will verify against the `x5c` leaf the Wallet reads
    /// it from.
    ///
    /// EC keys are compared as curve points rather than as bytes: certificates carry
    /// the uncompressed SEC1 encoding while [`crate::crypto::Key::pub_key`] yields
    /// the compressed one, so a plain byte comparison would reject every valid pair.
    ///
    /// # Errors
    ///
    /// [`crate::vc::oid4vp::InternalError::X509`] - if `key` exposes no public JWK,
    /// its type is not usable with an x509 `client_id`, or `leaf` certifies a
    /// different key.
    #[instrument(level = Level::TRACE, skip_all, err())]
    pub fn ensure_leaf_matches_signing_key<KH: KeyHandle>(
        leaf: &Certificate,
        key: &KH,
    ) -> Result<()> {
        use crate::crypto::Key as _;
        use crate::kms::KeyType;
        use ssi::crypto::{k256, p256};

        let jwk = key.jwk().ok_or_else(|| {
            X509Snafu {
                details: "the verifier signing key does not expose a public JWK".to_string(),
            }
            .build()
        })?;

        let key_bytes = jwk.pub_key().map_err(|e| {
            X509Snafu {
                details: format!("cannot read the verifier public key: {e}"),
            }
            .build()
        })?;

        let cert_bytes = leaf
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();

        let matches = match crate::utils::jwk::get_key_type(&jwk) {
            Some(KeyType::P256) => matches!(
                (
                    p256::PublicKey::from_sec1_bytes(cert_bytes),
                    p256::PublicKey::from_sec1_bytes(&key_bytes),
                ),
                (Ok(from_cert), Ok(from_key)) if from_cert == from_key
            ),
            Some(KeyType::K256) => matches!(
                (
                    k256::PublicKey::from_sec1_bytes(cert_bytes),
                    k256::PublicKey::from_sec1_bytes(&key_bytes),
                ),
                (Ok(from_cert), Ok(from_key)) if from_cert == from_key
            ),
            Some(KeyType::Ed25519) => cert_bytes == key_bytes,
            other => {
                return Err(X509Snafu {
                    details: format!(
                        "unsupported verifier key type for a x509 client_id: {other:?}"
                    ),
                }
                .build()
                .into());
            }
        };

        ensure!(
            matches,
            X509Snafu {
                details: "the leaf certificate does not certify the verifier signing key \
                          referenced by key_metadata; the Wallet would reject the request \
                          signature"
                    .to_string(),
            }
        );

        Ok(())
    }
}
