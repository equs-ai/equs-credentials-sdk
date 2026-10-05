//! Self-signed X.509 material and the SD-JWT VC that carries it in `x5c`.
//!
//! A credential with an `x5c` header is signature-bound to the certificate in
//! that header: the certificate certifies the key that signed the credential,
//! so neither can be edited without reissuing both. The truststore tests used
//! to hold both as committed strings; this builder mints them together.
//!
//! The issuing CA key is `rcgen`'s own, generated fresh per chain and never
//! touched again. `rcgen::SigningKey::sign` is synchronous, while the SDK's
//! [`equs_sdk::crypto::Signer::sign`] is async; blocking on the KMS from
//! inside `rcgen`'s signing callback would deadlock under the current-thread
//! runtime `#[tokio::test]` provides. Keeping the CA key inside `rcgen` costs
//! nothing: the leaf still certifies the KMS key (via the `KmsPublicKey`
//! adapter), and the credential itself is still signed inside the KMS.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use equs_sdk::crypto::{Key, Signer};
use rcgen::{CertificateParams, DnType, Issuer, KeyPair, SanType};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::keys::FixtureKey;

/// A self-signed leaf certificate certifying a KMS key.
pub struct X509Chain {
    /// The leaf certificate, PEM encoded.
    pub leaf_pem: String,
    /// The chain in the base64 (not base64url) form an `x5c` header takes.
    pub chain_b64: Vec<String>,
    // The KMS key the leaf certifies, kept so `sign_sd_jwt_vc` can sign
    // through it without the caller having to pass it again.
    subject: FixtureKey,
}

impl X509Chain {
    /// Issues a self-signed P-256 certificate with `subjectAltName = DNS:<dns_name>`,
    /// certifying `subject`'s public key.
    ///
    /// The issuing CA key is generated fresh by `rcgen` and discarded after
    /// signing.
    ///
    /// # Errors
    ///
    /// * [`Error::Signing`] — `rcgen` could not generate the CA key, build the
    ///   certificate parameters, or issue the certificate; `dns_name` is not a
    ///   valid DNS name; `subject` exposes no public JWK; or `subject` is not a
    ///   `P-256` key (this builder certifies `P-256` keys only, since the
    ///   signature algorithm the certificate advertises is fixed to
    ///   `ES256`/`PKCS_ECDSA_P256_SHA256`).
    /// * [`Error::Json`] — `subject`'s public JWK could not be re-serialised
    ///   to read its coordinates off.
    pub fn self_signed(subject: &FixtureKey, dns_name: &str) -> Result<Self> {
        let key_pair = KeyPair::generate().map_err(|e| Error::Signing {
            details: e.to_string(),
        })?;

        let mut params =
            CertificateParams::new(vec![dns_name.to_string()]).map_err(|e| Error::Signing {
                details: e.to_string(),
            })?;
        params.distinguished_name.push(DnType::CommonName, dns_name);
        params.subject_alt_names = vec![SanType::DnsName(dns_name.try_into().map_err(|_| {
            Error::Signing {
                details: format!("{dns_name} is not a valid DNS name"),
            }
        })?)];

        let public_key = KmsPublicKey::of(subject)?;
        let issuer = Issuer::from_params(&params, &key_pair);
        let cert = params
            .signed_by(&public_key, &issuer)
            .map_err(|e| Error::Signing {
                details: e.to_string(),
            })?;

        let leaf_pem = cert.pem();
        let chain_b64 = vec![STANDARD.encode(cert.der())];

        Ok(Self {
            leaf_pem,
            chain_b64,
            subject: subject.clone(),
        })
    }

    /// Issues an SD-JWT VC signed by the certified key, with `x5c` in the
    /// header, in compact form with no disclosures (`<jws>~`).
    ///
    /// The header carries `alg` (taken from the signer), `typ: "dc+sd-jwt"`,
    /// and the full `x5c` chain built by [`X509Chain::self_signed`].
    ///
    /// # Errors
    ///
    /// * [`Error::Json`] — the header or claim set could not be serialised.
    /// * [`Error::Signing`] — the KMS handle refused to sign.
    pub async fn sign_sd_jwt_vc(&self, claims: Map<String, Value>) -> Result<String> {
        let header = serde_json::json!({
            "alg": self.subject.handle.alg().to_string(),
            "typ": "dc+sd-jwt",
            "x5c": self.chain_b64,
        });
        let jws =
            crate::jws::sign_compact_with_header(&self.subject, &header, &Value::Object(claims))
                .await?;
        Ok(format!("{jws}~"))
    }
}

/// Adapts a [`FixtureKey`]'s public JWK into the DER form `rcgen` needs to
/// certify a key it never holds the private half of.
struct KmsPublicKey {
    der: Vec<u8>,
}

impl KmsPublicKey {
    /// Extracts the uncompressed EC point (`0x04 || x || y`) from a `P-256`
    /// fixture key's public JWK.
    fn of(key: &FixtureKey) -> Result<Self> {
        let jwk = key.handle.jwk().ok_or_else(|| Error::Signing {
            details: "key handle exposed no public JWK".to_string(),
        })?;
        let jwk_json = serde_json::to_value(&jwk).map_err(|e| Error::Json {
            details: e.to_string(),
        })?;

        let curve = jwk_json.get("crv").and_then(Value::as_str);
        if curve != Some("P-256") {
            return Err(Error::Signing {
                details: format!(
                    "X509Chain::self_signed certifies P-256 keys only, got {}",
                    curve.unwrap_or("a JWK with no \"crv\" member")
                ),
            });
        }

        let mut der = vec![0x04];
        der.extend_from_slice(&decode_b64url_coordinate(&jwk_json, "x")?);
        der.extend_from_slice(&decode_b64url_coordinate(&jwk_json, "y")?);
        Ok(Self { der })
    }
}

/// Base64url-decodes the named coordinate off a serialised JWK.
fn decode_b64url_coordinate(jwk_json: &Value, member: &str) -> Result<Vec<u8>> {
    let encoded = jwk_json
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Signing {
            details: format!("JWK has no \"{member}\" member"),
        })?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(|e| Error::Signing {
        details: e.to_string(),
    })
}

impl rcgen::PublicKeyData for KmsPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.der
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
