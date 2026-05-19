use crate::crypto::{Alg, Error, KeyGenerationSnafu, SigningSnafu, VerificationSnafu};
use async_trait::async_trait;
use tracing::{Level, instrument};

use crate::crypto;
use crate::inmem::crypto::HasAlg;
use crate::kms::CreationSnafu;
use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::elliptic_curve::ops::Invert;
use ecdsa::elliptic_curve::point::PointCompression;
use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use ecdsa::elliptic_curve::subtle::CtOption;
use ecdsa::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, Scalar, sec1};
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use ecdsa::signature::rand_core::OsRng;
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{
    PrimeCurve, Signature, SignatureSize, SigningKey as EcdsaSigningKey,
    VerifyingKey as EcdsaVerifyingKey,
};

#[derive(Clone)]
pub struct Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    signing_key: EcdsaSigningKey<C>,
}

impl<C> Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive + HasJWK + HasAlg,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub(crate) fn new(signing_key: EcdsaSigningKey<C>) -> Self {
        Self { signing_key }
    }

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    pub fn is_compressed_public_key(public_key: &[u8]) -> Result<bool, crate::kms::Error> {
        ecdsa::EncodedPoint::<C>::from_bytes(public_key)
            .map(|encoded_point| encoded_point.is_compressed())
            .map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    #[instrument(level = Level::TRACE, skip(public_key), err())]
    pub fn re_encode_public_key(
        public_key: &[u8],
        compress: bool,
    ) -> Result<Vec<u8>, crate::kms::Error> {
        let encoded_point = ecdsa::EncodedPoint::<C>::from_bytes(public_key).map_err(|err| {
            CreationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let verifying_key =
            ecdsa::VerifyingKey::<C>::from_encoded_point(&encoded_point).map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        Ok(verifying_key.to_encoded_point(compress).as_bytes().to_vec())
    }
}

pub trait HasJWK {
    fn jwk(key: Vec<u8>) -> Option<ssi::jwk::JWK>;
}

impl<C> crypto::SigningKey for Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive + HasJWK + HasAlg,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
}

impl<C> crypto::VerifyingKey for Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive + HasJWK + HasAlg,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
}

impl<C> crypto::Suite for Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive + HasJWK + HasAlg,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn generate() -> Vec<u8> {
        let signing_key = EcdsaSigningKey::<C>::random(&mut OsRng);
        signing_key.to_bytes().to_vec()
    }

    #[instrument(
        level = Level::TRACE,
        err(),
    )]
    fn from_secret(vec: Vec<u8>) -> Result<Ecdsa<C>, Error> {
        let s: &[u8] = &vec;

        EcdsaSigningKey::<C>::from_slice(s)
            .map(|signing_key| Ecdsa { signing_key })
            .map_err(|err| {
                KeyGenerationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}

impl<C> crypto::Key for Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive + HasJWK + HasAlg,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    fn pub_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.signing_key.verifying_key().to_sec1_bytes().to_vec())
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn jwk(&self) -> Option<ssi::jwk::JWK> {
        self.pub_key().ok().and_then(|key| C::jwk(key))
    }

    fn private_key(&self) -> crypto::Result<Vec<u8>> {
        Ok(self.signing_key.to_bytes().to_vec())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<C> crypto::Signer for Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive + HasJWK + HasAlg,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn alg(&self) -> Alg {
        C::algorithm()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.signing_key
            .try_sign(payload)
            .map(|s: Signature<C>| s.to_vec())
            .map_err(|err| {
                SigningSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<C> crypto::Verifier for Ecdsa<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive + HasJWK,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let signature = Signature::<C>::from_slice(signature).map_err(|err| {
            VerificationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let ver_key: EcdsaVerifyingKey<C> = self.signing_key.verifying_key().to_owned();

        ver_key.verify(data, &signature).map_err(|err| {
            VerificationSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{Alg, Key, Signer as _, Suite, Verifier as _};
    use crate::inmem::crypto::k256::K256;
    use crate::inmem::crypto::p256::P256;
    use rstest::rstest;

    fn fresh_p256() -> P256 {
        P256::from_secret(P256::generate()).unwrap()
    }

    fn fresh_k256() -> K256 {
        K256::from_secret(K256::generate()).unwrap()
    }

    #[rstest]
    #[case::p256(P256::generate())]
    #[case::k256(K256::generate())]
    fn generate_returns_32_byte_scalar(#[case] bytes: Vec<u8>) {
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn generate_returns_distinct_p256_secrets_each_call() {
        assert_ne!(P256::generate(), P256::generate());
    }

    #[test]
    fn from_secret_roundtrips_valid_scalar() {
        let bytes = P256::generate();
        let suite = P256::from_secret(bytes.clone()).unwrap();

        assert_eq!(suite.private_key().unwrap(), bytes);
    }

    #[test]
    #[should_panic(expected = "Key generation error")]
    fn from_secret_rejects_zero_scalar() {
        // The zero scalar is invalid for ECDSA; from_slice rejects it.
        P256::from_secret(vec![0u8; 32]).unwrap();
    }

    #[test]
    #[should_panic(expected = "Key generation error")]
    fn from_secret_rejects_wrong_length() {
        P256::from_secret(vec![1u8; 10]).unwrap();
    }

    #[test]
    fn pub_key_returns_uncompressed_sec1_encoding() {
        // SEC1 uncompressed P-256 point: 0x04 prefix + 32 x + 32 y = 65 bytes.
        let suite = fresh_p256();
        let bytes = suite.pub_key().unwrap();

        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
    }

    #[test]
    fn pub_key_is_deterministic_for_same_secret() {
        let secret = P256::generate();
        let a = P256::from_secret(secret.clone()).unwrap();
        let b = P256::from_secret(secret).unwrap();

        assert_eq!(a.pub_key().unwrap(), b.pub_key().unwrap());
    }

    #[rstest]
    #[case::p256(fresh_p256().jwk(), crate::kms::KeyType::P256)]
    #[case::k256(fresh_k256().jwk(), crate::kms::KeyType::K256)]
    fn jwk_returns_some_for_supported_curves(
        #[case] jwk: Option<ssi::jwk::JWK>,
        #[case] expected: crate::kms::KeyType,
    ) {
        let jwk = jwk.expect("jwk should be Some");
        assert_eq!(crate::utils::jwk::get_key_type(&jwk), Some(expected));
    }

    #[test]
    fn is_compressed_public_key_detects_compressed_point() {
        let suite = fresh_p256();
        let uncompressed = suite.pub_key().unwrap();
        let compressed = P256::re_encode_public_key(&uncompressed, true).unwrap();

        assert!(P256::is_compressed_public_key(&compressed).unwrap());
    }

    #[test]
    fn is_compressed_public_key_detects_uncompressed_point() {
        let suite = fresh_p256();
        let uncompressed = suite.pub_key().unwrap();

        assert!(!P256::is_compressed_public_key(&uncompressed).unwrap());
    }

    #[test]
    fn re_encode_public_key_produces_33_byte_compressed_point() {
        let suite = fresh_p256();
        let uncompressed = suite.pub_key().unwrap();

        let compressed = P256::re_encode_public_key(&uncompressed, true).unwrap();

        // Compressed P-256 point: 0x02|0x03 prefix + 32 bytes x = 33 bytes.
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn re_encode_public_key_roundtrips_compressed_to_uncompressed() {
        let suite = fresh_p256();
        let uncompressed_a = suite.pub_key().unwrap();

        let compressed = P256::re_encode_public_key(&uncompressed_a, true).unwrap();
        let uncompressed_b = P256::re_encode_public_key(&compressed, false).unwrap();

        assert_eq!(uncompressed_a, uncompressed_b);
    }

    #[tokio::test]
    async fn sign_then_verify_succeeds_for_p256() {
        let suite = fresh_p256();
        let msg = b"alea iacta est";

        let sig = suite.sign(msg).await.unwrap();
        suite.verify(msg, &sig).await.unwrap();
    }

    #[tokio::test]
    async fn sign_then_verify_succeeds_for_k256() {
        let suite = fresh_k256();
        let msg = b"alea iacta est";

        let sig = suite.sign(msg).await.unwrap();
        suite.verify(msg, &sig).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Verification error")]
    async fn verify_rejects_malformed_signature_bytes() {
        let suite = fresh_p256();

        suite.verify(b"data", &[0u8; 4]).await.unwrap();
    }

    #[test]
    fn alg_dispatches_to_curve_specific_algorithm() {
        assert_eq!(fresh_p256().alg(), Alg::ES256);
        assert_eq!(fresh_k256().alg(), Alg::ES256K);
    }
}
