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
