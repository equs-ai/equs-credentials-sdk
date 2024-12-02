use crate::crypto::SigningKey;
use crate::vc::oid4vp::internal_error::ParseSnafu;
use async_trait::async_trait;
use ssi::jwk::JWK;
use std::fmt::{Debug, Formatter};
use tracing::instrument;
use tracing::Level;

pub(super) struct Signer<S: SigningKey> {
    signer: S,
    key: JWK,
}

impl<S: SigningKey> Signer<S> {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
    pub(super) fn new(signer: S) -> crate::vc::oid4vp::verifier::Result<Signer<S>> {
        let key = signer.jwk().ok_or(
            ParseSnafu {
                details: "Could not retrieve JWK",
            }
            .build(),
        )?;

        Ok(Signer { signer, key })
    }
}

impl<S: SigningKey> Debug for Signer<S> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        std::write!(fmt, "JWK = {:?}", self.key)
    }
}

#[async_trait]
impl<S: SigningKey> oid4vp::signer::Signer for Signer<S> {
    type Error = anyhow::Error;

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    fn alg(&self) -> anyhow::Result<String, Self::Error> {
        Ok(self.signer.alg().to_string())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    fn jwk(&self) -> anyhow::Result<JWK, Self::Error> {
        Ok(self.key.to_owned())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>, Self::Error> {
        let signature = self.signer.sign(payload).await?;
        Ok(signature)
    }
}
