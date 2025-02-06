use crate::kms::{KeyHandleWrapper, NativeKms};
use agent_sdk::kms;
use agent_sdk::kms::{
    CreateOptions, CreationSnafu, DerivativeKms, ECDH1PUParams, ECDHESParams, KeyID, KeyType, Kms,
};
use async_trait::async_trait;

pub struct DIDCommKms(NativeKms);

#[async_trait]
impl Kms<KeyHandleWrapper> for DIDCommKms {
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> kms::Result<KeyID> {
        self.0.base.create(kt, opts).await
    }

    async fn get(&self, kid: &KeyID) -> kms::Result<KeyHandleWrapper> {
        self.0.base.get(kid).await
    }

    async fn get_by_public_key(&self, public_key: &[u8]) -> kms::Result<KeyHandleWrapper> {
        self.0.base.get_by_public_key(public_key).await
    }
}

#[async_trait]
impl DerivativeKms<ECDH1PUParams> for DIDCommKms {
    type Output = Vec<u8>;

    async fn derive(&self, params: ECDH1PUParams) -> kms::Result<Vec<u8>> {
        let derivative_kms = self.0.ecdh1pu.as_ref().ok_or_else(|| {
            CreationSnafu {
                details: "ECDH1-PU Key derivation is not supported",
            }
            .build()
        })?;

        derivative_kms.derive(params).await
    }
}

#[async_trait]
impl DerivativeKms<ECDHESParams> for DIDCommKms {
    type Output = Vec<u8>;

    async fn derive(&self, params: ECDHESParams) -> kms::Result<Vec<u8>> {
        let derivative_kms = self.0.ecdhes.as_ref().ok_or_else(|| {
            CreationSnafu {
                details: "ECDH1-ES Key derivation is not supported",
            }
            .build()
        })?;

        derivative_kms.derive(params).await
    }
}

impl From<&NativeKms> for DIDCommKms {
    fn from(value: &NativeKms) -> Self {
        DIDCommKms(value.clone())
    }
}
