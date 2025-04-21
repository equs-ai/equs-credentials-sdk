use crate::inmem::storage::InMemStorage;
use crate::nonce::{GenerateSnafu, Nonce, NonceHandler, Result, ValidateSnafu};
use crate::storage::Storage;
use async_trait::async_trait;

pub struct LocalNonceHandler {
    storage: InMemStorage<String, Nonce>,
}

impl Default for LocalNonceHandler {
    fn default() -> Self {
        Self {
            storage: InMemStorage::new(),
        }
    }
}

#[async_trait]
impl NonceHandler for LocalNonceHandler {
    async fn generate(&self) -> Result<Nonce> {
        let bytes: [u8; 32] = rand::random();
        let nonce = Nonce::new(bytes);

        self.storage
            .put(nonce.secret().to_owned(), nonce.clone())
            .await
            .map_err(|e| {
                GenerateSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        Ok(nonce)
    }

    async fn validate(&self, nonce: &Nonce) -> Result<bool> {
        let is_valid = self
            .storage
            .get(&nonce.secret().to_string())
            .await
            .map_err(|e| {
                ValidateSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .map(|_| true)
            .unwrap_or(false);

        Ok(is_valid)
    }
}
