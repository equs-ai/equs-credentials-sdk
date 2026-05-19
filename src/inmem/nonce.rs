use crate::inmem::storage::InMemStorage;
use crate::nonce::{GenerateSnafu, Nonce, NonceHandler, Result, ValidateSnafu};
use crate::storage::Storage;
use async_trait::async_trait;

#[derive(Debug, Clone)]
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_constructs_handler_with_empty_storage() {
        let h = LocalNonceHandler::default();

        // A handler with empty storage cannot validate any nonce.
        let n = Nonce::from_secret("anything".to_string());
        assert!(!h.validate(&n).await.unwrap());
    }

    #[tokio::test]
    async fn generate_returns_distinct_nonces_on_each_call() {
        let h = LocalNonceHandler::default();

        let a = h.generate().await.unwrap();
        let b = h.generate().await.unwrap();

        assert_ne!(a.secret(), b.secret());
    }

    #[tokio::test]
    async fn generate_persists_nonce_so_subsequent_validate_returns_true() {
        let h = LocalNonceHandler::default();

        let n = h.generate().await.unwrap();

        assert!(h.validate(&n).await.unwrap());
    }

    #[tokio::test]
    async fn validate_returns_false_for_nonce_never_generated_by_this_handler() {
        let h = LocalNonceHandler::default();

        let foreign = Nonce::from_secret("never-generated".to_string());

        assert!(!h.validate(&foreign).await.unwrap());
    }

    #[tokio::test]
    async fn validate_remains_true_on_repeated_calls_for_same_nonce() {
        // The current implementation is a presence check — it does not
        // consume the nonce, so validate is idempotent.
        let h = LocalNonceHandler::default();
        let n = h.generate().await.unwrap();

        assert!(h.validate(&n).await.unwrap());
        assert!(h.validate(&n).await.unwrap());
    }
}
