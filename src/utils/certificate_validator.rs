//! The process-wide certificate validator, so each CRL is fetched once and then cached.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use one_core::config::core_config::KeyAlgorithmType;
use one_core::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
    Error, ParsedCertificate,
};
use one_core::proto::clock::DefaultClock;
use one_core::proto::http_client::reqwest_client::ReqwestClient;
use one_core::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use one_core::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::remote_entity_storage::in_memory::InMemoryStorage;
use tracing::error;

/// Largest CRL read; a larger one leaves revocation unknown.
const MAX_CRL_BYTES: usize = 32 * 1024 * 1024;
/// Longest a CRL download may take.
const CRL_TIMEOUT: Duration = Duration::from_secs(30);
/// CRLs held in the cache.
const CRL_CACHE_SIZE: usize = 20;
/// A cached CRL is used for at most this long, and never past its own `nextUpdate`.
const CRL_EXPIRY: time::Duration = time::Duration::hours(1);
/// After this long a cached CRL is refetched; on failure the cached one is kept until it expires.
const CRL_REFRESH_AFTER: time::Duration = time::Duration::minutes(15);

static SHARED: LazyLock<Result<Arc<CertificateValidatorImpl>, String>> = LazyLock::new(|| {
    build().map(Arc::new).inspect_err(|details| {
        error!(%details, "Certificate validator could not be built");
    })
});

/// A handle on the process-wide certificate validator.
#[derive(Clone)]
pub(crate) struct SharedCertificateValidator(Result<Arc<CertificateValidatorImpl>, String>);

impl SharedCertificateValidator {
    pub(crate) fn get() -> Self {
        Self(SHARED.clone())
    }

    /// The validator, or why it could not be built.
    fn validator(&self) -> Result<&CertificateValidatorImpl, Error> {
        self.0
            .as_deref()
            .map_err(|details| Error::CRLCheckFailed(details.clone()))
    }
}

#[async_trait]
impl CertificateValidator for SharedCertificateValidator {
    async fn parse_pem_chain(
        &self,
        pem_chain: &str,
        validation: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, Error> {
        self.validator()?
            .parse_pem_chain(pem_chain, validation)
            .await
    }

    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &str,
        ca_pem_chain: &str,
        validation: CertificateValidationOptions,
        cert_selection: CertSelection,
    ) -> Result<ParsedCertificate, Error> {
        self.validator()?
            .validate_chain_against_ca_chain(pem_chain, ca_pem_chain, validation, cert_selection)
            .await
    }
}

/// A validator fetching CRLs over http(s) without redirects, bounded in size and time, and cached.
fn build() -> Result<CertificateValidatorImpl, String> {
    let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(
        HashMap::from_iter([
            (
                KeyAlgorithmType::Eddsa,
                Arc::new(Eddsa) as Arc<dyn KeyAlgorithm>,
            ),
            (
                KeyAlgorithmType::Ecdsa,
                Arc::new(Ecdsa) as Arc<dyn KeyAlgorithm>,
            ),
        ]),
        Default::default(),
    ));
    let crl_client = ReqwestClient::for_revocation_data(MAX_CRL_BYTES, CRL_TIMEOUT)
        .map_err(|e| format!("the CRL HTTP client could not be built: {e}"))?;
    let crl_cache = Arc::new(X509CrlCache::new(
        Arc::new(X509CrlResolver::new(Some(Arc::new(crl_client)))),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        CRL_CACHE_SIZE,
        CRL_EXPIRY,
        CRL_REFRESH_AFTER,
    ));
    let android_attestation_crl_cache = Arc::new(AndroidAttestationCrlCache::new(
        Arc::new(AndroidAttestationCrlResolver::new(Arc::new(
            ReqwestClient::default(),
        ))),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        1,
        time::Duration::hours(1),
        time::Duration::hours(1),
    ));
    Ok(CertificateValidatorImpl::new(
        key_algorithm_provider,
        crl_cache,
        Arc::new(DefaultClock),
        time::Duration::minutes(1),
        android_attestation_crl_cache,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_validator_that_could_not_be_built_fails_each_call() {
        let validator = SharedCertificateValidator(Err("no TLS backend".to_string()));

        let error = validator
            .parse_pem_chain("", CertificateValidationOptions::no_validation())
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::CRLCheckFailed(details) if details == "no TLS backend"),
            "{error:?}"
        );
    }
}
