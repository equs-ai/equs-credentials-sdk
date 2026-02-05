use crate::did::universal::{DIDResolver, UniversalResolver};
use crate::http::{HttpClient, HttpError, HttpSnafu};
use crate::kms::Kms;
use crate::nonce::NonceHandler;
use crate::reqwest::ReqwestClient;
use crate::reqwest::builder::ReqwestClientBuilder;
use crate::vc::core::KeyMetadata;
use crate::vc::core::{DEFAULT_POP_LIFETIME_MINUTES, ProofOfPossessionMetadata};
use crate::vc::oid4vp as api;
use crate::vc::oid4vp::ClientId;
use crate::vc::oid4vp::holder::HolderService;
use crate::vc::oid4vp::jwe::JweDecrypt;
use crate::vc::oid4vp::verifier::VerifierService;
use crate::{kms, vault, vc};
use common_macros::DebugError;
use snafu::ensure;
use snafu::{Location, Snafu};
use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use time::Duration;
use tracing::{Level, debug, info, instrument};

/// An `OID4VP` Builder errors.
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Could not build {}", details))]
    Build {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

/// A builder for creating an `OID4VP` `Verifier` instance.
pub struct VerifierBuilder<KH, KMS, NG, HC>
where
    KH: kms::KeyHandle,
    KMS: Kms<KH> + JweDecrypt<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    // data
    client_id: ClientId,
    key_metadata: KeyMetadata,
    client_metadata: Option<api::ClientMetadata>,

    // services
    kms: KMS,
    nonce_generator: NG,
    did_resolver: UniversalResolver,
    http_client: Result<HC, HttpError>,

    trusted_certs_skids: Option<HashSet<String>>,
    _marker: PhantomData<KH>,
}

impl<KH, KMS, NG> VerifierBuilder<KH, KMS, NG, ReqwestClient>
where
    KH: kms::KeyHandle,
    KMS: Kms<KH> + JweDecrypt<KH>,
    NG: NonceHandler,
{
    /// Creates a new instance of `VerifierBuilder` with default configurations.
    ///
    /// # Arguments
    ///
    /// * `kms` - a Key Management System (KMS) instance responsible for managing cryptographic keys.
    /// * `key_metadata` - a `KeyMetadata` with `DIDURL` and `KID` to be used for signing operations.
    /// * `client_id` - the Client ID of the `Verifier`.
    ///
    /// # Returns
    ///
    /// A new `VerifierBuilder` instance
    #[instrument(level = Level::TRACE, skip(kms, nonce_generator))]
    pub fn new(
        kms: KMS,
        nonce_generator: NG,
        key_metadata: KeyMetadata,
        client_id: ClientId,
    ) -> Self {
        let http_client = ReqwestClientBuilder::new().build().map_err(|e| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        });

        info!("oid4vp-verifier builder is initialized");
        Self {
            client_id,
            key_metadata,
            kms,
            nonce_generator,
            http_client,
            did_resolver: UniversalResolver::default(),
            client_metadata: None,
            trusted_certs_skids: None,
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, NG, HC> VerifierBuilder<KH, KMS, NG, HC>
where
    KH: kms::KeyHandle,
    KMS: Kms<KH> + JweDecrypt<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    /// Sets the Verifier's client metadata.
    ///
    /// This method allows setting custom metadata for the Verifier.
    /// If no client metadata is provided, a default value will be used.
    ///
    /// # Arguments
    ///
    /// * `client_metadata` - a JSON object containing the Verifier metadata values
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_client_metadata(mut self, client_metadata: api::ClientMetadata) -> Self {
        self.client_metadata = Some(client_metadata);
        self
    }

    /// Sets the Verifier's client metadata.
    ///
    /// This method allows setting custom did resolver for the Verifier.
    /// If did resolver is provided, it will be added to Universal resolver.
    /// Otherwise, default Universal resolver will be used.
    ///
    /// # Arguments
    ///
    /// * `did_resolver` - a did resolver implementing `DIDResolver` trait
    #[instrument(
        level = Level::TRACE,
        skip(self, did_resolver),
    )]
    pub fn with_did_resolver(
        mut self,
        did_resolver: impl DIDResolver + 'static,
    ) -> Result<Self, Error> {
        self.did_resolver
            .add_resolver(did_resolver)
            .map_err(|err| {
                BuildSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        Ok(self)
    }

    /// Use a specific `HttpClient`.
    ///
    /// # Arguments
    ///
    /// * `http_client` - a http client.
    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_http_client<HC_: HttpClient + 'static>(
        self,
        http_client: HC_,
    ) -> VerifierBuilder<KH, KMS, NG, HC_> {
        VerifierBuilder {
            http_client: Ok(http_client),
            // copied
            client_id: self.client_id,
            key_metadata: self.key_metadata,
            client_metadata: self.client_metadata,
            kms: self.kms,
            did_resolver: self.did_resolver,
            nonce_generator: self.nonce_generator,
            _marker: Default::default(),
            trusted_certs_skids: self.trusted_certs_skids,
        }
    }

    /// Add a trusted root x.509 certificate.
    /// The certificate must be:
    ///  * CA certificate and must have 'Key Cert Sign' and 'CRL Sign' bits set in the key usage extension
    ///  * Valid at the current time
    ///
    /// # Arguments
    ///
    /// * `pem_bytes` - a PEM-encoded certificate.
    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn add_trusted_root_certificate(mut self, pem_bytes: &[u8]) -> Result<Self, Error> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem_bytes).map_err(|e| {
            BuildSnafu {
                details: format!("Cannot parse certificate from pem bytes: {}", e),
            }
            .build()
        })?;

        let cert = pem.parse_x509().map_err(|e| {
            {
                BuildSnafu {
                    details: format!("Cannot parse certificate: {}", e),
                }
            }
            .build()
        })?;

        ensure!(
            cert.is_ca(),
            BuildSnafu {
                details: "Certificate is not CA".to_string(),
            }
        );

        cert.verify_signature(None).map_err(|e| {
            BuildSnafu {
                details: format!("Cannot verify certificate signature: {}", e),
            }
            .build()
        })?;

        let key_usage = cert
            .key_usage()
            .map_err(|e| {
                BuildSnafu {
                    details: format!("Cannot extract key usage from certificate: {}", e),
                }
                .build()
            })?
            .ok_or_else(|| {
                BuildSnafu {
                    details: "Certificate does not contain key usage extension".to_string(),
                }
                .build()
            })?;

        ensure!(
            cert.validity.is_valid(),
            BuildSnafu {
                details: "Certificate is not valid at the current time.".to_string(),
            }
        );

        ensure!(
            key_usage.value.key_cert_sign() && key_usage.value.crl_sign(),
            BuildSnafu {
                details:
                    "Certificate does not have 'Key Cert Sign' and 'CRL Sign' keyCertSign bits set"
                        .to_string(),
            }
        );

        let skid = one_core::mapper::x509::subject_key_identifier(&cert)
            .map_err(|e| {
                BuildSnafu {
                    details: format!(
                        "Cannot extract subject key identifier from certificate: {}",
                        e
                    ),
                }
                .build()
            })?
            .ok_or_else(|| {
                BuildSnafu {
                    details: "Certificate does not contain subject key identifier".to_string(),
                }
                .build()
            })?;

        let mut trusted_certs_skids = self.trusted_certs_skids.unwrap_or_default();
        trusted_certs_skids.insert(skid);
        self.trusted_certs_skids = Some(trusted_certs_skids);

        Ok(self)
    }

    /// Builds the `Verifier` API instance based on the current configuration of the builder.
    ///
    /// # Returns
    ///
    /// The `Verifier` API instance on success.
    ///
    /// # Errors
    ///
    /// [Error::Build] - if the build process fails.
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
    pub async fn build(self) -> Result<impl api::Verifier, Error> {
        let http_client = self.http_client.map_err(|e| {
            BuildSnafu {
                details: format!("Cannot initialize http client: {e}"),
            }
            .build()
        })?;

        let mut inner = vc::core::VerifierService::new(
            &self.client_id.get_full_id(),
            self.did_resolver.clone(),
        );
        inner = inner.with_verification_params(vc::core::VerificationParams {
            trusted_certs_skids: self.trusted_certs_skids,
        });

        let verifier = VerifierService::new(
            inner,
            self.kms,
            self.nonce_generator,
            http_client,
            self.client_id,
            self.key_metadata,
            self.did_resolver,
            self.client_metadata,
        );

        info!("oid4vp-verifier service is initialized");

        Ok(verifier)
    }
}

/// A builder for creating an `OID4VP` `Holder` API instance.
pub struct HolderBuilder<KH, KMS, V, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH> + Clone,
    V: vault::Vault,
    HC: HttpClient,
{
    // data
    client_id: String,
    wallet_metadata: Option<api::WalletMetadata>,

    // services
    kms: KMS,
    vault: V,
    did_resolver: UniversalResolver,
    http_client: Arc<HC>,
    pop: ProofOfPossessionMetadata,
    nonce_handler: Option<Box<dyn NonceHandler>>,
    _marker: PhantomData<KH>,
}

impl<KH, KMS, V, HC> HolderBuilder<KH, KMS, V, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH> + Clone,
    V: vault::Vault,
    HC: HttpClient + 'static,
{
    /// Creates a new instance of `HolderBuilder` with default configurations.
    ///
    /// # Arguments
    ///
    /// * `kms` - a Key Management System (KMS) instance responsible for managing cryptographic keys.
    /// * `vault` - a Vault service used for securely storing credentials.
    /// * `client_id` - the Client ID of the `Holder`.
    ///
    /// # Returns
    ///
    /// A new `HolderBuilder` instance.
    #[instrument(
        level = Level::TRACE,
        skip(kms, vault, http_client),
    )]
    pub fn new(kms: KMS, vault: V, client_id: String, http_client: HC) -> Self {
        info!("oid4vp-holder builder is initialized");

        let http_client = Arc::new(http_client);
        let did_resolver = UniversalResolver::new(http_client.clone());

        Self {
            client_id,
            kms,
            vault,
            http_client,
            did_resolver,
            wallet_metadata: None,
            pop: ProofOfPossessionMetadata {
                lifetime: Duration::minutes(DEFAULT_POP_LIFETIME_MINUTES),
                not_before: None,
            },
            _marker: Default::default(),
            nonce_handler: None,
        }
    }
}

impl<KH, KMS, V, HC> HolderBuilder<KH, KMS, V, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH> + Clone,
    V: vault::Vault,
    HC: HttpClient + 'static,
{
    /// Sets custom wallet metadata for the holder.
    ///
    /// This method allows providing a custom wallet metadata.
    /// If not provided, a default will be used.
    ///
    /// # Arguments
    ///
    /// * `wallet_metadata` - metadata defining the credential formats, proof types, and algorithms supported by the wallet.
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_wallet_metadata(mut self, wallet_metadata: api::WalletMetadata) -> Self {
        self.wallet_metadata = Some(wallet_metadata);
        self
    }

    /// Use a specific `Proof of Possession` generation config.
    ///
    /// # Arguments
    ///
    /// * `pop` - Proof Of Possession generation config
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_pop(mut self, pop: ProofOfPossessionMetadata) -> Self {
        self.pop = pop;
        self
    }

    /// Sets custom did resolver for the holder.
    ///
    /// This method allows providing a custom did resolver.
    /// If provided, it can be used to resolve did into the did document
    ///
    /// # Errors
    ///
    /// [Error::Build] - if did method already exists.
    ///
    /// # Arguments
    ///
    /// * `did_resolver` - did resolver implementing `DIDResolver`.
    #[instrument(
        level = Level::TRACE,
        skip(self, did_resolver),
    )]
    pub fn with_did_resolver(
        mut self,
        did_resolver: impl DIDResolver + 'static,
    ) -> Result<Self, Error> {
        self.did_resolver
            .add_resolver(did_resolver)
            .map_err(|err| {
                BuildSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        Ok(self)
    }

    /// Sets a custom HTTP client for the holder.
    ///
    /// This method allows providing a custom HTTP client for the holder.
    /// If not provided, a default HTTP client will be used.
    ///
    /// # Arguments
    ///
    /// * `http_client` - a custom HTTP client instance.
    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_http_client<HC_: HttpClient>(
        self,
        http_client: HC_,
    ) -> HolderBuilder<KH, KMS, V, HC_> {
        HolderBuilder {
            client_id: self.client_id,
            wallet_metadata: self.wallet_metadata,
            kms: self.kms,
            vault: self.vault,
            did_resolver: self.did_resolver,
            http_client: Arc::new(http_client),
            pop: self.pop,
            _marker: Default::default(),
            nonce_handler: self.nonce_handler,
        }
    }

    /// Sets custom nonce_handler for the holder.
    ///
    /// This NonceHandler is used to generate 'wallet_nonce' and to validate it
    /// during fetching AuthorizationRequest via reference.
    /// Details can be found here: <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#name-request-uri-method-post>
    /// If not provided, wallet nonce is not handled
    ///
    /// # Arguments
    ///
    /// * `nonce_handler` - an implementation of NonceHandler trait.
    pub fn with_nonce_handler(
        self,
        nonce_handler: Box<dyn NonceHandler>,
    ) -> HolderBuilder<KH, KMS, V, HC> {
        HolderBuilder {
            client_id: self.client_id,
            wallet_metadata: self.wallet_metadata,
            kms: self.kms,
            vault: self.vault,
            did_resolver: self.did_resolver,
            http_client: self.http_client,
            pop: self.pop,
            _marker: Default::default(),
            nonce_handler: Some(nonce_handler),
        }
    }

    /// Builds the `Holder` API instance based on the current configuration of the builder.
    ///
    /// # Returns
    ///
    /// The `Holder` API instance on success.
    ///
    /// # Errors
    ///
    /// [Error::Build] - if the build process fails.
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err()
    )]
    pub async fn build(self) -> Result<impl api::Holder, Error> {
        let holder_metadata = vc::core::HolderMetadata {
            client_id: self.client_id,
            pop: self.pop,
        };

        debug!(?holder_metadata);

        let inner = vc::core::HolderService::new(
            self.kms.clone(),
            self.vault,
            holder_metadata,
            self.did_resolver.clone(),
            self.http_client.clone(),
        );

        let holder = HolderService::new(
            inner,
            self.http_client,
            self.kms,
            self.did_resolver,
            self.wallet_metadata,
            self.nonce_handler,
        );

        info!("oid4vp-holder service is initialized");

        Ok(holder)
    }
}

#[cfg(test)]
mod tests {
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::inmem::vault::InMemVault;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vp::metadata::{default_client_metadata, default_wallet_metadata};
    use crate::vc::oid4vp::tests::fixtures::CLIENT_ID;
    use crate::vc::oid4vp::{ClientId, HolderBuilder, VerifierBuilder};

    #[tokio::test]
    async fn build_holder() {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        HolderBuilder::new(kms, vault, CLIENT_ID.to_owned(), MockHttpClient::new())
            .with_wallet_metadata(default_wallet_metadata())
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn build_holder_with_defaults() {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        HolderBuilder::new(kms, vault, CLIENT_ID.to_owned(), MockHttpClient::new())
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn build_verifier() {
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let verifier = VerifierBuilder::new(
            kms,
            nonce_gen,
            key_metadata,
            ClientId::from_did(&did).unwrap(),
        )
        .with_client_metadata(default_client_metadata())
        .build()
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn build_verifier_with_defaults() {
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let verifier = VerifierBuilder::new(
            kms,
            nonce_gen,
            key_metadata,
            ClientId::from_did(&did).unwrap(),
        )
        .build()
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn build_verifier_with_trusted_certs() {
        let pem = "-----BEGIN CERTIFICATE-----
MIIBZzCCAQ6gAwIBAgIUGaB+RAZje4MNjJqrAlNx1ByAiL8wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHQ0EgQ2VydDAeFw0yNTEyMTUxMDU2MzBaFw0zNTEyMTMxMDU2
MzBaMBIxEDAOBgNVBAMMB0NBIENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASVMf5Ykf8dzr46duTAZN3X2iFC1sp1pL15V3u/KDsmPjR21VnK1uv6kDvEziF7
VyIFbvb40t/+c5eB3jg1cMq4o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBhjAdBgNVHQ4EFgQULHoOFFycXvdnCIlsyQiI5izPKkMwCgYIKoZIzj0E
AwIDRwAwRAIgF+H7wT7a95WbiE+DDlZrQ7U3RlCUOMCFqudFRz+K6I4CIAT35kig
4Q1ALvtXiWKDOjZIVxlw5eKQiq0dsd+bXKZE
-----END CERTIFICATE-----";

        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let verifier = VerifierBuilder::new(
            kms,
            nonce_gen,
            key_metadata,
            ClientId::from_did(&did).unwrap(),
        )
        .add_trusted_root_certificate(pem.as_bytes())
        .unwrap()
        .build()
        .await
        .unwrap();
    }
}
