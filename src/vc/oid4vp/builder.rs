use crate::did::universal::UniversalResolver;
use crate::http::{HttpClient, HttpError, HttpSnafu};
use crate::reqwest::ReqwestClient;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp as api;
use crate::vc::oid4vp::holder::HolderService;
use crate::vc::oid4vp::verifier::VerifierService;
use crate::{did, kms, vault, vc};
use snafu::{Location, Snafu};
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::{debug, info, instrument, Level};

/// An `OID4VP` Builder errors.
#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    Build {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;
        Ok(())
    }
}

/// A builder for creating an `OID4VP` `Verifier` instance.
#[derive(Clone)]
pub struct VerifierBuilder<KH, KMS, D>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    D: did::DIDResolver,
{
    // data
    client_id: String,
    key_metadata: KeyMetadata,
    client_metadata: Option<api::ClientMetadata>,

    // services
    kms: KMS,
    resolver: D,

    _marker: PhantomData<KH>,
}

impl<KH, KMS> VerifierBuilder<KH, KMS, UniversalResolver>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
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
    #[instrument(
        level = Level::TRACE,
        skip(kms),
    )]
    pub fn new(kms: KMS, key_metadata: KeyMetadata, client_id: String) -> Self {
        info!("oid4vp-verifier builder is initialized");

        Self {
            client_id,
            key_metadata,
            kms,
            resolver: UniversalResolver::new(),
            client_metadata: None,
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, D> VerifierBuilder<KH, KMS, D>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    D: did::DIDResolver,
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

    /// Sets a custom DID resolver.
    ///
    /// This method allows providing a custom `DIDResolver` for resolving DIDs.
    /// If no custom resolver is provided, the default `UniversalResolver` will be used.
    ///
    /// # Arguments
    ///
    /// * `resolver` - an instance of a custom DID resolver.
    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_did_resolver<D_: did::DIDResolver>(
        self,
        resolver: D_,
    ) -> VerifierBuilder<KH, KMS, D_> {
        VerifierBuilder {
            resolver,
            // copied
            client_id: self.client_id,
            client_metadata: self.client_metadata,
            key_metadata: self.key_metadata,
            kms: self.kms,

            _marker: Default::default(),
        }
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
        let inner = vc::core::VerifierService::new(&self.client_id);

        let verifier = VerifierService::new(
            inner,
            self.kms,
            self.resolver,
            self.client_id,
            self.key_metadata,
            self.client_metadata,
        );

        info!("oid4vp-verifier service is initialized");

        Ok(verifier)
    }
}

/// A builder for creating an `OID4VP` `Holder` API instance.
pub struct HolderBuilder<KH, KMS, V, D, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    D: did::DIDResolver,
    HC: HttpClient,
{
    // data
    client_id: String,
    wallet_metadata: Option<api::WalletMetadata>,

    // services
    kms: KMS,
    vault: V,
    resolver: D,
    http_client: Result<HC, HttpError>,

    _marker: PhantomData<KH>,
}

impl<KH, KMS, V> HolderBuilder<KH, KMS, V, UniversalResolver, ReqwestClient>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
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
        skip(kms, vault)
    )]
    pub fn new(kms: KMS, vault: V, client_id: String) -> Self {
        let http_client = ReqwestClient::new(false, true).map_err(|e| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        });

        info!("oid4vp-holder builder is initialized");

        Self {
            client_id,
            kms,
            vault,
            http_client,
            resolver: UniversalResolver::new(),
            wallet_metadata: None,
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, V, D, HC> HolderBuilder<KH, KMS, V, D, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    D: did::DIDResolver,
    HC: HttpClient,
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
    ) -> HolderBuilder<KH, KMS, V, D, HC_> {
        HolderBuilder {
            client_id: self.client_id,
            wallet_metadata: self.wallet_metadata,
            kms: self.kms,
            vault: self.vault,
            resolver: self.resolver,
            http_client: Ok(http_client),
            _marker: Default::default(),
        }
    }

    /// Sets a custom DID resolver.
    ///
    /// This method allows providing a custom `DIDResolver` for resolving DIDs.
    /// If no custom resolver is provided, the default `UniversalResolver` will be used.
    ///
    /// # Arguments
    ///
    /// * `resolver` - an instance of a custom DID resolver.
    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_did_resolver<D_: did::DIDResolver>(
        self,
        resolver: D_,
    ) -> HolderBuilder<KH, KMS, V, D_, HC> {
        HolderBuilder {
            resolver,
            client_id: self.client_id,
            wallet_metadata: self.wallet_metadata,
            kms: self.kms,
            vault: self.vault,
            http_client: self.http_client,
            _marker: Default::default(),
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
        };

        debug!(?holder_metadata);

        let inner = vc::core::HolderService::new(self.kms, self.vault, holder_metadata);
        let http_client = self.http_client.map_err(|e| {
            BuildSnafu {
                details: format!("Cannot initialize http client: {e}"),
            }
            .build()
        })?;

        let holder = HolderService::new(inner, self.resolver, self.wallet_metadata, http_client);

        info!("oid4vp-holder service is initialized");

        Ok(holder)
    }
}

#[cfg(test)]
mod tests {
    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vp::metadata::{default_client_metadata, default_wallet_metadata};
    use crate::vc::oid4vp::tests::fixtures::CLIENT_ID;
    use crate::vc::oid4vp::{HolderBuilder, VerifierBuilder};

    #[tokio::test]
    async fn build_holder() {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        HolderBuilder::new(kms, vault, CLIENT_ID.to_owned())
            .with_http_client(MockHttpClient::new())
            .with_did_resolver(UniversalResolver::new())
            .with_wallet_metadata(default_wallet_metadata())
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn build_holder_with_defaults() {
        let kms = LocalKms::new();
        let vault = InMemVault::new();

        HolderBuilder::new(kms, vault, CLIENT_ID.to_owned())
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn build_verifier() {
        let kms = LocalKms::new();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let verifier = VerifierBuilder::new(kms, key_metadata, did.clone())
            .with_client_metadata(default_client_metadata())
            .with_did_resolver(UniversalResolver::new())
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn build_verifier_with_defaults() {
        let kms = LocalKms::new();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let verifier = VerifierBuilder::new(kms, key_metadata, did.clone())
            .build()
            .await
            .unwrap();
    }
}
