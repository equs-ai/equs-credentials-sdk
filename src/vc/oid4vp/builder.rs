use crate::did::universal::UniversalResolver;
use crate::inmem::storage::InMemStorage;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp as api;
use crate::vc::oid4vp::holder::HolderService;
use crate::vc::oid4vp::verifier::VerifierService;
use crate::{did, kms, vault, vc};
use std::marker::PhantomData;
use tracing::{debug, info, instrument, Level};

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum Error {
    #[error("Can't create service: {0}")]
    Build(String),
    #[error("Can't create default DID: {0}")]
    DID(#[from] did::Error),
    #[error("Can't create holder: {0}")]
    HolderInit(#[from] api::HolderError),
}

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
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_client_metadata(mut self, client_metadata: api::ClientMetadata) -> Self {
        self.client_metadata = Some(client_metadata);
        self
    }

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

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
    pub async fn build(self) -> Result<impl api::Verifier, Error> {
        let inner = vc::core::VerifierService::new(&self.client_id);

        // TODO: prune after removing storage usage in verifier
        let storage = InMemStorage::new();

        let verifier = VerifierService::new(
            inner,
            self.kms,
            self.resolver,
            storage,
            self.client_id,
            self.key_metadata,
            self.client_metadata,
        );

        info!("oid4vp-verifier service is initialized");

        Ok(verifier)
    }
}

pub struct HolderBuilder<KH, KMS, V, D>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    D: did::DIDResolver,
{
    // data
    client_id: String,
    key_metadata: KeyMetadata,
    wallet_metadata: Option<api::WalletMetadata>,

    // services
    kms: KMS,
    vault: V,
    resolver: D,
    http_client: Result<reqwest::Client, Error>,

    _marker: PhantomData<KH>,
}

impl<KH, KMS, V> HolderBuilder<KH, KMS, V, UniversalResolver>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
{
    #[instrument(
        level = Level::TRACE,
        skip(kms, vault)
    )]
    pub fn new(kms: KMS, vault: V, key_metadata: KeyMetadata, client_id: String) -> Self {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .https_only(false)
            .build()
            .map_err(|e| Error::Build(e.to_string()));

        info!("oid4vp-holder builder is initialized");

        Self {
            client_id,
            key_metadata,
            kms,
            vault,
            http_client,
            resolver: UniversalResolver::new(),
            wallet_metadata: None,
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, V, D> HolderBuilder<KH, KMS, V, D>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    D: did::DIDResolver,
{
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_wallet_metadata(mut self, wallet_metadata: api::WalletMetadata) -> Self {
        self.wallet_metadata = Some(wallet_metadata);
        self
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Ok(http_client);
        self
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_did_resolver<D_: did::DIDResolver>(
        self,
        resolver: D_,
    ) -> HolderBuilder<KH, KMS, V, D_> {
        HolderBuilder {
            resolver,
            // copied
            client_id: self.client_id,
            wallet_metadata: self.wallet_metadata,
            key_metadata: self.key_metadata,
            kms: self.kms,
            vault: self.vault,
            http_client: self.http_client,
            _marker: Default::default(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err()
    )]
    pub async fn build(self) -> Result<impl api::Holder, Error> {
        let key_metadata = self.key_metadata;
        let holder_metadata = vc::core::HolderMetadata {
            client_id: self.client_id,
            key_metadata,
        };

        debug!(?holder_metadata);

        let inner = vc::core::HolderService::new(self.kms, self.vault, holder_metadata);

        let holder = HolderService::new(
            inner,
            self.resolver,
            self.wallet_metadata,
            self.http_client?,
        );

        info!("oid4vp-holder service is initialized");

        Ok(holder)
    }
}
