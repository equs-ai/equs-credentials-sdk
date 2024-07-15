// Error handling

use std::fmt;
use crate::core_::kms;

#[derive(fmt::Debug)]
pub enum DIDError {}

// Basic types definitions

pub type DID = String;
pub type DIDURL = ssi::did::DIDURL;
pub type DIDDoc = ssi::did::Document;

pub enum DIDMethod {
    DidKey,
    DidWeb,
    // etc
}

// Methods results
#[derive(Default)]
pub enum State {
    #[default]
    Ready,
    // etc
}

#[derive(Default)]
pub struct Created {
    pub state: State,
    pub did: Option<DID>,
    pub doc: Option<DIDDoc>,
}

pub struct Resolution {
    pub state: State,
    pub did: Option<DID>,
    pub doc: Option<DIDDoc>,
}

pub struct Updated;
pub struct Deactivated;

// Methods options
pub struct CreateOptions;
pub struct ResolveOptions;
pub struct UpdateOptions;
pub struct DeactivateOptions;

pub trait DIDCore {
    async fn create<S: kms::Signer>(method: DIDMethod, signer: S, options: CreateOptions) -> Result<Created, DIDError>;

    async fn resolve(did: &DID, options: ResolveOptions) -> Result<Resolution, DIDError>;

    async fn update(did: &DID, options: UpdateOptions) -> Result<Updated, DIDError>;

    async fn deactivate(did: &DID, options: DeactivateOptions) -> Result<Deactivated, DIDError>;
}
