// Error handling

pub enum DIDError {}

// Basic types definitions

pub type DID = String;

pub type DIDDoc = ssi::did::Document;

pub enum DIDMethod {
    DidKey,
    // etc
}

// Methods results
pub enum State {}

pub struct Created {
    state: State,
    did: Option<DID>,
    doc: Option<DIDDoc>,
}

pub struct Resolution {
    state: State,
    did: Option<DID>,
    doc: Option<DIDDoc>,
}

pub struct Updated;
pub struct Deactivated;

// Methods options
pub struct CreateOptions;
pub struct ResolveOptions;
pub struct UpdateOptions;
pub struct DeactivateOptions;

pub trait DIDCore {
    async fn create(method: DIDMethod, options: CreateOptions) -> Result<Created, DIDError>;

    async fn resolve(did: &DID, options: ResolveOptions) -> Result<Resolution, DIDError>;

    async fn update(did: &DID, options: UpdateOptions) -> Result<Updated, DIDError>;

    async fn deactivate(did: &DID, options: DeactivateOptions) -> Result<Deactivated, DIDError>;
}
