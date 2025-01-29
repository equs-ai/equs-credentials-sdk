use common_macros::DebugError;
use iref::iri::InvalidIriRef;
use snafu::{Location, Snafu};
use ssi::dids::{InvalidDID, InvalidDIDURL};
use std::fmt::Debug;
use tracing::Level;

type Level_ = Level;

pub mod didkey;
pub mod didpeer;
pub mod didweb;
pub mod universal;

pub use ssi::claims::ProofValidationError;
pub use ssi::dids::DIDBuf;
pub use ssi::dids::DIDResolver;
/// `DID` Error.
///
/// Enumerates general errors expected during `DID` operations.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported method: {method}"))]
    MethodNotSupported { method: String },
    #[snafu(display("Unsupported key: {type_}"))]
    KeyNotSupported { type_: String },
    #[snafu(display("Invalid format of DID: {details}"))]
    InvalidDidFormat { details: String },
    #[snafu(display("DID generation error: {details}"))]
    DidGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DID buf creation error"))]
    DidBufCreation {
        source: InvalidDID<String>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DID url buf creation error"))]
    DidUrlBufCreation {
        source: InvalidDIDURL<String>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DID Document generation error: {details}"))]
    DidDocGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Resolution error: {details}"))]
    Resolution {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Resolution verification error: {details}"))]
    ResolutionVerification {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Resolving error"))]
    Resolving {
        source: ssi::dids::resolution::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Iri ref creation error"))]
    IriRefCreation {
        source: InvalidIriRef<String>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Parse error"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

/// `Result` alias for `DID`-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

// Basic types definitions
pub use ssi::jwk::JWKResolver;
pub type DID = String;
pub type DIDURL = ssi::dids::DIDURL;
pub type DIDURLBuf = ssi::dids::DIDURLBuf;
pub type DIDDoc = ssi::dids::document::representation::Represented;
pub type DocumentMetadata = ssi::dids::document::Metadata;
pub type VerificationMethodMap = ssi::dids::document::verification_method::DIDVerificationMethod;
pub type Service = ssi::dids::document::Service;
pub type ResolutionMetadata = ssi::dids::resolution::Metadata;
pub type ResolutionOptions = ssi::dids::resolution::Options;
pub type ResolutionOptionsMediaType = ssi::dids::document::representation::MediaType;
pub type ResolutionOptionsParameters = ssi::dids::resolution::Parameters;

/// A result of `DID` resolution.
///
/// Contains resolution metadata, resolved DID doc and the doc's metadata.
#[derive(Debug, Default, Clone)]
pub struct Resolution {
    pub metadata: ResolutionMetadata,
    pub doc: Option<DIDDoc>,
    pub doc_metadata: Option<DocumentMetadata>,
}
