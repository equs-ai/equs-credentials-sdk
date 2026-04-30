//! DID methods and DID resolvers.

use common_macros::DebugError;
use iref::iri::InvalidIriRef;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use ssi::dids::{InvalidDID, InvalidDIDURL};
use std::collections::HashSet;
use std::fmt::Debug;
use tracing::Level;

type Level_ = Level;

pub mod didethr;
pub mod didkey;
pub mod didpeer;
pub mod didweb;
pub mod universal;

/// Enumerates errors expected during `Proof Validation` operations.
pub use ssi::claims::ProofValidationError;
pub use ssi::dids::DIDBuf;
pub use ssi::dids::DIDResolver;

/// Enumerates general errors expected during `DID` operations.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported method: {method}"))]
    MethodNotSupported { method: String },
    #[snafu(display("Method already exists: {method}"))]
    MethodAlreadyExists { method: String },
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
use crate::crypto::Key;
pub use ssi::jwk::JWKResolver;
use strum_macros::{EnumString, IntoStaticStr};

/// Decentralized identifier
pub type DID = String;
pub type SpruceDID = ssi::dids::DID;
/// DID URL an identifier of a network location for a specific resource.
pub type DIDURL = ssi::dids::DIDURL;
/// Provides methods for the creation of a `DIDURL`.
pub type DIDURLBuf = ssi::dids::DIDURLBuf;
/// DID document in a specific representation.
pub type DIDDoc = ssi::dids::document::representation::Represented;
/// DID document metadata
pub type DocumentMetadata = ssi::dids::document::Metadata;
/// DID Verification Method
pub type VerificationMethodMap = ssi::dids::document::verification_method::DIDVerificationMethod;
/// Service express ways of communicating with the DID subject or related entities.
pub type Service = ssi::dids::document::Service;
/// DID resolution metadata.
pub type ResolutionMetadata = ssi::dids::resolution::Metadata;
/// DID resolution options
pub type ResolutionOptions = ssi::dids::resolution::Options;
pub type ResolutionOutput = ssi::dids::resolution::Output;
pub type ResolutionError = ssi::dids::resolution::Error;
/// DID document representation media type.
pub type ResolutionOptionsMediaType = ssi::dids::document::representation::MediaType;
/// DID parameters.
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

/// The types of verification relationships that a key may support
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, EnumString, IntoStaticStr)]
pub enum VerificationRelationshipType {
    Authentication,
    Assertion,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

/// Verification method key used in the DID Document
pub struct VerificationMethodKey<'a> {
    pub key: &'a dyn Key,
    pub verification_relationships: HashSet<VerificationRelationshipType>,
}
