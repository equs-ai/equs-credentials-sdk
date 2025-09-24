use crate::didcomm::protocol::outofband;
use crate::didcomm::{agent, connection, service};
use crate::storage;
use common_macros::DebugError;
use snafu::{Location, Snafu};
use ssi::dids::InvalidDIDURL;

pub mod holder;
pub mod message;
mod protocol;
pub mod verifier;

const PROTOCOL_NAME: &str = "present-proof";
const PROTOCOL_VERSION: &str = "3.0";
const REQUEST_PRESENTATION: &str = "request-presentation";
const PRESENTATION: &str = "presentation";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, DebugError)]
pub enum Error {
    #[snafu(display("Agent error"))]
    Agent {
        source: agent::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Holder in state {current_state} not ready to get {next_state} message"))]
    NotReady {
        current_state: String,
        next_state: String,
    },

    #[snafu(display("Invalid state: {details}"))]
    InvalidState { details: String },

    #[snafu(display("Create presentation failed"))]
    CreatePresentation {
        source: crate::vc::core::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("DIDComm Service error"))]
    DIDCommService {
        source: service::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Connection error"))]
    Connection {
        source: connection::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Parse error"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Decode error"))]
    Decode {
        source: base64::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("DID url buf resolution error"))]
    DidUrlResolution {
        source: InvalidDIDURL<String>,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Invalid Proof: {details}"))]
    InvalidProof { details: String },

    #[snafu(display("Verification failed"))]
    VerificationFailed {
        source: crate::vc::core::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Storage error"))]
    Storage {
        source: storage::Error,
        #[snafu(implicit)]
        location: Location,
    },

    OOB {
        source: outofband::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Invalid attachment: {details}"))]
    InvalidAttachment {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Invalid attachment encoding: {details}"))]
    InvalidAttachmentEncoding { details: String },

    #[snafu(display("Error during generating nonce"))]
    NonceGeneration { source: crate::nonce::Error },

    #[snafu(display("Invalid Credential Request: {details}"))]
    InvalidCredentialRequest { details: String },

    #[snafu(display("Could not parse Presentation Definition"))]
    PresentationDefinitionParse {
        source: crate::vc::presentation_exchange::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Could not build Reqwest Client"))]
    ReqwestClientBuilder {
        source: crate::http::HttpError,
        #[snafu(implicit)]
        location: Location,
    },
}
