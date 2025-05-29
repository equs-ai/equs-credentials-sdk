use common_macros::DebugError;
use snafu::{Location, Snafu};
use ssi::dids::InvalidDIDURL;

use crate::didcomm::core::message_type;
use crate::didcomm::protocol::outofband;
use crate::didcomm::{agent, connection, service};
use crate::utils::http::MimeType;
use crate::{kms, storage, vault, vc};

pub mod holder;
pub mod issuer;
pub mod message;
pub mod protocol;

const PROTOCOL_NAME: &str = "issue-credential";
const PROTOCOL_VERSION: &str = "3.0";
const OFFER_CREDENTIAL: &str = "offer-credential";
const ISSUE_CREDENTIAL: &str = "issue-credential";
const PROPOSE_CREDENTIAL: &str = "propose-credential";
const REQUEST_CREDENTIAL: &str = "request-credential";
const CREDENTIAL_PREVIEW: &str = "credential-preview";

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Invalid credential value type: {type_}"))]
    InvalidCredentialValueType { type_: MimeType },
    #[snafu(display("Invalid attachment encoding: {details}"))]
    InvalidAttachmentEncoding { details: String },
    #[snafu(display("Invalid attributes: {details}"))]
    InvalidAttributesStructure { details: String },
    #[snafu(display("Invalid state: {details}"))]
    InvalidState { details: String },
    #[snafu(display("Invalid attachment: {details}"))]
    InvalidAttachment { details: String },
    #[snafu(display("Invalid Credential Offer: {details}"))]
    InvalidCredentialOffer { details: String },
    #[snafu(display("Invalid Credential Request: {details}"))]
    InvalidCredentialRequest { details: String },
    #[snafu(display("Message is out of thread"))]
    MessageIsOutOfThread,
    #[snafu(display("Agent error"))]
    Agent {
        source: agent::Error,
        #[snafu(implicit)]
        location: Location,
    },
    DIDCommService {
        source: service::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("KMS error"))]
    KMS {
        source: kms::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Storage error"))]
    Storage {
        source: storage::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Vault error"))]
    Vault {
        source: vault::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DID url buf resolution error"))]
    DidUrlResolution {
        source: InvalidDIDURL<String>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("VC error"))]
    VC {
        source: vc::formats::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("VC Metadata error"))]
    VCMetadata {
        source: vc::metadata::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Parse error"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Incorrect Message Type"))]
    IncorrectMessageType {
        source: message_type::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Connection error"))]
    Connection {
        source: connection::Error,
        #[snafu(implicit)]
        location: Location,
    },
    OOB {
        source: outofband::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
