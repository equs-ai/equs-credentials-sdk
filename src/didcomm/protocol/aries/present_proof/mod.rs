use crate::didcomm::protocol::outofband;
use crate::didcomm::{agent, connection, service};
use crate::nonce::Nonce;
use crate::storage;
use crate::vc::core::HolderBinder;
use common_macros::DebugError;
use snafu::{Location, OptionExt, Snafu, ensure};
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

/// The challenge and domain a presentation for `request` must carry. Missing values fall back
/// to the request id and `verifier_did`.
///
/// Any domain is accepted, but a DID domain must be `verifier_did`, so one verifier can't pass
/// on another verifier's request.
///
/// # Errors
///
/// * [Error::InvalidState] - `verifier_did` is missing (state stored before binding existed).
/// * [Error::InvalidCredentialRequest] - the domain is another verifier's DID.
/// * Any error from reading the request attachment.
fn holder_binder(
    request: &message::presentation_request::PresentationRequest,
    verifier_did: Option<&str>,
) -> Result<HolderBinder> {
    let verifier_did = verifier_did.context(InvalidStateSnafu {
        details: "state has no verifier DID; restart with a new presentation request",
    })?;
    let options = request
        .attachments
        .first()
        .map(message::proof_request::ProofRequest::try_from)
        .transpose()?
        .and_then(|proof_request| proof_request.options)
        .unwrap_or_default();

    let domain = match options.domain {
        Some(domain) => {
            ensure!(
                !domain.starts_with("did:") || domain == verifier_did,
                InvalidCredentialRequestSnafu {
                    details: "request domain is a DID other than the one the request was sent from",
                }
            );
            domain
        }
        None => verifier_did.to_owned(),
    };
    let challenge = options.challenge.unwrap_or_else(|| request.id.to_string());

    Ok(HolderBinder {
        nonce: Nonce::from_secret(challenge),
        verifier_id: domain,
        response_uri: None,
    })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;
    use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
    use crate::didcomm::protocol::aries::present_proof::message::proof_request::{
        ProofOptions, ProofRequest,
    };

    const VERIFIER_DID: &str = "did:example:verifier";

    #[rstest]
    #[case::did_domain(Some("challenge"), Some(VERIFIER_DID), "challenge", VERIFIER_DID)]
    #[case::operational_domain(
        Some("challenge"),
        Some("us.gov/DriversLicense"),
        "challenge",
        "us.gov/DriversLicense"
    )]
    #[case::challenge_only(Some("challenge"), None, "challenge", VERIFIER_DID)]
    fn holder_binder_takes_the_request_options(
        #[case] challenge: Option<&str>,
        #[case] domain: Option<&str>,
        #[case] expected_nonce: &str,
        #[case] expected_verifier_id: &str,
    ) {
        let request = request(Some(ProofOptions {
            challenge: challenge.map(str::to_owned),
            domain: domain.map(str::to_owned),
        }));

        let binder = holder_binder(&request, Some(VERIFIER_DID)).unwrap();

        assert_eq!(binder.nonce.secret(), expected_nonce);
        assert_eq!(binder.verifier_id, expected_verifier_id);
    }

    #[rstest]
    #[case::without_options(None)]
    #[case::domain_only(Some(ProofOptions { challenge: None, domain: Some(VERIFIER_DID.to_owned()) }))]
    fn holder_binder_falls_back_to_the_request_id_without_a_challenge(
        #[case] options: Option<ProofOptions>,
    ) {
        let request = request(options);

        let binder = holder_binder(&request, Some(VERIFIER_DID)).unwrap();

        assert_eq!(binder.nonce.secret(), request.id.to_string());
        assert_eq!(binder.verifier_id, VERIFIER_DID);
    }

    #[rstest]
    #[case::did_of_another_verifier(Some(VERIFIER_DID), "did:example:another-verifier")]
    #[case::state_without_verifier_did(None, VERIFIER_DID)]
    fn holder_binder_rejects_a_request_it_cannot_bind(
        #[case] verifier_did: Option<&str>,
        #[case] domain: &str,
    ) {
        let request = request(Some(ProofOptions {
            challenge: Some("challenge".to_owned()),
            domain: Some(domain.to_owned()),
        }));

        let result = holder_binder(&request, verifier_did);

        assert!(
            matches!(
                result,
                Err(Error::InvalidCredentialRequest { .. } | Error::InvalidState { .. })
            ),
            "{result:?}"
        );
    }

    fn request(options: Option<ProofOptions>) -> PresentationRequest {
        let definition =
            serde_json::from_value(json!({ "id": "pd", "input_descriptors": [] })).unwrap();
        let mut proof_request = ProofRequest::new(definition);
        if let Some(options) = options {
            proof_request = proof_request.set_options(options);
        }
        PresentationRequest::new().add_attachment(proof_request.try_into().unwrap())
    }
}
