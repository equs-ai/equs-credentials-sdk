use oid4vci::openidconnect::url::Url;

use crate::core_::{did, kms};
use crate::exchange::oid4vc::Error;

pub type AuthorizationRequest = oidc4vp::presentation_exchange::ResponseRequest;
pub type AuthorizationResponse = oidc4vp::response::authorization_response::AuthorizationResponse;
pub type PresentationDefinition = oidc4vp::presentation_exchange::PresentationDefinition;
pub type RequestObject = oidc4vp::request::request_object::RequestObject;


pub trait Verifier {
    // 1. Verifier creates AuthorizationRequest and returns a URI to it
    async fn authz_request(&self, obj: RequestObject) -> Result<Url, Error>;

    // 2. Verifier should return Request Object created before
    async fn presentation_request(&self, nonce: String, state: Option<String>) -> Result<RequestObject, Error>;

    // 3. Verifier to verify proposed VPs and submissions
    async fn verify_presentation(&self, resp: AuthorizationResponse) -> Result<(), Error>;
}

pub trait Holder {
    async fn get_request(&self, url: Url) -> Result<RequestObject, Error>;

    async fn prepare_authorization_response(&self, presentation: PresentationDefinition,
                                            did_url: did::DIDURL, kid: kms::KeyID,
    ) -> Result<AuthorizationResponse, Error>;

    async fn send_authz_response(&self, resp: AuthorizationResponse) -> Result<(), Error>;
}