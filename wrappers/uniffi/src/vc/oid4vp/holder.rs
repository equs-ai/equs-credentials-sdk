use agent_sdk::vc::oid4vp::{Holder, ResolvedAuthRequest};
use std::collections::HashMap;

use crate::common::{Error, Result};
use crate::utils::parse_url_arg;
use crate::vault::{CredentialEntry, CredentialsFindResult, CredentialsSearchResult};
use crate::vc::oid4vp::{AuthorizationRequest, AuthorizationResponseMetadata, PresentationResult};

/// The `OID4VP` `Holder` API.
///
/// Supports presentation flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// @property getAuthorizationRequest - {@link OID4VPHolder.getAuthorizationRequest}
/// @property presentCredentialsAuto - {@link OID4VPHolder.presentCredentialsAuto}
/// @property findVcsForPresentation - {@link OID4VPHolder.findVcsForPresentation}
/// @property presentCredentials - {@link OID4VPHolder.presentCredentials}
#[derive(uniffi::Object)]
pub struct OID4VPHolder(Box<dyn Holder>);

impl OID4VPHolder {
    pub fn new(holder: impl Holder + 'static) -> Self {
        OID4VPHolder(Box::new(holder))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl OID4VPHolder {
    /// Fetches the `OID4VP` authorization request object from the provided URI.
    /// If the validation of authorization request fails then related `ProtocolError` response will be sent to the `response_uri` endpoint
    ///
    /// @param {string} requestUri - a request URI provided by the authorization URL.
    ///
    /// @returns {AuthorizationRequest} A {@link AuthorizationRequest} with the presentation definition and other relevant details on success.
    pub async fn get_authorization_request(
        &self,
        request_uri: String,
    ) -> Result<AuthorizationRequest> {
        self.0
            .get_authorization_request(
                &parse_url_arg(&request_uri).map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            )
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))
            .and_then(|result| result.try_into())
    }

    /// Automatically presents credentials to the Verifier based on the authorization request.
    ///
    /// This method selects the first appropriate credential that matches the requirements of the authorization request.
    /// To present specific credentials, use {@link OID4VPHolder.findVcsForPresentation} to discover suitable credentials and
    /// {@link OID4VPHolder.presentCredentials} to manually present them.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
    /// @param {AuthorizationResponseMetadata} authResponseMetadata - the metadata for the authorization response.
    ///
    /// @returns {PresentationResult} - The result of presenting credentials, which can be either:
    ///   * {PresentationResult::DcApi} - {AuthorizationResponse} when Digital Credentials API response mode is used (`response_mode: dc_api` or `response_mode: dc_api.jwt`)
    ///   * {PresentationResult::RedirectUri} - Redirect URI, which is got either:
    ///     * Optionally can be returned from Verifier after submitting Authorization Response.
    ///     * In the case of Same Device Flow, Authorization Response is embedded into the redirect URI as a fragment.
    ///   * {PresentationResult::Presented} - Presentation is successfully presented to the Verifier.
    pub async fn present_credentials_auto(
        &self,
        auth_request: AuthorizationRequest,
        auth_response_metadata: AuthorizationResponseMetadata,
    ) -> Result<PresentationResult> {
        let result = self
            .0
            .present_credentials_auto(&auth_request.try_into()?, &auth_response_metadata)
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))?;

        Ok(result.into())
    }

    /// Finds verifiable credentials required for the presentation based on the authorization request.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
    ///
    /// @returns {Record<string, Array<CredentialEntry>}
    /// * An object of credentials that satisfy the authorization request's requirements.
    /// * If no matching credentials are found, an empty object is returned.
    pub async fn find_vcs_for_presentation(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<HashMap<String, CredentialsFindResult>> {
        let vcs_for_presentation = self
            .0
            .find_vcs_for_presentation(&auth_request.try_into()?)
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))?;

        let mut result = HashMap::<String, CredentialsFindResult>::new();

        for (key, value) in vcs_for_presentation {
            match value {
                agent_sdk::vc::oid4vp::CredentialsFindResult::Credentials(creds) => {
                    result.insert(
                        key,
                        CredentialsFindResult {
                            data: CredentialsSearchResult::Credentials(creds),
                        },
                    );
                }
                agent_sdk::vc::oid4vp::CredentialsFindResult::Reason(reasons) => {
                    result.insert(
                        key,
                        CredentialsFindResult {
                            data: CredentialsSearchResult::Reason(reasons),
                        },
                    );
                }
            }
        }

        Ok(result)
    }

    /// Manually presents credentials to the Verifier.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request.
    /// @param {Record<string, CredentialEntry>} credentialMapping - the map of credentials required for the presentation.
    /// @param {AuthorizationResponseMetadata} authResponseMetadata -the authorization response metadata.
    ///
    /// @returns {PresentationResult} - The result of presenting credentials, which can be either:
    ///   * {PresentationResult::DcApi} - {AuthorizationResponse} when Digital Credentials API response mode is used (`response_mode: dc_api` or `response_mode: dc_api.jwt`)
    ///   * {PresentationResult::RedirectUri} - Redirect URI, which is got either:
    ///     * Optionally can be returned from Verifier after submitting Authorization Response.
    ///     * In the case of Same Device Flow, Authorization Response is embedded into the redirect URI as a fragment.
    ///   * {PresentationResult::Presented} - Presentation is successfully presented to the Verifier.
    pub async fn present_credentials(
        &self,
        auth_request: AuthorizationRequest,
        credential_mapping: HashMap<String, Vec<CredentialEntry>>,
        auth_response_metadata: AuthorizationResponseMetadata,
    ) -> Result<PresentationResult> {
        let result = self
            .0
            .present_credentials(
                &auth_request.try_into()?,
                &credential_mapping,
                &auth_response_metadata,
            )
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))?;

        Ok(result.into())
    }

    /// Decline the authorization request by sending authorization error response to the `response_uri` endpoint.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request.
    /// @returns {string | null}
    /// An optional redirect URL(in case of Same Device Flow) where the error response is embedded as a fragment.
    pub async fn decline_authorization_request(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<Option<String>> {
        let auth_request: ResolvedAuthRequest = auth_request.try_into()?;
        let redirect_url = self
            .0
            .decline_authorization_request(&auth_request)
            .await
            .map_err(|err| Error::OID4VPHolder(err.to_string()))?;

        Ok(redirect_url.map(|url| url.to_string()))
    }
}
