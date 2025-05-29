import {
  AuthorizationRequest,
  AuthorizationResponseMetadata,
  CredentialEntry,
  InnerOID4VPHolder,
  PresentationQuery,
} from "../../..";

/**
 *  The `OID4VP` `Holder` API.
 * Supports presentation flow according to the `OID4VP` specification.
 * See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
 * @property getIssuerMetadata - {@link OID4VPHolder.getIssuerMetadata}
 * @property getAuthorizationRequest - {@link OID4VPHolder.getAuthorizationRequest}
 * @property presentCredentialsAuto - {@link OID4VPHolder.presentCredentialsAuto}
 * @property findVcsForPresentation - {@link OID4VPHolder.findVcsForPresentation}
 * @property presentCredentials - {@link OID4VPHolder.presentCredentials}
 */
export class OID4VPHolder {
  constructor(private readonly inner: InnerOID4VPHolder) {}

  /**
   *   Fetches the `OID4VP` authorization request object from the provided URI.
   *   If the validation of authorization request fails then related `ProtocolError` response will be sent to the `response_uri` endpoint
   *   @param {string} requestUri - a request URI provided by the authorization URL.
   *   @returns {AuthorizationRequest} A {@link AuthorizationRequest}
   */
  async getAuthorizationRequest(requestUri: string): Promise<AuthorizationRequest> {
    const authRequest = await this.inner.getAuthorizationRequest(requestUri);

    const query: PresentationQuery = Object.hasOwn(authRequest, "dcql_query")
      ? {
          dcql_query: authRequest.resolved_presentation_query.dcql_query,
        }
      : {
          presentation_definition: authRequest.resolved_presentation_query.presentation_definition,
        };
    return new AuthorizationRequest({
      client_id: authRequest.client_id,
      client_metadata: authRequest.client_metadata,
      response_uri: authRequest.response_uri,
      response_mode: authRequest.response_mode,
      response_type: authRequest.response_type,
      nonce: authRequest.nonce,
      state: authRequest.state,
      ...query,
    });
  }

  /**
   *   Automatically presents credentials to the Verifier based on the authorization request.
   *   This method selects the first appropriate credential that matches the requirements of the authorization request.
   *   To present specific credentials, use {@link OID4VPHolder.findVcsForPresentation} to discover suitable credentials and
   *   {@link OID4VPHolder.presentCredentials} to manually present them.
   *   @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
   *   @param {AuthorizationResponseMetadata} authResponseMetadata - the metadata for the authorization response.
   *   @returns {string | null}
   *   * A redirect URL if the presentation is successful
   *   * `null` on success without redirection.
   */
  async presentCredentialsAuto(
    authRequest: AuthorizationRequest,
    authResponseMetadata: AuthorizationResponseMetadata,
  ): Promise<string | null> {
    return await this.inner.presentCredentialsAuto(authRequest.toRustObject(), authResponseMetadata);
  }

  /**
   * Finds verifiable credentials required for the presentation based on the authorization request.
   * @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
   * @returns {Record<string, Array<CredentialEntry>}
   * An object of credentials that satisfy the authorization request's requirements.
   * If no matching credentials are found, an empty object is returned.
   */
  async findVcsForPresentation(authRequest: AuthorizationRequest): Promise<Record<string, Array<CredentialEntry>>> {
    return await this.inner.findVcsForPresentation(authRequest.toRustObject());
  }

  /**
   * Manually presents credentials to the Verifier.
   * @param {AuthorizationRequest} authRequest - the resolved authorization request.
   * @param {Record<string, CredentialEntry>} credentialMapping - the map of credentials required for the presentation.
   * @param {AuthorizationResponseMetadata} authResponseMetadata -the authorization response metadata.
   * @returns {string | null}
   * A redirect URL if the presentation is successful
   * `null` on success without redirection.
   */
  async presentCredentials(
    authRequest: AuthorizationRequest,
    credentialMapping: Record<string, CredentialEntry>,
    authResponseMetadata: AuthorizationResponseMetadata,
  ): Promise<string | null> {
    return await this.inner.presentCredentials(authRequest.toRustObject(), credentialMapping, authResponseMetadata);
  }

  /**
   * Decline the authorization request by sending authorization error response to the `response_uri` endpoint.
   * @returns {string | null}
   * An optional redirect URL(in case of Same Device Flow) where the error response is embedded as a fragment.
   * @param {AuthorizationRequest} authRequest - the resolved authorization request.
   */
  async declineAuthorizationRequest(authRequest: AuthorizationRequest): Promise<void> {
    await this.inner.declineAuthorizationRequest(authRequest.toRustObject());
  }
}
