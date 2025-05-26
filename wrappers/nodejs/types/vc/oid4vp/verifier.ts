import {
  _PresentationSession,
  AuthorizationRequestWithSession,
  AuthorizationResponse,
  AuthResponseOptions,
  Claims,
  InternalOID4VPVerifier,
  JsPassAuthRequestObject,
  PresentationQuery,
  PresentationSession,
  ResolvedPresentationQuery,
  WalletMetadata,
} from "../../..";

/**
 *  The `OID4VP` `Verifier` API.
 *  Supports presentation request and verification flow according to the `OID4VP` specification.
 *  See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
 *
 *  @property createAuthorizationRequest - {@link OID4VPVerifier.createAuthorizationRequest}
 *  @property verifyPresentation - {@link OID4VPVerifier.verifyPresentation}
 */
export class OID4VPVerifier {
  constructor(private readonly inner: InternalOID4VPVerifier) {}

  /**
   *    Creates an `OID4VP` authorization request.
   *    @param {PresentationQuery} presentationQuery - the presentation query specifying the presentation requirements. Either dcql or presentation definition
   *    @param {AuthResponseOptions} passAuthRequestObject - how to pass an authorization request object to holder, by value or by reference.
   *    @param {PassAuthRequestObject} authResponseOptions - config about how and where to send authorization response.
   *    @param {WalletMetadata | null} [walletMetadata] - optional metadata of holder. if it is `null`, default metadata will be used
   *    @returns {AuthorizationRequestWithSession}
   */
  createAuthorizationRequest(
    presentationQuery: PresentationQuery,
    authResponseOptions: AuthResponseOptions,
    passAuthRequestObject: JsPassAuthRequestObject,
    walletMetadata?: WalletMetadata | undefined | null,
  ): Promise<AuthorizationRequestWithSession> {
    const rpq: ResolvedPresentationQuery = {
      presentation_definition: presentationQuery.presentation_definition,
      dcql_query: presentationQuery.dcql_query,
    };
    return this.inner.createAuthorizationRequest(rpq, authResponseOptions, passAuthRequestObject, walletMetadata);
  }

  /**
   *    Verifies the presentation provided by the Holder.
   *    @param {AuthorizationResponse} authorizationResponse - the authorization response containing the VP token and presentation submission.
   *    @param { PresentationSession} session - a session object containing `Nonce` and {@link PresentationQuery}, which are generated when the {@link OID4VPVerifier.createAuthorizationRequest} method is called.
   *    @returns {Claims} - The verified claims as a JSON object on success.
   */
  verifyPresentation(authorizationResponse: AuthorizationResponse, session: PresentationSession): Promise<Claims> {
    const rpq: ResolvedPresentationQuery = {
      presentation_definition: session.presentation_query.presentation_definition,
      dcql_query: session.presentation_query.dcql_query,
    };
    const ps: _PresentationSession = {
      nonce: session.nonce,
      resolvedPresentationQuery: rpq,
      authorizationRequestJwt: session.authorizationRequestJwt,
    };
    return this.inner.verifyPresentation(authorizationResponse, ps);
  }
}
