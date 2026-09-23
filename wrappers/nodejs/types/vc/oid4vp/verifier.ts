import {
  _PresentationSession,
  AuthorizationRequestMetadata,
  AuthorizationRequestWithSession,
  InnerAuthorizationResponse,
  AuthorizationResponseObject,
  Claims,
  CredentialVerificationMetadata,
  InternalOID4VPVerifier,
  PresentationQuery,
  ResolvedPresentationQuery,
  WalletMetadata,
  AuthorizationResponseType,
  ClaimsPresentations,
} from "../../..";

export type AuthorizationResponse = {
  [T in InnerAuthorizationResponse["type"]]: T extends AuthorizationResponseType.Plain
    ? { type: AuthorizationResponseType.Plain; object: AuthorizationResponseObject; jwe?: never }
    : { type: AuthorizationResponseType.Jwe; object?: never; jwe: string };
}[InnerAuthorizationResponse["type"]];

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
   *    @param {AuthorizationRequestMetadata} authorizationRequestMetadata - Metadata used during the creation of AuthorizationRequest. Contains:
   *      {AuthResponseOptions} passAuthRequestObject - how to pass an authorization request object to holder, by value or by reference.
   *      {PassAuthRequestObject} authResponseOptions - config about how and where to send authorization response.
   *      {Array<TransactionDataItem> | undefined | null } [transactionData] - TransactionData. If given, it will be returned as an array of hashes.
   *    @param {WalletMetadata | null} [walletMetadata] - optional metadata of holder. if it is `null`, default metadata will be used
   *    @returns {AuthorizationRequestWithSession}
   */
  createAuthorizationRequest(
    presentationQuery: PresentationQuery,
    authorizationRequestMetadata: AuthorizationRequestMetadata,
    walletMetadata?: WalletMetadata | undefined | null,
  ): Promise<AuthorizationRequestWithSession> {
    const rpq: ResolvedPresentationQuery = {
      presentation_definition: presentationQuery.presentation_definition,
      dcql_query: presentationQuery.dcql_query,
    };
    return this.inner.createAuthorizationRequest(rpq, authorizationRequestMetadata, walletMetadata);
  }

  /**
   *    Verifies the presentation provided by the Holder.
   *    @param {AuthorizationResponse} authorizationResponse - the authorization response containing the VP token and presentation submission.
   *    @param { _PresentationSession} session - a session object containing `Nonce` and {@link resolvedPresentationQuery: ResolvedPresentationQuery}, which are generated when the {@link OID4VPVerifier.createAuthorizationRequest} method is called.
   *    @param {CredentialVerificationMetadata} verificationMetadata - metadata used during/before the Credential Verification:
   *    * {Array<TransactionDataItem> | undefined | null } [transactionData] - TransactionData. If given, it will be used to validate the hashes returned in AuthorizationResponse
   *    * {string | undefined | null } [audience] - In the case of DC API response mode, audience is the bare Origin of the Verifier (e.g. `https://verifier.example.com`); the SDK binds the presentation to it as `origin:<Origin>`.
   *    @returns {Claims} - The verified claims as a JSON object on success.
   */
  verifyPresentation(
    authorizationResponse: AuthorizationResponse,
    session: _PresentationSession,
    verificationMetadata: CredentialVerificationMetadata,
  ): Promise<Claims> {
    return this.inner.verifyPresentation(authorizationResponse, session, verificationMetadata);
  }

  /**
   * Verifies the presentation **and** returns the raw presentations alongside the claims.
   *
   * Runs the same verification as {@link OID4VPVerifier.verifyPresentation} (transaction-data
   * hashes, per-presentation holder binding / proof of possession), and additionally returns
   * the raw presentation(s) per credential id. A Delegate Holder uses this to **store** a
   * returned dSD-JWT delegation grant: the grant's KB-SD-JWT is Holder-signed (proof of
   * possession), and its `aud`/`nonce` are verified, so it is accepted through this normal path.
   *
   * @param {AuthorizationResponse} authorizationResponse - the authorization response containing the VP token and presentation submission.
   * @param {_PresentationSession} session - a session object containing `Nonce` and {@link ResolvedPresentationQuery}.
   * @param {CredentialVerificationMetadata} verificationMetadata - transaction-data and audience metadata.
   *
   * @returns {ClaimsPresentations} - the verified claims plus the raw presentations keyed by credential id.
   */
  verifyAndExtractPresentation(
    authorizationResponse: AuthorizationResponse,
    session: _PresentationSession,
    verificationMetadata: CredentialVerificationMetadata,
  ): Promise<ClaimsPresentations> {
    return this.inner.verifyAndExtractPresentation(authorizationResponse, session, verificationMetadata);
  }
}
