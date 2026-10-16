/**
 * Authorization Code Grant type parameters
 *
 * @property {string} [issuer_state] Opaque string created by the Credential Issuer
 * that binds the subsequent Authorization Request to a context set up during previous steps.
 * @property {string} [authorization_server] Identifies which Authorization Server to use
 * when multiple entries are available in the authorization_servers parameter.
 */
export interface AuthorizationCodeGrant {
  issuer_state?: string;
  authorization_server?: string;
}

/**
 * Transaction Code requirements for Pre-Authorized Code flow
 *
 * @property {number} [length] Integer specifying the length of the Transaction Code
 * to help the Wallet render the appropriate input screen.
 * @property {string} [input_mode] Input character set type. Possible values are
 * "numeric" (only digits) and "text" (any characters). Default is "numeric".
 * @property {string} [description] Guidance for the Holder on how to obtain the
 * Transaction Code, such as which communication channel it's delivered through.
 */
export interface TransactionCode {
  length?: number;
  input_mode?: string;
  description?: string;
}

/**
 * Pre-Authorization Code Grant type parameters
 *
 * @property {string} pre-authorized_code REQUIRED. The code representing the Credential
 * Issuer's authorization for the Wallet to obtain Credentials of a specified type.
 * @property {TransactionCode} [tx_code] Requirements for a Transaction Code that the
 * Authorization Server expects the End-User to present with the Token Request.
 * @property {number} [interval] Time interval in seconds.
 * @property {string} [authorization_server] Identifies which Authorization Server to use
 * when multiple entries are available in the authorization_servers parameter.
 */
export interface PreAuthorizationCodeGrant {
  "pre-authorized_code": string;
  tx_code?: TransactionCode;
  interval?: number;
  authorization_server?: string;
}

/**
 * Grant Types the Credential Issuer's Authorization Server can process
 *
 * @property {AuthorizationCodeGrant} [authorization_code] Parameters for the
 * "authorization_code" grant type.
 * @property {PreAuthorizationCodeGrant} [urn:ietf:params:oauth:grant-type:pre-authorized_code]
 * Parameters for the "urn:ietf:params:oauth:grant-type:pre-authorized_code" grant type.
 */
export interface CredentialOfferGrants {
  authorization_code?: AuthorizationCodeGrant;
  "urn:ietf:params:oauth:grant-type:pre-authorized_code"?: PreAuthorizationCodeGrant;
}