import { ClaimFormatMap } from "./common";

export interface JWKs {
  keys: Array<Record<string, any>>;
}

/***
 *  An Interface containing the Verifier metadata values..
 *
 * @property {JWKs} [jwks] - JSON Web Key Set containing the client's public keys.
 * @property {ClaimFormatMap} vp_formats - Map of supported verifiable presentation formats.
 * @property {string} [authorization_signed_response_alg] - Algorithm used for signing authorization responses.
 * @property {string} [authorization_encrypted_response_alg] - Algorithm used for encrypting authorization responses.
 * @property {string} [authorization_encrypted_response_enc] - Encryption method used for authorization responses.
 * @property {unknown} [key] - Additional properties may be included in the metadata.
 *
 * @see {@link https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.4|OpenID for Verifiable Presentations}
 */
export interface ClientMetadata {
  jwks?: JWKs;
  vp_formats: ClaimFormatMap;
  authorization_signed_response_alg?: string;
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;

  [key: string]: unknown;
}
