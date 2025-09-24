import { ClaimFormatMap } from "./common";

export interface JWKs {
  keys: Array<Record<string, any>>;
}

/***
 *  An Interface containing the Verifier metadata values..
 *
 * @property {JWKs} [jwks] - JSON Web Key Set containing the client's public keys.
 * @property {ClaimFormatMap} vp_formats_supported - Map of supported verifiable presentation formats.
 * @property {ClaimFormatMap} encrypted_response_enc_values_supported -Non-empty array of strings, where each string is a JWE enc algorithm that can be used as the content encryption algorithm for encrypting the Response
 * @property {unknown} [key] - Additional properties may be included in the metadata.
 *
 * @see {@link https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.4|OpenID for Verifiable Presentations}
 */
export interface ClientMetadata {
  jwks?: JWKs;
  vp_formats_supported: ClaimFormatMap;
  encrypted_response_enc_values_supported?: Array<string> | null | undefined;
  [key: string]: unknown;
}
