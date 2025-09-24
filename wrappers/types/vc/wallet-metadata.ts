import { ClaimFormatMap } from "./common";

/**
 * Wallet Metadata for OpenID for Verifiable Presentations (OID4VP)
 *
 * @property {string} authorization_endpoint REQUIRED. URL of the Wallet's Authorization Endpoint
 * @property {ClaimFormatMap} vp_formats_supported REQUIRED. Verifiable Presentation formats supported
 * @property {Array<string>} [response_types_supported] OAuth 2.0 response_type values supported
 * @property {Array<string>} [client_id_prefixes_supported] Client identifier prefixes supported
 * @property {Array<string>} [request_object_signing_alg_values_supported] JWS algorithms for Request Object signing
 * @property {Array<string>} [scopes_supported] OAuth 2.0 scope values recognized
 * @property {Array<string>} [subject_syntax_types_supported] Subject syntax types supported
 * @property {Array<string>} [id_token_types_supported] ID Token types supported
 * @property {Array<string>} [id_token_signing_alg_values_supported] JWS algorithms for ID Token signing
 */
export interface WalletMetadata {
  authorization_endpoint: string;
  vp_formats_supported: ClaimFormatMap;
  response_types_supported?: Array<string>;
  client_id_prefixes_supported?: Array<string>;
  request_object_signing_alg_values_supported?: Array<string>;
  scopes_supported?: Array<string>;
  subject_syntax_types_supported?: Array<string>;
  id_token_types_supported?: Array<string>;
  id_token_signing_alg_values_supported?: Array<string>;

  [key: string]: unknown;
}