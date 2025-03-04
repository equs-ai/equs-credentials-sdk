import { CredentialEntry } from "./credential";
import { KeyMetadata } from "../crypto";
// @ts-ignore
import { ClientMetadata, PresentationDefinition } from "../../dist";

/**
 * A `OID4VP` authorization request.
 *
 * `client_id` Verifier's identifier.
 * `presentation_definition` Rules for the required Verifiable Presentation(s).
 * `nonce` Unique value to prevent replay attacks.
 * `response_mode` Method for returning the authorization response.
 * `response_uri` URI to send the response.
 */
export interface AuthorizationRequest {
  client_id: string;
  presentation_definition: PresentationDefinition;
  client_metadata: ClientMetadata;
  nonce: string;
  response_type: string;
  response_mode: string;
  response_uri: string;
  state?: string;
}

/**
 * Metadata for an Authorization Response.
 *
 * # Fields
 *
 * - `claims_to_exclude` - map of claims divided by input descriptors that need to be excluded.
 * - `id_token_metadata`: metadata containing the signing key and lifetime for the SIOP ID token
 */
export interface AuthorizationResponseMetadata {
  claims_to_exclude?: Record<string, Array<string>>;
  id_token_metadata?: IdTokenMetadata;
}

/**
 * Metadata for an ID Token.
 *
 * - `id_token_key`: metadata for the key used to sign the SIOP ID token.
 * - `lifetime`: lifetime of the ID token.
 */
export interface IdTokenMetadata {
  key_metadata: KeyMetadata;
  lifetime: number;
}

/**
 * A mapping an input descriptor ID to a single credential entry.
 */
export type CredentialMapping = Record<string, CredentialEntry>;
/**
 * A mapping an input descriptor ID to an array of credential entries.
 */
export type CredentialsMapping = Record<string, Array<CredentialEntry>>;
