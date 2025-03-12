import { CredentialEntry } from "./credential";
import { KeyMetadata } from "../crypto";
// @ts-ignore
import { ClientMetadata, PresentationDefinition } from "../../dist";

/**
 * A `OID4VP` authorization request.
 *
 * @property {string} `client_id` - Verifier's identifier.
 * @property {PresentationDefinition} `presentation_definition` - Rules for the required Verifiable Presentation(s).
 * @property {ClientMetadata} `client_metadata` - Metadata information about the client.
 * @property {string} `nonce` - Unique value to prevent replay attacks.
 * @property {string} `response_mode` - Method for returning the authorization response.
 * @property {string} `response_uri` - URI to send the response.
 * @property {string} `state` - A value to keep state between the auth request and the response.
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
 * @property {Record<string, Array<string>>} `claims_to_exclude` - A map of claims divided by input descriptors that need to be excluded.
 * @property {IdTokenMetadata} `id_token_metadata` - The metadata containing the signing key and lifetime for the SIOPv2 ID token
 */
export interface AuthorizationResponseMetadata {
  claims_to_exclude?: Record<string, Array<string>>;
  id_token_metadata?: IdTokenMetadata;
}

/**
 * Metadata for an ID Token.
 *
 * @property {KeyMetadata} `key_metadata` - The metadata for the key used to sign the SIOPv2 ID token.
 * @property {number} `lifetime` - The lifetime of the ID token.
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
