import {CredentialEntry} from "./credential";
import {KeyMetadata} from "../crypto";
// @ts-ignore
import {ClientMetadata, PresentationDefinition} from "../../";

/**
 * Metadata for an Authorization Response.
 *
 * # Fields
 *
 * @property {Record<string, Array<string>>} claimsToExclude - A map of claims divided by input descriptors that need to be excluded.
 * @property {IdTokenMetadata} idTokenMetadata - The metadata containing the signing key and lifetime for the SIOPv2 ID token
 */
export interface AuthorizationResponseMetadata {
  claimsToExclude?: Record<string, Array<string>>;
  idTokenMetadata?: IdTokenMetadata;
}

/**
 * Metadata for an ID Token.
 *
 * @property {KeyMetadata} keyMetadata - The metadata for the key used to sign the SIOPv2 ID token.
 * @property {number} lifetime - The lifetime of the ID token.
 */
export interface IdTokenMetadata {
  keyMetadata: KeyMetadata;
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
