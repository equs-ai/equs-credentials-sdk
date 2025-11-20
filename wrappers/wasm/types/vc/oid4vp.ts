import { CredentialEntry, FindVCsFailReason } from "./credential";
import { KeyMetadata } from "../crypto";
//@ts-ignore
import { PresentationSubmission } from "../../";

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

export type CredentialsFindResult = { data: CredentialEntry[] | FindVCsFailReason };

/**
 * A mapping an input descriptor ID to a single credential entry.
 */
export type CredentialMapping = Record<string, Array<CredentialEntry>>;
/**
 * A mapping an input descriptor ID to an array of credential entries.
 */
export type CredentialsMapping = Record<string, CredentialsFindResult>;

/**
 * The result of the presentation/authorization request.
 * Can be either an authorization response, a redirect URI, or a presented.
 */
export type PresentationResult = AuthorizationResponse | RedirectUri | Presented;

/**
 * An authorization/presentation response that can be either plain or JWE-encrypted.
 */
export type AuthorizationResponse = AuthorizationResponsePlain | AuthorizationResponseJwe;

/**
 * A JWE-encrypted authorization/presentation response.
 * @property {AuthorizationResponseType.Jwe} type - The type indicating JWE encryption.
 * @property {string} jwe - The JWE-encrypted authorization response string.
 */
export type AuthorizationResponseJwe = { type: AuthorizationResponseType.Jwe; jwe: string };

/**
 * A plain authorization/presentation response.
 * @property {AuthorizationResponseType.Plain} type - The type indicating plain format.
 * @property {AuthorizationResponseObject} value - The authorization response object.
 */
export type AuthorizationResponsePlain = { type: AuthorizationResponseType.Plain; value: AuthorizationResponseObject };

/**
 * Enum defining the possible types of presentation results.
 * @enum {string}
 */
export const enum PresentationResultType {
  /** Indicates an authorization response result */
  AuthorizationResponse = "AuthorizationResponse",
  /** Indicates a redirect URI result */
  RedirectUri = "RedirectUri",
  /** Indicates a presented status result */
  Presented = "Presented",
}

/**
 * A presentation result containing a redirect URI.
 * @property {PresentationResultType.RedirectUri} type - The type indicating a redirect URI.
 * @property {string} value - The redirect URI string.
 */
type RedirectUri = {
  type: PresentationResultType.RedirectUri;
  value: string;
};

/**
 * A presentation result indicating the presentation has been completed.
 * @property {PresentationResultType.Presented} type - The type indicating presented status.
 */
type Presented = {
  type: PresentationResultType.Presented;
};

/**
 * Enum defining the possible types of authorization responses.
 * @enum {string}
 */
export const enum AuthorizationResponseType {
  /** Indicates a plain authorization response */
  Plain = "Plain",
  /** Indicates a JWE-encrypted authorization response */
  Jwe = "Jwe",
}

/**
 * An OID4VP authorization response object.
 *
 * @property {any} vpToken - VP Token containing the Verifiable Presentation(s).
 * @property {string | null} [idToken] - The OpenID Connect ID token used in the SIOP flow.
 * @property {PresentationSubmission} presentationSubmission - Details of the submitted presentation.
 * @property {string | null} [state] - The state may be used by a verifier to link requests and responses.
 */
export interface AuthorizationResponseObject {
  vpToken: any;
  idToken?: string;
  presentationSubmission?: PresentationSubmission;
  state?: string;
  transactionDataResponse?: TransactionDataResponse;
}

export interface TransactionDataResponse {
  hashes: Array<string>;
  alg?: string;
}
