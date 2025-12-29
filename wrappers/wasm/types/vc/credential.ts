import { Alg } from "../crypto";

/**
 * Formats for Verifiable Credentials.
 */
export enum VCFormat {
  JwtVcJson = "JwtVcJson",
  JwtVcJsonLD = "JwtVcJsonLD",
  LdpVc = "LdpVc",
  SdJwtVc = "SdJwtVc",
  MsoMdoc = "MsoMdoc",
}

/**
 * Verifiable Credential.
 *
 * @property {VCFormat} format - Verifiable Credentials format.
 * @property {string} payload - the serialized credential data (e.g., a SD-JWT or JSON-LD document).
 */
export interface Credential {
  format: VCFormat;
  payload: string;
}

/**
 * An interface for stored `Credential` in `Vault` with some extra information.
 *
 * @property {Credential} credential - Verifiable Credential.
 * @property {string} kid - The ID of the cryptographic key.
 * @property {string} id - Credential ID.
 */
export interface CredentialEntry {
  credential: Credential;
  kid: string;
  id: string;
}

export enum FindVCsFailReasonType {
  Paths = "Paths",
  TypeMismatch = "TypeMismatch",
  CredentialsNotFound = "CredentialsNotFound",
}

export interface FindVCsFailReason {
  type: FindVCsFailReasonType;
  paths?: Array<string> | null;
}

/**
 * Credential Metadata.
 *
 * @property {string} type - The type of the Verifiable Credential.
 * @property {VCFormat} format - The format of the Verifiable Credential.
 * @property {string} kid - The key identifier, representing the ID of the cryptographic key used to sign or verify the credential.
 * @property {Alg} alg - The signing algorithm used.
 * @property {Array<string>} fields - TThe fields contained in the credential.
 */
export interface CredentialMetadata {
  type: string;
  format: VCFormat;
  kid: string;
  alg?: Alg;
  fields: Array<string>;
}

export const enum TslVcStatusType {
  VALID = 'VALID',
  INVALID = 'INVALID',
  SUSPENDED = 'SUSPENDED',
  APPSPECIFIC = 'APPSPECIFIC'
}

export const enum VCStatusFormat {
  StatusListToken = 'StatusListToken'
}

/**
 * Represents the status of a Verifiable Credential.
 * 
 * @property {VCStatusFormat} format - The format of the status (e.g., StatusListToken).
 * @property {VcTslStatusPayload | any} payload - The status payload data, which can be either a VcTslStatusPayload or any other format.
 */
export interface VCStatus {
  format: VCStatusFormat
  payload: VcTslStatusPayload | any
}

/**
 * Represents the Token Status List status payload for a Verifiable Credential.
 * 
 * @property {TslVcStatusType} status - The status type of the credential (VALID, INVALID, SUSPENDED, or APPSPECIFIC).
 * @property {number} [value] - Optional numerical value associated with the status.
 */
export interface VcTslStatusPayload {
  status: TslVcStatusType
  value?: number
}