import {Alg} from "../crypto";

/**
 * Formats for Verifiable Credentials
 */
export enum VCFormat {
  JwtVcJson = "JwtVcJson",
  JwtVcJsonLD = "JwtVcJsonLD",
  LdpVc = "LdpVc",
  SdJwtVc = "SdJwtVc",
  MsoMdoc = "MsoMdoc",
}

/**
 * Verifiable Credential
 *
 * Fields:
 * - `format`: Verifiable Credentials format
 * - `payload`: the serialized credential data (e.g., a SD-JWT or JSON-LD document)
 */
export interface Credential {
  format: VCFormat,
  payload: string,
}

/**
 * An interface for stored `Credential` in `Vault` with some extra information.
 *
 * Fields:
 * - `credential`: Verifiable Credential
 * - `kid`: The ID of the cryptographic key
 * - `id`: Credential ID
 */
export interface CredentialEntry {
  credential: Credential,
  kid: string,
  id: string,
}

/**
 * Credential Metadata.
 *
 * Fields:
 * - `type`: The type of the Verifiable Credential.
 * - `format`: The format of the Verifiable Credential.
 * - `kid`: The key identifier, representing the ID of the cryptographic key used to sign or verify the credential.
 * - `alg`: The signing algorithm used.
 * - `fields`: The fields contained in the credential.
 */
export interface CredentialMetadata {
  type: string
  format: VCFormat
  kid: string
  alg?: Alg
  fields: Array<string>
}