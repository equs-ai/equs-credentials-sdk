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
