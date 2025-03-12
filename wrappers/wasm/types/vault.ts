import { Credential, CredentialEntry, CredentialMetadata } from "./vc";

/**
 * `Vault`
 *
 * An async Vault interface for managing Verifiable Credentials.
 * This interface supports operations to `store`, `retrieve`, `delete`, and `search` for credentials.
 *
 * @method storeCredential - Stores a Credential with its metadata.
 * @method deleteCredential - Deletes a CredentialEntry by its ID.
 * @method getCredential - Retrieves a CredentialEntry by its ID.
 * @method getCredentials - Lists all CredentialEntries.
 * @method findCredentials - Searches for CredentialEntries based on given criteria.
 */
export interface Vault {
  /**
   * Stores a Credential with its metadata.
   *
   * @param {Credential} credential - The Credential to be stored.
   * @param {CredentialMetadata} metadata - The metadata associated with the Credential.
   *
   * @returns {Promise<string>} - The ID of the stored Credential.
   */
  storeCredential(credential: Credential, metadata: CredentialMetadata): Promise<string>;

  /**
   * Deletes a CredentialEntry by its ID.
   *
   * @param {string} id - The unique ID of the CredentialEntry to delete.
   *
   * @returns {Promise<void>}
   */
  deleteCredential(id: string): Promise<void>;

  /**
   * Retrieves a CredentialEntry by its ID.
   *
   * @param {string} id - The unique ID of the CredentialEntry to retrieve.
   * @returns {Promise<CredentialEntry | undefined>} - The CredentialEntry, or undefined if no entry is found.
   */
  getCredential(id: string): Promise<CredentialEntry | undefined>;

  /**
   * Lists all CredentialEntries.
   *
   * @returns {Promise<Array<CredentialEntry>>} - An array of CredentialEntries.
   * The array will be empty if no entries exist.
   */
  getCredentials(): Promise<Array<CredentialEntry>>;

  /**
   * Searches for CredentialEntries based on given criteria.
   *
   * @param {Array<string>} criteria - An array of fields or keywords to search for credentials.
   *
   * @returns {Promise<Array<CredentialEntry>>} - An array of matching CredentialEntries.
   * The array will be empty if no entries meet the criteria.
   */
  findCredentials(criteria: Array<string>): Promise<Array<CredentialEntry>>;
}