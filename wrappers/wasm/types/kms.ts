import { Alg, KeyType } from "./crypto";

/**
 * `KeyHandle`
 *
 * Represents a cryptographic key handle with properties for different key representations
 * and methods to perform signing and verification.
 *
 * @property pubKey - {@link KeyHandle.pubKey}
 * @property jwk - {@link KeyHandle.jwk}
 * @property alg - {@link KeyHandle.alg}
 * @property sign - {@link KeyHandle.sign}
 * @property verify - {@link KeyHandle.verify}
 */
export interface KeyHandle {
  /**
   * The public key in Uint8Array form.
   *
   * - Defined if the algorithm supports a public key.
   * - Undefined if the public key is not supported.
   */
  pubKey?: Uint8Array;

  /**
   * The public key in JWK form.
   *
   * - Provided as a string if the key can be represented in JWK format.
   * - Undefined if the JWK representation is not supported.
   */
  jwk?: string;

  /**
   * The signing {@link Alg}.
   */
  alg: Alg;

  /**
   * Signs a given binary payload.
   *
   * @param {Uint8Array} payload - The binary data to be signed.
   *
   * @returns {Promise<Uint8Array>} - The generated signature.
   */
  sign(payload: Uint8Array): Promise<Uint8Array>;

  /**
   * Verifies a cryptographic signature for given binary data.
   *
   * @param {Uint8Array} data - The original binary data that was signed.
   * @param {Uint8Array} signature - The cryptographic signature to verify.
   *
   * @returns {Promise<void>}
   */
  verify(data: Uint8Array, signature: Uint8Array): Promise<void>;
}

/**
 * `Kms`
 *
 * Provides key management operations, including key creation and retrieval.
 * It uses {@link KeyHandle} for cryptographic operations.
 *
 * @method create - {@link Kms.create}
 * @method get - {@link Kms.get}
 * @method getByPublicKey - {@link Kms.getByPublicKey}
 */
export interface Kms {
  /**
   * Creates and stores a key in the Kms.
   *
   * @param {KeyType} kt - The {@link KeyType} of key to create.
   *
   * @returns {Promise<string>} - The key identifier for the created key.
   */
  create(kt: KeyType): Promise<string>;

  /**
   * Retrieves a KeyHandle for the specified key identifier.
   *
   * @param {string} kid - The key identifier of the requested key.
   *
   * @returns {Promise<KeyHandle>} - A {@link KeyHandle} supporting basic cryptographic operations.
   */
  get(kid: string): Promise<KeyHandle>;

  /**
   * Retrieves a {@link KeyHandle} for the key associated with the provided public key.
   *
   * @param {Uint8Array} pk - The public key of the requested key.
   *
   * @returns {Promise<KeyHandle>} A {@link KeyHandle} supporting basic cryptographic operations.
   */
  getByPublicKey(pk: Uint8Array): Promise<KeyHandle>;
}
