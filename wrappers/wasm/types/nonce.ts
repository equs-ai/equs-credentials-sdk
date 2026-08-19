/**
 * `NonceHandler`
 *
 * @property generate - {@link NonceHandler.generate}
 * @method validate - {@link NonceHandler.validate}
 * @method invalidate - {@link NonceHandler.invalidate}
 */
export interface NonceHandler {
  /**
   * @returns {Promise<string>}
   */
  generate(): Promise<string>;

  /**
   * Validates a Nonce string
   *
   * @param {string} nonce - Nonce.
   *
   * @returns {Promise<boolean>}
   */
  validate(nonce: string): Promise<boolean>;

  /**
   * Spends the Nonces that a finished request carried
   *
   * @param {string[]} nonces - Nonces.
   *
   * @returns {Promise<void>}
   */
  invalidate(nonces: Array<string>): Promise<void>;
}
