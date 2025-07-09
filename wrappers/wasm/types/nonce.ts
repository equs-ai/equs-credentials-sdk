/**
 * `NonceHandler`
 *
 * @property generate - {@link NonceHandler.generate}
 * @method validate - {@link NonceHandler.validate}
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
}
