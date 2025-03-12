export enum Alg {
  ES256 = "ES256",
  ES256K = "ES256K",
  EdDSA = "EdDSA",
  BBS = "BBS",
}

export enum KeyType {
  Ed25519 = "Ed25519",
  P256 = "P256",
  K256 = "K256",
  Bls12381 = "Bls12381",
}

/**
 * `Nonce data`
 *
 * @property {string} value - The nonce value.
 * @property {number} [expires_in] - The expiration time in seconds.
 * @property {number} created - The nonce created time in seconds.
 */
export interface NonceData {
  value: string;
  expires_in?: number;
  created: number;
}

/**
 * `KeyMetadata`
 *
 * @property {string} did_url - The DID URL associated with the key.
 * @property {string} kid - The key identifier.
 */
export interface KeyMetadata {
  did_url: string;
  kid: string;
}
