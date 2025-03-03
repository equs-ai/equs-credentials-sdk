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

export interface NonceData {
  value: string
  expires_in?: number
  created: number
}

export interface KeyMetadata {
  did_url: string
  kid: string
}