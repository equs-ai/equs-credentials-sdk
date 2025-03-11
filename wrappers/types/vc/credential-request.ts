import { JwkAlgorithm } from "./common";

/**
 * Represents proof formats supported for credential requests
 *
 * @property {string} proof_type REQUIRED. The type of proof being presented.
 * @property {string} jwt JWT-based proof with compact serialization. Required when proof_type is "jwt".
 * @property {string} cwt CBOR Web Token proof. Required when proof_type is "cwt".
 */
export type CredentialRequestProof =
/** JWT-based proof format with a compact serialization */
  { proof_type: "jwt"; jwt: string } |
  /** CBOR Web Token proof format */
  { proof_type: "cwt"; cwt: string };

/**
 * JSON Web Key (JWK) as defined in {@link https://datatracker.ietf.org/doc/html/rfc7517|RFC 7517}
 *
 * @property {string} [use] Intended use of the public key (typically "sig" for signature or "enc" for encryption).
 * @property {Array<string>} [key_ops] Key operations that the key is intended to be used for.
 * @property {JwkAlgorithm} [alg] Algorithm intended for use with the key.
 * @property {string} [kid] Key ID parameter.
 * @property {string} [x5u] URL that refers to a resource for an X.509 certificate.
 * @property {string[]} [x5c] Chain of X.509 certificates.
 * @property {Uint8Array} [x5t] X.509 certificate SHA-1 thumbprint.
 * @property {Uint8Array} [x5t#S256] X.509 certificate SHA-256 thumbprint.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517|RFC 7517}
 */
export interface JWK {
  use?: string;
  key_ops?: Array<string>;
  alg?: JwkAlgorithm;
  kid?: string;
  x5u?: string;
  x5c?: string[];
  x5t?: Uint8Array;
  "x5t#S256"?: Uint8Array;

  /** Additional properties of the JWK */
  [key: string]: unknown;
}

/**
 * Configuration for encrypting the credential response
 *
 * @property {JWK} [jwk] JWK containing a public key that the Credential Issuer
 * should use to encrypt the response.
 * @property {string} [alg] JWE "alg" header parameter identifying the algorithm
 * to be used for key encryption.
 * @property {string} [enc] JWE "enc" header parameter identifying the algorithm
 * to be used for content encryption.
 */
export interface CredentialResponseEncryption {
  jwk?: JWK;
  alg?: string;
  enc?: string;
}

/**
 * Request parameters specific to Selective Disclosure JWT format
 *
 * @property {string} format REQUIRED. The format identifier for SD-JWT-based Verifiable Credentials.
 * @property {string} vct REQUIRED. Verifiable Credential Type for the SD-JWT.
 */
export type SDJWTRequest = {
  format: "dc+sd-jwt";
  vct: string;
};

/**
 * Parameters for a credential request in the OpenID4VCI protocol
 *
 * @property {string} [credential_identifier] Identifier for the credential being requested.
 * @property {CredentialRequestProof} [proof] Proof of possession used to authenticate the Wallet.
 * @property {CredentialResponseEncryption} [credential_response_encryption] Configuration
 * for encrypting the credential response.
 *
 * @see {@link https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html|OpenID for Verifiable Credential Issuance}
 */
export interface OID4VCICredentialRequest {
  credential_identifier?: string;
  proof?: CredentialRequestProof;
  credential_response_encryption?: CredentialResponseEncryption;

  [key: string]: SDJWTRequest | unknown;
}