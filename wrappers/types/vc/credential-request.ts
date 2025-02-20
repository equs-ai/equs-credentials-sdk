import { JwkAlgorithm } from "./common";

export type CredentialRequestProof = { proof_type: "jwt"; jwt: string } | { proof_type: "cwt"; cwt: string };

export interface JWK {
  use?: string;
  key_ops?: Array<string>;
  alg?: JwkAlgorithm;
  kid?: string;
  x5u?: string;
  x5c?: string[];
  x5t?: Uint8Array;
  "x5t#S256"?: Uint8Array;

  [key: string]: unknown;
}

export interface CredentialResponseEncryption {
  jwk?: JWK;
  alg?: string;
  enc?: string;
}

export type SDJWTRequest = {
  format: "dc+sd-jwt";
  vct: string;
};

export interface OID4VCICredentialRequest {
  credential_identifier?: string;
  proof?: CredentialRequestProof;
  credential_response_encryption?: CredentialResponseEncryption;

  [key: string]: SDJWTRequest | unknown;
}
