import { ClaimFormatMap } from "./common";

interface JWKs {
  keys: Array<Record<string, any>>;
}

export interface ClientMetadata {
  jwks?: JWKs;
  vp_formats: ClaimFormatMap;
  authorization_signed_response_alg?: string;
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;

  [key: string]: unknown;
}
