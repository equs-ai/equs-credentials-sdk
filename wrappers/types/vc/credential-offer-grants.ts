export interface AuthorizationCodeGrant {
  issuer_state?: string;
  authorization_server?: string;
}

export interface TransactionCode {
  length?: number;
  input_mode?: string;
  description?: string;
}

export interface PreAuthorizationCodeGrant {
  "pre-authorized_code": string;
  tx_code?: TransactionCode;
  interval?: number;
  authorization_server?: string;
}

export interface CredentialOfferGrants {
  authorization_code?: AuthorizationCodeGrant;
  "urn:ietf:params:oauth:grant-type:pre-authorized_code"?: PreAuthorizationCodeGrant;
}
