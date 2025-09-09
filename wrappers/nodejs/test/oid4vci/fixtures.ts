import {
  AuthMetadata,
  Claims,
  CredentialFormats,
  CredentialOfferGrants,
  JwkAlgorithm,
  NonceHandler,
  OID4VCICredentialMetadata,
  OID4VCICredentialOffer,
  OID4VCICredentialRequest,
  OID4VCIIssuerMetadata,
} from "../../";

export const IssuerEndpoint = "http://localhost:9000";
export const TokenEndpoint = `${IssuerEndpoint}/auth/token`;
export const PushedAuthRequestEndpoint = `${IssuerEndpoint}/auth/par/request`;
export const CredDefId1 = "IDENTITY_SD_JWT_1";
export const CredDefId2 = "IDENTITY_SD_JWT_2";
export const CredType = "SD_JWT_cred";
export const Scope = "SD_JWT_cred";

const CredentialDefinition = {
  format: CredentialFormats.VCSDJWT,
  scope: Scope,
  cryptographic_binding_methods_supported: ["jwk"],
  credential_signing_alg_values_supported: [JwkAlgorithm.ES256],
  proof_types_supported: {
    jwt: {
      proof_signing_alg_values_supported: ["ES256"],
    },
  },
  vct: CredType,
  claims: [
    {
      path: ["given_name"],
      display: [{ name: "Name" }],
      mandatory: true,
    },
    {
      path: ["family_name"],
      display: [{ name: "Surname" }],
      mandatory: true,
    },
    {
      path: ["dob"],
      display: [{ name: "Date of birth" }],
      mandatory: true,
    },
  ],
} satisfies OID4VCICredentialMetadata;

export const ISSUER_METADATA: OID4VCIIssuerMetadata = {
  credential_issuer: IssuerEndpoint,
  authorization_servers: [`${IssuerEndpoint}/auth`],
  credential_endpoint: `${IssuerEndpoint}/credential`,
  batch_credential_issuance: {
    batch_size: 2,
  },
  credential_configurations_supported: {
    [CredDefId1]: CredentialDefinition,
    [CredDefId2]: CredentialDefinition,
  },
};

export const AUTH_SERVER_METADATA: AuthMetadata = {
  issuer: `${IssuerEndpoint}/auth`,
  authorization_endpoint: `${IssuerEndpoint}/auth`,
  token_endpoint: TokenEndpoint,
  introspection_endpoint: `${IssuerEndpoint}/auth/introspection`,
  jwks_uri: `${IssuerEndpoint}/auth/jwks`,
  grant_types_supported: ["authorization_code"],
  response_types_supported: ["code", "token"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["ES256"],
  pushed_authorization_request_endpoint: PushedAuthRequestEndpoint,
};

export const CRED_DEF_METADATA: OID4VCICredentialMetadata = {
  scope: Scope,
  cryptographic_binding_methods_supported: ["jwk"],
  proof_types_supported: {
    jwt: {
      proof_signing_alg_values_supported: ["ES256"],
    },
  },
  format: CredentialFormats.VCSDJWT,
  credential_signing_alg_values_supported: [JwkAlgorithm.ES256],
  vct: "SD_JWT_cred",
  claims: [
    {
      path: ["given_name"],
      display: [{ name: "Name" }],
      mandatory: true,
    },
    {
      path: ["family_name"],
      display: [{ name: "Surname" }],
      mandatory: true,
    },
    {
      path: ["dob"],
      display: [{ name: "Date of birth" }],
      mandatory: true,
    },
  ],
};

export const PROOF_JWT =
  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVmM2lLZTFGV3U4QUtOM25yUEpCdWtTenNTNE5KNm95b0xiVjh1QkNTR2ZjZiN6RG5hZWYzaUtlMUZXdThBS04zbnJQSkJ1a1N6c1M0Tko2b3lvTGJWOHVCQ1NHZmNmIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QifQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJuYmYiOjE3MzYxODIzOTcsImlhdCI6MTczNjE4MjM5NywiZXhwIjo0ODg5NzgyMzk3LCJub25jZSI6IktCNTBWT205SS1rUExUOW1BQUNWOGcifQ.IteWgE_LbL7lanDu3CJDdwGheGRDrJdh_gn-ldOraEWazE_kTtcgXMp4WJG871FOqRzI8lphSxWfqrGBXG4wxA";

export const CredRequest1: OID4VCICredentialRequest = {
  credential_configuration_id: CredDefId1,
  proofs: {
    jwt: [PROOF_JWT],
  },
  credential_response_encryption: null,
};
export const CredRequest2: OID4VCICredentialRequest = {
  credential_configuration_id: CredDefId2,
  proofs: {
    jwt: [PROOF_JWT],
  },
  credential_response_encryption: null,
};

export const CRED_REQUEST_FOR_BATCH_ISSUANCE: OID4VCICredentialRequest = {
  credential_configuration_id: CredDefId1,
  proofs: {
    jwt: [PROOF_JWT, PROOF_JWT],
  },
  credential_response_encryption: null,
};

export const GRANTS: CredentialOfferGrants = {
  authorization_code: {
    issuer_state: null,
    authorization_server: null,
  },
};

export const CRED_OFFER: OID4VCICredentialOffer = {
  credential_issuer: IssuerEndpoint,
  credential_configuration_ids: [CredDefId1],
  grants: GRANTS,
};

export const ACCESS_TOKEN =
  "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA";

export const CODE_RESPONSE = {
  request_uri: "urn:ietf:params:oauth:request_uri:code",
  expires_in: 86400,
};

export const ACCESS_TOKEN_RESPONSE = {
  access_token: ACCESS_TOKEN,
  token_type: "bearer",
  expires_in: 86400,
};

export const CLAIMS: Claims = {
  vct: "SD_JWT_cred",
  given_name: "John",
  family_name: "Doe",
  dob: "09/09/1989",
};

export const SD_JWT_CREDS =
  "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~";

export const CRED_RESPONSE = {
  format: "dc+sd-jwt",
  credential: SD_JWT_CREDS,
  notification_id: "1111",
};

export const CRED_OFFER_WITH_PRE_AUTH_GRANT: OID4VCICredentialOffer = {
  credential_issuer: IssuerEndpoint,
  credential_configuration_ids: [CredDefId1],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "code",
      tx_code: null,
      interval: null,
      authorization_server: `${IssuerEndpoint}/auth`,
    },
  },
};

export const CRED_OFFER_WITH_AUTH_GRANT: OID4VCICredentialOffer = {
  credential_issuer: IssuerEndpoint,
  credential_configuration_ids: [CredDefId1],
  grants: {
    authorization_code: {
      issuer_state: "state",
    },
  },
};

export class MockNonceHandler implements NonceHandler {
  constructor(private readonly nonce: string) {
    this.generate = this.generate.bind(this);
    this.validate = this.validate.bind(this);
  }

  async generate(): Promise<string> {
    return this.nonce;
  }

  async validate(nonce: string): Promise<boolean> {
    return true;
  }
}
