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
  FixtureKey,
  fixtureDidKey,
  fixtureDidKeyUrl,
  fixtureJws,
  fixturePublicJwk,
  fixtureSdJwt,
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
  credential_metadata: {
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
  },
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
  credential_metadata: {
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
  },
};

export const PROOF_JWT = fixtureJws(
  JSON.stringify({ alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Holder), typ: "openid4vci-proof+jwt" }),
  JSON.stringify({
    aud: IssuerEndpoint,
    nbf: 1736182397,
    iat: 1736182397,
    exp: 4889782397,
    nonce: "KB50VOm9I-kPLT9mAACV8g",
  }),
  FixtureKey.Holder,
);

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
  },
};

export const CRED_OFFER: OID4VCICredentialOffer = {
  credential_issuer: IssuerEndpoint,
  credential_configuration_ids: [CredDefId1],
  grants: GRANTS,
};

export const ACCESS_TOKEN = fixtureJws(
  JSON.stringify({ alg: "RS256", typ: "JWT", kid: JSON.parse(fixturePublicJwk(FixtureKey.Authz)).kid }),
  JSON.stringify({
    exp: 1724398494,
    iat: 1724398194,
    auth_time: 1724398182,
    jti: "0b4fe390-4921-4042-b7e1-b03b3d196229",
    iss: "http://localhost:8080/idp/realms/pid-issuer-realm",
    sub: "60b8ba5f-c73f-4976-b0da-48d0e53335de",
    typ: "Bearer",
    azp: "wallet-dev",
    sid: "f15b3e11-ff28-44df-8fcf-a77d24714a23",
    "allowed-origins": ["/*"],
    scope: "SD_JWT_cred",
  }),
  FixtureKey.Authz,
);

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

export const SD_JWT_CREDS = fixtureSdJwt(
  JSON.stringify({ typ: "vc+sd-jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
  JSON.stringify({
    vct: "SD_JWT_cred",
    sub: fixtureDidKey(FixtureKey.Holder),
    nbf: 1725533254,
    _sd_alg: "sha-256",
    iss: fixtureDidKey(FixtureKey.Issuer),
    iat: 1725533254,
    exp: 1757069254,
    cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
  }),
  [
    '["o0TxtL8AhuLRWRgnH984_Q", "given_name", "John"]',
    '["vIS3esPLyQPtQgBLgOFaag", "family_name", "Doe"]',
    '["lio5qsUdvI_uwyGbFamNqQ", "dob", "09/09/1989"]',
  ],
  FixtureKey.Issuer,
);

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
  /** The nonces of each `invalidate` call, in call order. */
  readonly invalidated: Array<Array<string>> = [];

  constructor(private readonly nonce: string) {
    this.generate = this.generate.bind(this);
    this.validate = this.validate.bind(this);
    this.invalidate = this.invalidate.bind(this);
  }

  async generate(): Promise<string> {
    return this.nonce;
  }

  async validate(nonce: string): Promise<boolean> {
    return true;
  }

  async invalidate(nonces: Array<string>): Promise<void> {
    this.invalidated.push(nonces);
  }
}
