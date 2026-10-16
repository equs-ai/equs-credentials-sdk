import {
  Claims,
  CredentialFormats,
  CredentialOfferGrants,
  JwkAlgorithm,
  OID4VCICredentialMetadata,
  OID4VCICredentialOffer,
  OID4VCIIssuerMetadata,
  OID4VCICredentialRequest,
  FixtureKey,
  fixtureDidKey,
  fixtureDidKeyUrl,
  fixtureJws,
  fixturePublicJwk,
  fixtureSdJwt,
} from "equs-credentials-sdk";

const PROOF_JWT = fixtureJws(
  JSON.stringify({ alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Holder), typ: "openid4vci-proof+jwt" }),
  JSON.stringify({
    aud: "http://localhost:9000",
    nbf: 1736182397,
    iat: 1736182397,
    exp: 4889782397,
    nonce: "KB50VOm9I-kPLT9mAACV8g",
  }),
  FixtureKey.Holder,
);

const ACCESS_TOKEN = fixtureJws(
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

const SD_JWT_CREDS = fixtureSdJwt(
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

export class Utils {
  readonly proofJWT = PROOF_JWT;

  readonly accessToken = ACCESS_TOKEN;

  readonly sdJWTCreds = SD_JWT_CREDS;

  readonly issuerEndpoint: string;
  readonly issuerEndpointPort: number;
  readonly authServerEndpoint: string;

  constructor(params: { issuerUrlPort: number }) {
    this.issuerEndpointPort = params.issuerUrlPort;
    this.issuerEndpoint = `http://localhost:${this.issuerEndpointPort}`;
    this.authServerEndpoint = `${this.issuerEndpoint}/auth`;
  }

  get tokenEndpoint(): string {
    return `${this.authServerEndpoint}/token`;
  }

  get pushedAuthRequestEndpoint(): string {
    return `${this.authServerEndpoint}/par/request`;
  }

  get credDefId(): string {
    return "IDENTITY_SD_JWT";
  }

  get credType(): string {
    return "SD_JWT_cred";
  }

  get scope(): string {
    return "SD_JWT_cred";
  }

  get issuerMetadata(): OID4VCIIssuerMetadata {
    return {
      credential_issuer: this.issuerEndpoint,
      authorization_servers: [this.authServerEndpoint],
      credential_endpoint: `${this.issuerEndpoint}/credential`,
      deferred_credential_endpoint: `${this.issuerEndpoint}/deferred_credential`,
      notification_endpoint: `${this.issuerEndpoint}/notification`,
      nonce_endpoint: `${this.issuerEndpoint}/nonce`,
      batch_credential_issuance: {
        batch_size: 2
      },
      credential_configurations_supported: {
        IDENTITY_SD_JWT: {
          format: CredentialFormats.VCSDJWT,
          scope: this.scope,
          cryptographic_binding_methods_supported: ["jwk"],
          credential_signing_alg_values_supported: [JwkAlgorithm.ES256],
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ["ES256"],
            },
          },
          vct: this.credType,
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
        },
      },
    };
  }

  get authServerMetadata() {
    return {
      issuer: this.authServerEndpoint,
      authorization_endpoint: this.authServerEndpoint,
      token_endpoint: this.tokenEndpoint,
      introspection_endpoint: `${this.authServerEndpoint}/introspection`,
      jwks_uri: `${this.authServerEndpoint}/jwks`,
      grant_types_supported: ["authorization_code"],
      response_types_supported: ["code", "token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      pushed_authorization_request_endpoint: this.pushedAuthRequestEndpoint,
    };
  }

  get credDefMetadata(): OID4VCICredentialMetadata {
    return {
      scope: this.scope,
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
            mandatory: true,
            display: [{ name: "Name" }],
          },
          {
            path: ["dob"],
            mandatory: true,
            display: [{ name: "Date of birth" }],
          },
          {
            path: ["family_name"],
            mandatory: true,
            display: [{ name: "Surname" }],
          },
        ],
      }
    };
  }

  get credRequest(): OID4VCICredentialRequest {
    return {
      vct: "SD_JWT_cred",
      proofs: {
        jwt: [this.proofJWT],
      },
      credential_response_encryption: null,
    };
  }

  get grants(): CredentialOfferGrants {
    return {
      authorization_code: {
        issuer_state: undefined,
        authorization_server: undefined,
      },
    };
  }

  get credOffer(): OID4VCICredentialOffer {
    return {
      credential_issuer: this.issuerEndpoint,
      credential_configuration_ids: [this.credDefId],
      grants: this.grants,
    };
  }

  get codeResponse() {
    return {
      request_uri: "urn:ietf:params:oauth:request_uri:code",
      expires_in: 86400,
    };
  }

  get accessTokenResponse() {
    return {
      access_token: this.accessToken,
      token_type: "bearer",
      expires_in: 86400,
    };
  }

  get claims(): Claims {
    return {
      vct: "SD_JWT_cred",
      given_name: "John",
      family_name: "Doe",
      dob: "09/09/1989",
    };
  }

  get credResponse() {
    return {
      credentials: [
        {
          format: "dc+sd-jwt",
          credential: this.sdJWTCreds,
        }
      ],
      notification_id: "1111",
    };
  }

  get deferredCredResponse() {
    return {
      transaction_id: "8xLOxBtZp8",
      interval: 300,
    }
  }

  get batchCredResponse() {
    return {
      credentials: [
        {
          format: "dc+sd-jwt",
          credential: this.sdJWTCreds,
        },
        {
          format: "dc+sd-jwt",
          credential: this.sdJWTCreds,
        }
      ],
      notification_id: "1111",
    };
  }

  get nonceResponse() {
    return {
      c_nonce: "KB50VOm9I-kPLT9mAACV8g",
    };
  }

  get credOfferWithPreAuthGrant(): OID4VCICredentialOffer {
    return {
      credential_issuer: this.issuerEndpoint,
      credential_configuration_ids: [this.credDefId],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": "code",
          authorization_server: `${this.issuerEndpoint}/auth`,
        },
      },
      additional_field: "additional_value",
    };
  }

  get credOfferWithAuthGrant(): OID4VCICredentialOffer {
    return {
      credential_issuer: this.issuerEndpoint,
      credential_configuration_ids: [this.credDefId],
      grants: {
        authorization_code: {
          issuer_state: "state",
        },
      },
    };
  }
}
