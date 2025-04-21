import {
  Claims,
  CredentialFormats,
  CredentialOfferGrants,
  JwkAlgorithm,
  OID4VCICredentialMetadata,
  OID4VCICredentialOffer,
  OID4VCIIssuerMetadata,
  OID4VCICredentialRequest,
} from "agent-sdk";

export class Utils {
  readonly proofJWT =
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVmM2lLZTFGV3U4QUtOM25yUEpCdWtTenNTNE5KNm95b0xiVjh1QkNTR2ZjZiN6RG5hZWYzaUtlMUZXdThBS04zbnJQSkJ1a1N6c1M0Tko2b3lvTGJWOHVCQ1NHZmNmIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QifQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJuYmYiOjE3MzYxODIzOTcsImlhdCI6MTczNjE4MjM5NywiZXhwIjo0ODg5NzgyMzk3LCJub25jZSI6IktCNTBWT205SS1rUExUOW1BQUNWOGcifQ.IteWgE_LbL7lanDu3CJDdwGheGRDrJdh_gn-ldOraEWazE_kTtcgXMp4WJG871FOqRzI8lphSxWfqrGBXG4wxA";

  readonly accessToken =
    "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA";

  readonly sdJWTCreds =
    "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~";

  readonly issuerEndpoint: string;
  readonly issuerEndpointPort: number;

  constructor(params: { issuerUrlPort: number }) {
    this.issuerEndpointPort = params.issuerUrlPort;
    this.issuerEndpoint = `http://localhost:${this.issuerEndpointPort}`;
  }

  get tokenEndpoint(): string {
    return `${this.issuerEndpoint}/auth/token`;
  }

  get pushedAuthRequestEndpoint(): string {
    return `${this.issuerEndpoint}/auth/par/request`;
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
      authorization_servers: [`${this.issuerEndpoint}/auth`],
      credential_endpoint: `${this.issuerEndpoint}/credential`,
      nonce_endpoint: `${this.issuerEndpoint}/nonce`,
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
          claims: {
            given_name: {
              display: [{ name: "Name" }],
              mandatory: true,
              value_type: "string",
            },
            family_name: {
              display: [{ name: "Surname" }],
              mandatory: true,
              value_type: "string",
            },
            dob: {
              display: [{ name: "Date of birth" }],
              mandatory: true,
              value_type: "number",
            },
          },
        },
      },
    };
  }

  get authServerMetadata() {
    return {
      issuer: `${this.issuerEndpoint}/auth`,
      authorization_endpoint: `${this.issuerEndpoint}/auth`,
      token_endpoint: this.tokenEndpoint,
      introspection_endpoint: `${this.issuerEndpoint}/auth/introspection`,
      jwks_uri: `${this.issuerEndpoint}/auth/jwks`,
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
      claims: {
        given_name: {
          mandatory: true,
          value_type: "string",
          display: [{ name: "Name" }],
        },
        dob: {
          mandatory: true,
          value_type: "number",
          display: [{ name: "Date of birth" }],
        },
        family_name: {
          mandatory: true,
          value_type: "string",
          display: [{ name: "Surname" }],
        },
      },
    };
  }

  get credRequest(): OID4VCICredentialRequest {
    return {
      format: "dc+sd-jwt",
      vct: "SD_JWT_cred",
      proof: {
        proof_type: "jwt",
        jwt: this.proofJWT,
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
      format: "dc+sd-jwt",
      credential: this.sdJWTCreds,
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
          tx_code: null,
          interval: null,
          authorization_server: `${this.issuerEndpoint}/auth`,
        },
      },
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
