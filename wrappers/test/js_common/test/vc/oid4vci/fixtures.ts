import {
  Claims,
  CredentialFormats,
  CredentialOfferGrants,
  JwkAlgorithm,
  OID4VCICredentialMetadata,
  OID4VCICredentialOffer,
  OID4VCIIssuerMetadata,
  OID4VCICredentialRequest,
} from "equs-credentials-sdk";
import { jwtDecode } from "jwt-decode";
import { token } from "../../bundle";

export class Utils {
  readonly proofJWT = token("proofJwt");

  readonly accessToken = token("accessToken");

  readonly sdJWTCreds = token("sdJwtCreds");

  /**
   * The `did:key#fragment` verification method URL for `sdJWTCreds`'s own
   * `sub` — random per bundle regeneration, so nothing can hardcode it.
   */
  get sdJWTCredsSubjectDidUrl(): string {
    const { sub } = jwtDecode(this.sdJWTCreds) as { sub: string };
    return `${sub}#${sub.replace(/^did:key:/, "")}`;
  }

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
