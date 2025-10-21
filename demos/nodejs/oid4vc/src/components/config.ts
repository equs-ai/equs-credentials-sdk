import {
  Claims,
  CredentialFormats,
  JwkAlgorithm,
  OID4VCIIssuerMetadata,
  PresentationQuery,
  TransactionDataItem,
} from "@equstng/agent-sdk";
export class Config {
  readonly servers = {
    issuer: {
      host: "localhost",
      port: 35001,
    },
    verifier: {
      host: "localhost",
      port: 35003,
    },
  };

  readonly clientId = "wallet-dev";

  readonly issuerServerUrl = `http://${this.servers.issuer.host}:${this.servers.issuer.port}`;

  readonly keycloakUrl = "http://localhost:8080";

  readonly claims: Claims = {
    given_name: "John",
    family_name: "Doe",
    email: "john@doe.com",
    username: "john_doe",
  };

  readonly issuerMetadata: OID4VCIIssuerMetadata = {
    credential_issuer: this.issuerServerUrl,
    authorization_servers: [`${this.keycloakUrl}/idp/realms/pid-issuer-realm`],
    credential_endpoint: `${this.issuerServerUrl}/credential`,
    nonce_endpoint: `${this.issuerServerUrl}/nonce`,
    credential_configurations_supported: {
      SD_JWT_cred_1: {
        format: CredentialFormats.VCSDJWT,
        scope: "SD_JWT_cred_scope",
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: [JwkAlgorithm.ES256],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
        vct: "https://credentials.example.com/identity_credential_1",
        credential_metadata: {
          claims: [
            { path: ["given_name"] },
            { path: ["age_over_18"] },
            { path: ["street"] },
            { path: ["email"] },
            { path: ["username"] },
            { path: ["postal_code"] },
            { path: ["locality"] },
            { path: ["region"] },
            { path: ["birthdate"] },
            { path: ["gender"] },
            { path: ["country"] },
            { path: ["family_name"] },
          ],
        },
      },
      SD_JWT_cred_2: {
        format: CredentialFormats.VCSDJWT,
        scope: "SD_JWT_cred_scope",
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: [JwkAlgorithm.ES256],

        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
        vct: "https://credentials.example.com/identity_credential_2",
        credential_metadata: {
          claims: [
            { path: ["given_name"] },
            { path: ["family_name"] },
            { path: ["email"] },
            { path: ["username"] },
          ],
        },
      },
    },
  };

  readonly resolvedPresentationQuery: PresentationQuery = {
    presentation_definition: {
      id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
      input_descriptors: [
        {
          id: "Identity-1",
          name: "Identity VC",
          purpose: "We want an identity",
          format: {
            "dc+sd-jwt": {
              "sd-jwt_alg_values": ["ES256", "EdDSA"],
              "kb-jwt_alg_values": ["ES256", "EdDSA"],
            },
          },
          constraints: {
            fields: [
              {
                path: ["$.vct"],
                filter: {
                  type: "string",
                  const:
                    "https://credentials.example.com/identity_credential_1",
                },
              },
              {
                path: ["$.given_name", "$.family_name"],
              },
            ],
          },
        },
        {
          id: "Identity-2",
          name: "Identity VC",
          purpose: "We want an identity",
          format: {
            "dc+sd-jwt": {
              "sd-jwt_alg_values": ["ES256", "EdDSA"],
              "kb-jwt_alg_values": ["ES256", "EdDSA"],
            },
          },
          constraints: {
            fields: [
              {
                path: ["$.email", "$.username"],
              },
              {
                path: ["$.vct"],
                filter: {
                  type: "string",
                  const:
                    "https://credentials.example.com/identity_credential_2",
                },
              },
            ],
          },
        },
      ],
    },
  };
}

export const config = new Config();

export const transactionData: Array<TransactionDataItem> = [
  {
    type: "type1",
    credential_ids: ["Identity-1"],
    transaction_data_hashes_alg: ["sha-256", "sha-512"],
  },
  {
    type: "type2",
    credential_ids: ["Identity-2"],
    transaction_data_hashes_alg: ["sha-512"],
  },
];
