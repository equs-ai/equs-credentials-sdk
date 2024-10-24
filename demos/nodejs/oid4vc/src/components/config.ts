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

  readonly claims = {
    given_name: "John",
    family_name: "Doe",
    email: "john@doe.com",
    username: "john_doe",
  };

  readonly issuerMetadata = {
    credential_issuer: this.issuerServerUrl,
    authorization_servers: [`${this.keycloakUrl}/idp/realms/pid-issuer-realm`],
    credential_endpoint: `${this.issuerServerUrl}/credential`,
    credential_configurations_supported: {
      SD_JWT_cred_1: {
        format: "vc+sd-jwt",
        scope: "SD_JWT_cred_scope",
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
        vct: "https://credentials.example.com/identity_credential_1",
        credential_definition: {
          type: "SD_JWT_cred",
          claims: {
            given_name: {},
            age_over_18: {},
            street: {},
            email: {},
            username: {},
            postal_code: {},
            locality: {},
            region: {},
            birthdate: {},
            gender: {},
            country: {},
            family_name: {},
          },
        },
      },
      SD_JWT_cred_2: {
        format: "vc+sd-jwt",
        scope: "SD_JWT_cred_scope",
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
        vct: "https://credentials.example.com/identity_credential_2",
        credential_definition: {
          type: "SD_JWT_cred",
          claims: {
            given_name: {},
            family_name: {},
            email: {},
            username: {},
          },
        },
      },
    },
  };

  readonly presentationDefinition = {
    id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
    input_descriptors: [
      {
        id: "Identity-1",
        name: "Identity VC",
        purpose: "We want an identity",
        format: {
          "vc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256", "ES384"],
            "kb-jwt_alg_values": ["ES256", "ES384"],
          },
        },
        constraints: {
          fields: [
            {
              path: ["$.vct"],
              filter: {
                type: "string",
                const: "https://credentials.example.com/identity_credential_1",
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
          "vc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256", "ES384"],
            "kb-jwt_alg_values": ["ES256", "ES384"],
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
                const: "https://credentials.example.com/identity_credential_2",
              },
            },
          ],
        },
      },
    ],
  };
}

export const config = new Config();
