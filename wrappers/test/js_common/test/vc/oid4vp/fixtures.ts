import {
  Claims,
  CommonAuthorizationRequest,
  CredentialFormats,
  PresentationDefinition,
  PresentationSubmission,
  FixtureKey,
  fixtureDidKey,
  fixtureDidKeyUrl,
  fixtureJws,
  fixturePublicJwk,
  fixtureSdJwt,
  fixtureSdJwtKb,
} from "equs-credentials-sdk";
import { Fixtures } from "../../fixtures";

export const CLIENT_ID = `decentralized_identifier:${fixtureDidKey(FixtureKey.Verifier)}`;
export const REQUEST_URI = `openid4vp://?client_id=${encodeURIComponent(CLIENT_ID)}&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest`;
export const REQUEST_URI_WITH_POST = `openid4vp://?client_id=${encodeURIComponent(CLIENT_ID)}&request_uri_method=post&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest`;
export const STATE = "1d8b0d93-86e8-4135-87d4-524bb0500bf3";

export const PRESENTATION_DEFINITION: PresentationDefinition = {
  id: "f64edc99-2b79-45ce-ad36-5e346ebfc6ec",
  input_descriptors: [
    {
      id: "Identity-1",
      constraints: {
        fields: [
          {
            path: ["$.vct"],
            filter: {
              type: "string",
              const: "https://credentials.example.com/identity_credential",
            },
            predicate: null,
            intent_to_retain: false,
          },
          {
            path: ["$.name"],
            optional: true,
            predicate: null,
            intent_to_retain: false,
          },
        ],
      },
      name: "Identity VC",
      purpose: "We want an identity",
      format: {
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "EdDSA"],
          "kb-jwt_alg_values": ["ES256", "EdDSA"],
        },
      },
    },
  ],
  name: "Example with selective disclosure",
};
export const PRESENTATION_DEFINITION_WITH_FAKE_VCT: PresentationDefinition = {
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
            predicate: null,
            filter: {
              type: "string",
              const: "https://credentials.example.com/identity_credential_1",
            },
            intent_to_retain: false,
          },
          {
            path: ["$.name"],
            intent_to_retain: false,
            predicate: null,
            optional: true,
          },
        ],
      },
    },
  ],
};
export const PRESENTATION_DEFINITION_WITH_FAKE_CONSTRAINTS: PresentationDefinition = {
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
            predicate: null,
            filter: {
              type: "string",
              const: "https://credentials.example.com/identity_credential",
            },
            intent_to_retain: false,
          },
          {
            path: ["$.first_name"],
            intent_to_retain: false,
            predicate: null,
            optional: false,
          },
          {
            path: ["$.surname", "$.last_name"],
            intent_to_retain: false,
            predicate: null,
            optional: false,
          },
        ],
      },
    },
  ],
};

export const AUTH_REQUEST: CommonAuthorizationRequest = {
  client_id: CLIENT_ID,
  client_metadata: {
    vp_formats_supported: {
      "dc+sd-jwt": {
        "sd-jwt_alg_values": ["EdDSA", "ES256"],
        "kb-jwt_alg_values": ["EdDSA", "ES256"],
      },
    },
    jwks: {
      keys: [
        {
          use: "enc",
          alg: "ES256",
          kid: "1CKT7Smhoh:P256:",
          kty: "EC",
          crv: "P-256",
          x: "YPNZ8G5d4SO8nGX5AfH8H1yog81Ag_5s7yzfd5Sv1Kw",
          y: "84OGFXGqMAtqZAQ9C6BT7EV02bUAm6OHl5d7Y30gOk0",
        },
      ],
    },
    encrypted_response_enc_values_supported: ["A128GCM", "A128CBC-HS256"],
    subject_syntax_types_supported: ["did:key"],
  },
  response_uri: "http://localhost:9001/response",
  response_mode: "direct_post",
  response_type: "vp_token",
  nonce: "EA9zzU_kQfgGUF2MiwrYuFgMgPpXUFzqsPxs-zEdoDI",
  state: STATE,
  presentation_definition: PRESENTATION_DEFINITION,
  transaction_data: [
    {
      type: "some_type",
      credential_ids: ["Identity-1"],
      transaction_data_hashes_alg: ["sha-256", "sha-512"],
    },
  ],
};

export const AUTH_REQUEST_JWT = fixtureJws(
  JSON.stringify({ alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Verifier), typ: "application/oauth-authz-req+jwt" }),
  JSON.stringify({
    response_type: "vp_token",
    state: STATE,
    transaction_data: AUTH_REQUEST.transaction_data.map((item) =>
      Buffer.from(JSON.stringify(item)).toString("base64url"),
    ),
    response_mode: "direct_post",
    nonce: AUTH_REQUEST.nonce,
    client_metadata: AUTH_REQUEST.client_metadata,
    client_id: CLIENT_ID,
    presentation_definition: PRESENTATION_DEFINITION,
    response_uri: AUTH_REQUEST.response_uri,
  }),
  FixtureKey.Verifier,
);

export const AUTH_REQUEST_WITH_DIRECT_POST_JWT: CommonAuthorizationRequest = {
  ...AUTH_REQUEST,
  client_metadata: {
    ...AUTH_REQUEST.client_metadata,
    jwks: {
      keys: [{ kid: "ecdsa-kid", ...JSON.parse(fixturePublicJwk(FixtureKey.Verifier)), alg: "ES256" }],
    },
  },
  response_mode: "direct_post.jwt",
};

export const AUTH_REQUEST_WITH_FAKE_VCT: CommonAuthorizationRequest = {
  ...AUTH_REQUEST,
  presentation_definition: PRESENTATION_DEFINITION_WITH_FAKE_VCT,
};
export const AUTH_REQUEST_WITH_FAKE_CONSTRAINTS: CommonAuthorizationRequest = {
  ...AUTH_REQUEST,
  presentation_definition: PRESENTATION_DEFINITION_WITH_FAKE_CONSTRAINTS,
};

export const PRESENTATION_SUBMISSION: PresentationSubmission = {
  id: "e18f2155-1235-43e9-8f0c-1f18cf72911a",
  definition_id: "f64edc99-2b79-45ce-ad36-5e346ebfc6ec",
  descriptor_map: [{ id: "Identity-1", format: CredentialFormats.VCSDJWT, path: "$", path_nested: null }],
};

export const VC_TYPE = "https://credentials.example.com/identity_credential";

export const VC = fixtureSdJwt(
  JSON.stringify({ typ: "dc+sd-jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
  JSON.stringify({
    vct: VC_TYPE,
    iat: 1760610964,
    sub: fixtureDidKey(FixtureKey.Holder),
    _sd_alg: "sha-256",
    iss: fixtureDidKey(FixtureKey.Issuer),
    exp: 2075970964,
    nbf: 1760610964,
    cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
  }),
  ['["O2po0l0CFhb7uIJQ6vpWNA", "name", "John"]'],
  FixtureKey.Issuer,
);
export const VC_WITH_STATUS = fixtureSdJwt(
  JSON.stringify({ typ: "dc+sd-jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
  JSON.stringify({
    address: "221B Baker Street",
    iat: 1753054448,
    date: "09/09/1989",
    sub: fixtureDidKey(FixtureKey.Holder),
    vct: VC_TYPE,
    status: { status_list: { uri: "http://localhost:9001/status_list", idx: 1 } },
    _sd_alg: "sha-256",
    iss: fixtureDidKey(FixtureKey.Issuer),
    exp: 1753055048,
    nbf: 1753054448,
    cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
  }),
  ['["uxLNTemWQkc1VO6LgsArlQ", "name", "John"]', '["2CBudCWI5EImahgzdcU1Vw", "surname", "Doe"]'],
  FixtureKey.Issuer,
);
export const STATUS_LIST_JWT = `${fixtureJws(
  JSON.stringify({ typ: "statuslist+jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
  JSON.stringify({
    status_list: { lst: "eNqbwMwABgAEnQCU", bits: 2 },
    sub: "http://localhost:9001/status_list",
    iat: 1763025623,
    _sd_alg: "sha-256",
  }),
  FixtureKey.Issuer,
)}~`;
export const VP = fixtureSdJwtKb(
  Fixtures.SDJWTVCPayload,
  JSON.stringify({ typ: "kb+jwt", alg: "ES256" }),
  JSON.stringify({ nonce: "n0NcE", aud: fixtureDidKey(FixtureKey.Verifier), iat: 1728882611 }),
  FixtureKey.Holder,
);

export const CLAIMS: Claims = {
  vp_token: {
    "Identity-1": {
      vct: VC_TYPE,
      sub: fixtureDidKey(FixtureKey.Holder),
      nbf: 1728882611,
      iss: fixtureDidKey(FixtureKey.Issuer),
      iat: 1728882611,
      exp: 1760418611,
      cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
      name: "John",
    },
  },
};
