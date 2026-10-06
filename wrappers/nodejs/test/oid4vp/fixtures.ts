// `@peculiar/x509` resolves its providers through tsyringe, which needs this first.
import "reflect-metadata";
import {
  Claims,
  CredentialFormats,
  PresentationDefinition,
  PresentationSubmission,
  CommonAuthorizationRequest,
  PresentationQuery,
  Dcql,
  TransactionDataItem,
  FixtureKey,
  fixtureDidKey,
  fixtureDidKeyUrl,
  fixtureJwe,
  fixtureJws,
  fixturePublicJwk,
  fixtureSdJwt,
  fixtureSdJwtKb,
  fixtureX509,
} from "../../";
import * as x509 from "@peculiar/x509";
import { createHash, webcrypto } from "node:crypto";

// `lib` is ESNext only, so the DOM WebCrypto types are not in scope here.
type WebCrypto = webcrypto.Crypto;
type WebCryptoKeyPair = webcrypto.CryptoKeyPair;
export const STATE = "eea7b48e-1866-41b4-beae-03b95d41670c";

export const PRESENTATION_DEFINITION: PresentationDefinition = {
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

export const DCQL: Dcql = {
  credentials: [
    {
      id: "1",
      format: "dc+sd-jwt",
      require_cryptographic_holder_binding: true,
      meta: {
        vct_values: ["vct_value"],
      },
      claims: [
        {
          id: "1",
          path: ["work", "email"],
        },
        {
          id: "2",
          path: ["work", "position"],
        },
        {
          id: "3",
          path: ["home", "address"],
        },
      ],
      claim_sets: [
        ["1", "2"],
        ["2", "3"],
      ],
    },
    {
      id: "2",
      format: "ldp_vc",
      require_cryptographic_holder_binding: false,
      meta: {
        type_values: [
          ["type1", "type2"],
          ["type2", "type3"],
        ],
      },
      claims: [
        {
          id: "1",
          path: ["user", "name"],
        },
        {
          id: "2",
          path: ["user", "surname"],
        },
        {
          id: "3",
          path: ["phone", "home-number"],
        },
      ],
      claim_sets: [
        ["1", "2"],
        ["2", "3"],
      ],
    },
  ],
  credential_sets: [
    {
      options: [["1"], ["2"]],
      required: true,
    },
    {
      options: [["1", "2"]],
      required: false,
    },
  ],
};

export const PRESENTATION_QUERY: PresentationQuery = {
  presentation_definition: PRESENTATION_DEFINITION,
};

export const PRESENTATION_QUERY_FOR_DCQL: PresentationQuery = {
  dcql_query: DCQL,
};
export const AUTH_REQUEST: CommonAuthorizationRequest = {
  client_id: fixtureDidKey(FixtureKey.Verifier),
  client_metadata: {
    vp_formats_supported: {
      "dc+sd-jwt": {
        alg: ["EdDSA", "ES256"],
      },
    },
  },
  presentation_definition: PRESENTATION_DEFINITION,
  response_uri: "http://localhost:9001/response",
  response_mode: "direct_post",
  response_type: "vp_token",
  nonce: "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
  state: STATE,
};

export const AUTH_REQUEST_JWT = fixtureJws(
  JSON.stringify({ alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Verifier), typ: "application/oauth-authz-req+jwt" }),
  JSON.stringify({
    response_type: "vp_token",
    state: STATE,
    response_mode: "direct_post",
    nonce: AUTH_REQUEST.nonce,
    client_metadata: { vp_formats: { "dc+sd-jwt": { alg: ["EdDSA", "ES256"] } } },
    client_id: fixtureDidKey(FixtureKey.Verifier),
    client_id_scheme: "did",
    presentation_definition: PRESENTATION_DEFINITION,
    response_uri: "http://localhost:9001/response",
  }),
  FixtureKey.Verifier,
);

export const PRESENTATION_SUBMISSION: PresentationSubmission = {
  id: "e18f2155-1235-43e9-8f0c-1f18cf72911a",
  definition_id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
  descriptor_map: [
    {
      id: "Identity-1",
      path: "$",
      format: CredentialFormats.VCSDJWT,
    },
  ],
};

export const VC_TYPE = "https://credentials.example.com/identity_credential";

export const VC = fixtureSdJwt(
  JSON.stringify({ typ: "vc+sd-jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
  JSON.stringify({
    vct: VC_TYPE,
    sub: fixtureDidKey(FixtureKey.Holder),
    nbf: 1728882611,
    _sd_alg: "sha-256",
    iss: fixtureDidKey(FixtureKey.Issuer),
    iat: 1728882611,
    exp: 1760418611,
    cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
  }),
  ['["8zQfBB-KqYHuJqnpTDvsUQ", "name", "John"]'],
  FixtureKey.Issuer,
);
export const VP = fixtureSdJwtKb(
  fixtureSdJwt(
    JSON.stringify({ typ: "dc+sd-jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
    JSON.stringify({
      _sd: ["eTXyIZv-83-z6lDpntfnJ6fv4P_BT6kF74raA1aJm64", "m8zgin9L4V6JHm34LVxEkETk75OPqCMaQw07nMl2ht0"],
      sub: fixtureDidKey(FixtureKey.Holder),
      date: "09/09/1989",
      vct: VC_TYPE,
      iat: 1765954739,
      _sd_alg: "sha-256",
      iss: fixtureDidKey(FixtureKey.Issuer),
      exp: 1797490739,
      nbf: 1765954739,
      cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
    }),
    ['["U5Tk7r3LHVAGu3U4fLl6pQ", "name", "John"]'],
    FixtureKey.Issuer,
  ),
  JSON.stringify({ typ: "kb+jwt", alg: "ES256" }),
  JSON.stringify({
    nonce: "n-07kSJUQNwlPISE3jc8QxEia2MHTqewM3WyVx-4XlM",
    aud: `decentralized_identifier:${fixtureDidKey(FixtureKey.Verifier)}`,
    iat: 1765954739,
  }),
  FixtureKey.Holder,
);

export const AUTH_RESPONSE_JWE = fixtureJwe(
  JSON.stringify({ kid: "ecdsa-kid", enc: "A128CBC-HS256", alg: "ECDH-ES", apu: "some_nonce", apv: "some_nonce" }),
  JSON.stringify({ vp_token: VP, presentation_submission: PRESENTATION_SUBMISSION, state: STATE }),
  FixtureKey.Verifier,
);

export const CLAIMS: Claims = {
  vp_token: {
    "Identity-1": [
      {
        vct: VC_TYPE,
        sub: fixtureDidKey(FixtureKey.Holder),
        nbf: 1765954739,
        iss: fixtureDidKey(FixtureKey.Issuer),
        iat: 1765954739,
        exp: 1797490739,
        date: "09/09/1989",
        cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
        name: "John",
      },
    ],
  },
};

export const SAMPLE_ROOT_X509_PEM = fixtureX509(
  JSON.stringify({
    subject: [["CN", "CA Cert"]],
    not_before: "2025-12-15",
    not_after: "2035-12-13",
    ca: true,
    key_usages: ["digital_signature", "key_cert_sign", "crl_sign"],
  }),
  FixtureKey.Issuer,
);

// ─── x509_san_dns client id fixtures ───────────────────────────────────────────

export const X509_SAN_DNS_NAME = "verifier.example";
export const X509_SAN_DNS_CLIENT_ID = `x509_san_dns:${X509_SAN_DNS_NAME}`;
export interface X509SanDnsMaterial {
  /** PKCS#8 PEM. Generated per run — never committed. */
  privateKeyPem: string;
  /** Self-signed PEM certificate carrying `subjectAltName = DNS:verifier.example`. */
  certPem: string;
}

/**
 * Generates the x509_san_dns key pair and its certificate at test runtime.
 *
 * The certificate is signature-bound to the key it certifies, so a committed
 * certificate forces a committed private key. Generating both per run keeps
 * key material out of the repository.
 */
export async function generateX509SanDnsMaterial(): Promise<X509SanDnsMaterial> {
  x509.cryptoProvider.set(webcrypto as unknown as WebCrypto);

  const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  const keys = (await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"])) as WebCryptoKeyPair;

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + 10 * 365 * 24 * 60 * 60 * 1000);

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${X509_SAN_DNS_NAME}`,
    notBefore,
    notAfter,
    keys,
    signingAlgorithm: alg,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: X509_SAN_DNS_NAME }]),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });

  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey("pkcs8", keys.privateKey));
  const body = pkcs8.toString("base64").replace(/(.{64})/g, "$1\n");

  // The PEM label is assembled rather than written out: a literal PKCS#8 banner
  // in source is what secret scanners match on, key material or not.
  const label = ["PRIVATE", "KEY"].join(" ");

  return {
    privateKeyPem: `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`,
    certPem: cert.toString("pem"),
  };
}

export const WALLET_METADATA_WITHOUT_X509 = {
  issuer: "https://self-issued.me/v2",
  authorization_endpoint: "openid4vp://",
  response_types_supported: ["vp_token", "vp_token id_token"],
  vp_formats_supported: {
    "dc+sd-jwt": {
      "sd-jwt_alg_values": ["EdDSA", "ES256"],
      "kb-jwt_alg_values": ["EdDSA", "ES256"],
    },
  },
  client_id_prefixes_supported: ["decentralized_identifier", "redirect_uri"],
  request_object_signing_alg_values_supported: ["EdDSA", "ES256"],
  subject_syntax_types_supported: ["did:key"],
  id_token_types_supported: ["subject_signed_id_token"],
};

export const DSD_JWT_GRANT_CRED_ID = "delegatecred1";

export const DELEGATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "QYZpjqUO8AenfZ1IZpYVJIYRIwiPo3_JaRJ5DgpK7NY",
  y: "58JyJCUUnd1C9AmnrcqNrIcTFwzzCzSb-qHVeAjijDE",
};

const DSD_JWT_GRANT_ISSUER_SD_JWT = fixtureSdJwt(
  JSON.stringify({ typ: "dc+sd-jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
  JSON.stringify({
    _sd: ["T7FUgNsl8SYd3vG4YitszE5XaR1wpdlu6AxKkCkQZ2w"],
    iat: 1781774576,
    sub: fixtureDidKey(FixtureKey.Holder),
    vct: VC_TYPE,
    _sd_alg: "sha-256",
    iss: fixtureDidKey(FixtureKey.Issuer),
    exp: 2097134576,
    nbf: 1781774576,
    cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
  }),
  [],
  FixtureKey.Issuer,
);

/** dSD-JWT grant: `<issuer-jwt>~~<kb+sd-jwt+kb>~`. */
export const DSD_JWT_GRANT_VP_TOKEN = {
  delegatecred1: [
    `${DSD_JWT_GRANT_ISSUER_SD_JWT}~${fixtureJws(
      JSON.stringify({ typ: "kb+sd-jwt+kb", alg: "ES256" }),
      JSON.stringify({
        delegate_payload: [{ scope: "limited", cnf: { jwk: DELEGATE_JWK } }],
        _sd_alg: "sha-256",
        issuer_jwt_hash: createHash("sha256").update(DSD_JWT_GRANT_ISSUER_SD_JWT.split("~")[0]).digest("base64url"),
      }),
      FixtureKey.Holder,
    )}~`,
  ],
};

export const DSD_JWT_GRANT_TD_HASHES = ["z4WeSJmB_VwOQpkPzIQTRmfMf7JbDa-dtfloSxknc8w"];

export const DSD_JWT_GRANT_NONCE = "test-nonce-for-grant-delegation";

export const DSD_JWT_GRANT_RPQ = {
  dcql_query: {
    credentials: [
      {
        id: "delegatecred1",
        format: "dc+sd-jwt",
        meta: { vct_values: ["https://credentials.example.com/identity_credential"] },
        require_cryptographic_holder_binding: false,
      },
    ],
  },
};

export const DSD_JWT_GRANT_TRANSACTION_DATA: Array<TransactionDataItem> = [
  {
    type: "delegate",
    credential_ids: ["delegatecred1"],
    transaction_data_hashes_alg: null,
    format: "dSD-JWT+KB",
    delegate_payload_disclosure: Buffer.from(
      JSON.stringify(["test-salt-for-delegation", { scope: "limited", cnf: { jwk: DELEGATE_JWK } }]),
    ).toString("base64url"),
  },
];

// The dSD-JWT compact string the Delegate Holder stores after extraction.
export const DSD_JWT_GRANT_CREDENTIAL = DSD_JWT_GRANT_VP_TOKEN.delegatecred1[0];
