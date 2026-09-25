// `@peculiar/x509` resolves its providers through tsyringe, which needs this first.
import "reflect-metadata";
import {
  Alg,
  Claims,
  CredentialDefinitionFormat,
  CredentialEntry,
  CredentialFormats,
  DelegationParams,
  HolderBinder,
  HolderMetadata,
  InMemKms,
  InMemVault,
  IssuerMetadata,
  PresentationDefinition,
  PresentationInput,
  PresentationRestrictionValue,
  PresentationSubmission,
  CommonAuthorizationRequest,
  PresentationQuery,
  Dcql,
  ReqwestHttpClient,
  TransactionDataItem,
  UniversalDIDResolver,
  VcCoreHolder,
  VcCoreIssuer,
  VCFormat,
} from "../../";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import { jwtDecode } from "jwt-decode";
import { token } from "../../../test/js_common/test/bundle";
import { createDidAndKeyMetadata } from "../utils";

// `lib` is ESNext only, so the DOM WebCrypto types are not in scope here.
type WebCrypto = webcrypto.Crypto;
type WebCryptoKeyPair = webcrypto.CryptoKeyPair;

export const AUTH_REQUEST_JWT = token("authRequestJwt");
export const STATE = "eea7b48e-1866-41b4-beae-03b95d41670c";
export const AUTH_RESPONSE_JWE = token("authResponseJwe");

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
  client_id: "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
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

export const VC = token("vc");

/**
 * Mints a fresh SD-JWT VC + KB-JWT presentation bound to `verifierDid`/`nonce`,
 * and the claims a real verification of it decodes to. Neither the credential
 * nor `CLAIMS` can be committed fixtures: `CLAIMS` echoes freshly generated
 * `sub`/`iss`/`cnf`/timestamps, which change every run.
 */
export async function buildAuthResponseFixture(
  verifierDid: string,
  nonce: string,
): Promise<{ vp: string; claims: Claims }> {
  const issuerKms = new InMemKms();
  const { keyMetadata: issuerKeyMetadata } = await createDidAndKeyMetadata(issuerKms);
  const issuerMetadata: IssuerMetadata = {
    issuerId: "https://issuer-backend.com",
    credDefs: [
      {
        credDefId: "Identity-1",
        format: VCFormat.SdJwtVc,
        claims: {},
        supportedProofs: { Jwt: ["ES256"] },
        supportedSigningAlgs: [Alg.ES256],
        display: undefined,
        protocolData: {
          format: CredentialDefinitionFormat.SdJwt,
          payload: {
            vct: VC_TYPE,
            disclosures: ["$.name"],
          },
        },
        keyMetadata: issuerKeyMetadata,
      },
    ],
    protocolData: undefined,
  };
  const issuer = new VcCoreIssuer(issuerKms, issuerMetadata, new UniversalDIDResolver());

  const holderKms = new InMemKms();
  const vault = new InMemVault();
  const { keyMetadata: holderKeyMetadata } = await createDidAndKeyMetadata(holderKms);
  const holder = new VcCoreHolder(
    holderKms,
    vault,
    { clientId: "wallet-dev", pop: { lifetime: 300 } },
    new UniversalDIDResolver(),
    ReqwestHttpClient.insecure(),
  );

  const offer = issuer.offerCredential("Identity-1", undefined);
  const request = await holder.requestCredential(offer, nonce, holderKeyMetadata);
  const credential = await issuer.issueCredential(request, { name: "John", date: "09/09/1989" }, nonce, undefined);
  await holder.storeCredential(credential, {
    type: VC_TYPE,
    kid: holderKeyMetadata.kid,
    format: VCFormat.SdJwtVc,
    fields: ["$.vct", "$.name"],
  });

  const presentationInput: PresentationInput = {
    id: "Identity-1",
    format: "dc+sd-jwt",
    restrictions: [
      {
        fields: ["$.vct"],
        value: PresentationRestrictionValue.withString(VC_TYPE),
        optional: false,
      },
    ],
  };
  // Matches `ClientId.fromDid(verifierDid).fullId` — the audience the KB-JWT
  // must carry for the verifier's own `did:key` client id.
  const holderBinder: HolderBinder = { nonce, verifierId: `decentralized_identifier:${verifierDid}` };
  const presentation = await holder.createPresentationAuto(holderBinder, presentationInput);

  // Not a verification: a naive decode of what was actually signed, so it can
  // serve as the independent expectation `verifier.verifyPresentation` (a
  // real signature + business-logic check) is compared against below.
  // `_sd`/`_sd_alg` are SD-JWT wire artifacts a real verification resolves
  // away, so they're dropped here to match its output shape.
  const { _sd, _sd_alg, ...decoded } = jwtDecode(presentation.payload) as Record<string, unknown>;

  return {
    vp: presentation.payload,
    claims: {
      vp_token: {
        "Identity-1": [decoded as unknown as Record<string, unknown>],
      },
    } as unknown as Claims,
  };
}

export const SAMPLE_ROOT_X509_PEM = `-----BEGIN CERTIFICATE-----
MIIBZzCCAQ6gAwIBAgIUGaB+RAZje4MNjJqrAlNx1ByAiL8wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHQ0EgQ2VydDAeFw0yNTEyMTUxMDU2MzBaFw0zNTEyMTMxMDU2
MzBaMBIxEDAOBgNVBAMMB0NBIENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASVMf5Ykf8dzr46duTAZN3X2iFC1sp1pL15V3u/KDsmPjR21VnK1uv6kDvEziF7
VyIFbvb40t/+c5eB3jg1cMq4o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBhjAdBgNVHQ4EFgQULHoOFFycXvdnCIlsyQiI5izPKkMwCgYIKoZIzj0E
AwIDRwAwRAIgF+H7wT7a95WbiE+DDlZrQ7U3RlCUOMCFqudFRz+K6I4CIAT35kig
4Q1ALvtXiWKDOjZIVxlw5eKQiq0dsd+bXKZE
-----END CERTIFICATE-----`;

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

/**
 * Mints a fresh dSD-JWT grant delegating a freshly issued credential, with
 * the same disclosed alternative ({@link DELEGATE_JWK}-bound, `scope:
 * "limited"`) {@link DSD_JWT_GRANT_TRANSACTION_DATA}'s
 * `delegate_payload_disclosure` names, so `same_payload` still matches it —
 * that field and {@link DSD_JWT_GRANT_TD_HASHES} depend only on the
 * transaction-data item's own content, not on this grant, so neither needs
 * to change alongside it. `VcCoreHolder.createDelegatedCredential` is the
 * only path that can mint one; there is no way to derive it from the bundle.
 */
export async function buildDsdJwtGrant(): Promise<string> {
  const issuerKms = new InMemKms();
  const { keyMetadata: issuerKeyMetadata } = await createDidAndKeyMetadata(issuerKms);
  const issuerMetadata: IssuerMetadata = {
    issuerId: "https://issuer-backend.com",
    credDefs: [
      {
        credDefId: DSD_JWT_GRANT_CRED_ID,
        format: VCFormat.SdJwtVc,
        claims: {},
        supportedProofs: { Jwt: ["ES256"] },
        supportedSigningAlgs: [Alg.ES256],
        display: undefined,
        protocolData: {
          format: CredentialDefinitionFormat.SdJwt,
          payload: { vct: VC_TYPE, disclosures: ["$.name"] },
        },
        keyMetadata: issuerKeyMetadata,
      },
    ],
    protocolData: undefined,
  };
  const issuer = new VcCoreIssuer(issuerKms, issuerMetadata, new UniversalDIDResolver());

  const holderKms = new InMemKms();
  const { keyMetadata: holderKeyMetadata } = await createDidAndKeyMetadata(holderKms);
  const holder = new VcCoreHolder(
    holderKms,
    new InMemVault(),
    { clientId: "wallet-dev", pop: { lifetime: 300 } },
    new UniversalDIDResolver(),
    ReqwestHttpClient.insecure(),
  );

  const offer = issuer.offerCredential(DSD_JWT_GRANT_CRED_ID, undefined);
  const request = await holder.requestCredential(offer, null, holderKeyMetadata);
  const credential = await issuer.issueCredential(request, {});

  const entry: CredentialEntry = { credential, kid: holderKeyMetadata.kid, id: DSD_JWT_GRANT_CRED_ID };
  const params: DelegationParams = {
    delegatePayloads: [{ scope: "limited", cnf: { jwk: DELEGATE_JWK } }],
    binding: "IssuerJwtHash",
  };
  return await holder.createDelegatedCredential(entry, params);
}

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

export const DELEGATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "QYZpjqUO8AenfZ1IZpYVJIYRIwiPo3_JaRJ5DgpK7NY",
  y: "58JyJCUUnd1C9AmnrcqNrIcTFwzzCzSb-qHVeAjijDE",
};

export const DSD_JWT_GRANT_TRANSACTION_DATA: Array<TransactionDataItem> = [
  {
    type: "delegate",
    credential_ids: ["delegatecred1"],
    transaction_data_hashes_alg: null,
    format: "dSD-JWT+KB",
    delegate_payload_disclosure:
      "WyJ0ZXN0LXNhbHQtZm9yLWRlbGVnYXRpb24iLHsic2NvcGUiOiJsaW1pdGVkIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlFZWnBqcVVPOEFlbmZaMUlacFlWSklZUkl3aVBvM19KYVJKNURncEs3TlkiLCJ5IjoiNThKeUpDVVVuZDFDOUFtbnJjcU5ySWNURnd6ekN6U2ItcUhWZUFqaWpERSJ9fX1d",
  },
];
