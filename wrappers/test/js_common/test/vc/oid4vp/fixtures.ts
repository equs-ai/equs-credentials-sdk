import {
  Alg,
  Claims,
  ClientMetadata,
  CommonAuthorizationRequest,
  CredentialDefinitionFormat,
  CredentialFormats,
  CredentialStatusInfoFormat,
  DIDKey,
  InMemKms,
  InMemVault,
  IssuerMetadata,
  KeyMetadata,
  KeyType,
  PresentationDefinition,
  PresentationSubmission,
  ReqwestHttpClient,
  StatusIssuerMetadata,
  StatusListFormatFmt,
  UniversalDIDResolver,
  VcCoreHolder,
  VcCoreIssuer,
  VcCoreStatusIssuer,
  VCFormat,
  VCStatusesDataFormat,
} from "equs-credentials-sdk";
import { token } from "../../bundle";

async function createDidAndKeyMetadata(kms: InMemKms): Promise<{ did: string; keyMetadata: KeyMetadata }> {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);
  const did = new DIDKey().generate(keyHandle);
  const vm = await new UniversalDIDResolver().resolveVerificationMethod(did);
  return { did, keyMetadata: { didUrl: vm.id, kid: keyId } };
}

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
              const: "https://issuer.example/credential-schema",
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
              const: "https://issuer.example/credential-schema",
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
            path: ["$.middle_name", "$.honorific_prefix"],
            intent_to_retain: false,
            predicate: null,
            optional: false,
          },
        ],
      },
    },
  ],
};

const AUTH_REQUEST_CLIENT_METADATA: ClientMetadata = {
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
};

/**
 * Mints a signed OID4VP authorization request object plus the
 * `CommonAuthorizationRequest` a holder resolves it to. Signed directly with
 * the key handle rather than through a verifier, since the WASM build exposes
 * no OID4VP verifier; `client_id` names the signing key's DID, which is what
 * the holder checks first.
 */
export async function buildAuthRequestFixture(): Promise<{
  authRequestJwt: string;
  authRequest: CommonAuthorizationRequest;
}> {
  const kms = new InMemKms();
  const { did, keyMetadata } = await createDidAndKeyMetadata(kms);

  const authRequest: CommonAuthorizationRequest = {
    client_id: `decentralized_identifier:${did}`,
    client_metadata: AUTH_REQUEST_CLIENT_METADATA,
    response_uri: "http://localhost:9001/response",
    response_mode: "direct_post",
    response_type: "vp_token",
    nonce: "fixture-nonce",
    state: STATE,
    presentation_definition: PRESENTATION_DEFINITION,
    transaction_data: [
      {
        type: "some_type",
        credential_ids: ["Identity-1"],
        transaction_data_hashes_alg: ["sha-256", "sha-512"],
      },
    ] as any,
  };

  const b64url = (value: string | Uint8Array) => Buffer.from(value).toString("base64url");
  const header = { alg: "ES256", kid: keyMetadata.didUrl, typ: "application/oauth-authz-req+jwt" };
  const claims = {
    ...authRequest,
    transaction_data: (authRequest.transaction_data as unknown[]).map((item) => b64url(JSON.stringify(item))),
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = await (await kms.get(keyMetadata.kid)).sign(Buffer.from(signingInput));

  return { authRequestJwt: `${signingInput}.${b64url(signature)}`, authRequest };
}

export function withDirectPostJwt(authRequest: CommonAuthorizationRequest): CommonAuthorizationRequest {
  return {
    ...authRequest,
    client_metadata: {
      ...authRequest.client_metadata,
      jwks: {
        keys: [
          {
            kid: "ecdsa-kid",
            kty: "EC",
            crv: "P-256",
            x: "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
            y: "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
            alg: "ES256",
          },
        ],
      },
    },
    response_mode: "direct_post.jwt",
  };
}

export function withFakeVct(authRequest: CommonAuthorizationRequest): CommonAuthorizationRequest {
  return { ...authRequest, presentation_definition: PRESENTATION_DEFINITION_WITH_FAKE_VCT } as CommonAuthorizationRequest;
}

export function withFakeConstraints(authRequest: CommonAuthorizationRequest): CommonAuthorizationRequest {
  return {
    ...authRequest,
    presentation_definition: PRESENTATION_DEFINITION_WITH_FAKE_CONSTRAINTS,
  } as CommonAuthorizationRequest;
}

export const PRESENTATION_SUBMISSION: PresentationSubmission = {
  id: "e18f2155-1235-43e9-8f0c-1f18cf72911a",
  definition_id: "f64edc99-2b79-45ce-ad36-5e346ebfc6ec",
  descriptor_map: [{ id: "Identity-1", format: CredentialFormats.VCSDJWT, path: "$", path_nested: null }],
};

export const VC_TYPE = "https://issuer.example/credential-schema";

export const VC = token("vc");

/**
 * Mints a fresh SD-JWT VC whose `status` claim points at index `idx` of a
 * fresh status list published at `http://localhost:9001/status_list` (the
 * mock server tests here already serve), with the bit at that index set to
 * `valid`.
 *
 * The bundle's own `vcWithStatus`/`statusListJwt` pair (and the revoked
 * pair) can't stand in for this: their status list is published at a fixed
 * `https://issuer.example/...` URL that this suite's `mockServer` — bound to
 * `localhost:9001` — can never intercept, since the fetch never reaches it
 * (no DNS entry resolves that host to the mock server). Minting locally with
 * an explicit `http://localhost:9001/status_list` URL keeps the credential
 * and status list a real, SDK-signed, mutually coherent pair while staying
 * reachable by the mock server the way the committed fixtures were.
 */
export async function buildStatusCredential(
  statusIdx: number,
  valid: boolean,
): Promise<{ credential: string; statusListJwt: string }> {
  const kms = new InMemKms();
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  const statusIssuerMetadata: StatusIssuerMetadata = {
    issuerId: "test",
    supportedStatusLists: [
      {
        id: "test_status_list",
        format: {
          format: StatusListFormatFmt.StatusListTokenJwt,
          payload: {
            statuses_nr: 32,
            status_list_url: "http://localhost:9001/status_list",
            status_size: 2,
          },
        },
        keyMetadata,
      },
    ],
  };
  const statusIssuer = new VcCoreStatusIssuer(kms, statusIssuerMetadata);
  const statusList = await statusIssuer.issueStatusList("test_status_list", {
    format: VCStatusesDataFormat.StatusListToken,
    payload: { statuses: { [statusIdx.toString()]: valid ? 0 : 1 } },
  });

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
          payload: { vct: VC_TYPE, disclosures: ["$.name"] },
        },
        keyMetadata,
      },
    ],
    protocolData: undefined,
  };
  const issuer = new VcCoreIssuer(kms, issuerMetadata, new UniversalDIDResolver());
  const offer = issuer.offerCredential("Identity-1", undefined);

  const holderKms = new InMemKms();
  const { keyMetadata: holderKeyMetadata } = await createDidAndKeyMetadata(holderKms);
  const holder = new VcCoreHolder(
    holderKms,
    new InMemVault(),
    { clientId: "wallet-dev", pop: { lifetime: 300 } },
    new UniversalDIDResolver(),
    ReqwestHttpClient.insecure(),
  );
  const request = await holder.requestCredential(offer, null, holderKeyMetadata);
  const credential = await issuer.issueCredential(request, { name: "John" }, null, {
    format: CredentialStatusInfoFormat.TokenStatusList,
    payload: { idx: statusIdx, uri: "http://localhost:9001/status_list" },
  });

  return { credential: credential.payload as string, statusListJwt: statusList.payload.jwt as string };
}
