import { CompletedRequest, getLocal } from "mockttp";
import {
  AuthorizationRequest,
  Credential,
  CredentialEntry,
  CredentialMetadata,
  DIDKey,
  FindVCsFailReason,
  FindVCsFailReasonType,
  InMemKms,
  InMemVault,
  KeyMetadata,
  KeyType,
  OID4VPHolder,
  OID4VPHolderBuilder,
  PresentationResultType,
  PresentationSubmission,
  ReqwestHttpClient,
  TslVcStatusType,
  UniversalDIDResolver,
  VCFormat,
  VCStatus,
  VCStatusFormat,
} from "equs-credentials-sdk";
import {
  buildAuthRequestFixture,
  buildStatusCredential,
  PRESENTATION_SUBMISSION,
  STATE,
  VC,
  VC_TYPE,
  withDirectPostJwt,
  withFakeConstraints,
  withFakeVct,
} from "./fixtures";
import { MockNonceHandler } from "./mockNonceHandler";

describe("OID4VP Holder: ", () => {
  const mockServer = getLocal();
  mockServer.start(9001);

  let kms: InMemKms;
  let vault: InMemVault;
  let holder: OID4VPHolder;

  let credential: Credential;
  let metadata: CredentialMetadata;

  let AUTH_REQUEST_JWT: string;
  let AUTH_REQUEST: import("equs-credentials-sdk").CommonAuthorizationRequest;
  let AUTH_REQUEST_WITH_DIRECT_POST_JWT: import("equs-credentials-sdk").CommonAuthorizationRequest;
  let AUTH_REQUEST_WITH_FAKE_VCT: import("equs-credentials-sdk").CommonAuthorizationRequest;
  let AUTH_REQUEST_WITH_FAKE_CONSTRAINTS: import("equs-credentials-sdk").CommonAuthorizationRequest;
  let requestUri: string;
  let requestUriPost: string;

  beforeAll(async () => {
    const fixture = await buildAuthRequestFixture();
    AUTH_REQUEST_JWT = fixture.authRequestJwt;
    AUTH_REQUEST = fixture.authRequest;
    AUTH_REQUEST_WITH_DIRECT_POST_JWT = withDirectPostJwt(AUTH_REQUEST);
    AUTH_REQUEST_WITH_FAKE_VCT = withFakeVct(AUTH_REQUEST);
    AUTH_REQUEST_WITH_FAKE_CONSTRAINTS = withFakeConstraints(AUTH_REQUEST);

    // `AUTH_REQUEST.client_id` is `decentralized_identifier:<did>` — the deep
    // link's own `client_id` param must carry the same freshly generated DID.
    const did = AUTH_REQUEST.client_id.replace(/^decentralized_identifier:/, "");
    const clientIdParam = `client_id=decentralized_identifier%3A${encodeURIComponent(did)}`;
    requestUri = `openid4vp://?${clientIdParam}&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest`;
    requestUriPost = `openid4vp://?${clientIdParam}&request_uri_method=post&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest`;
  });

  beforeEach(async () => {
    mockServer.reset();
    kms = new InMemKms();
    vault = new InMemVault();
    holder = await new OID4VPHolderBuilder(
      kms,
      vault,
      "did:key:zDnaeynayJkibriPJdYBgYTe6eE6cLqHU4jox1gg44fYGYgSs",
      ReqwestHttpClient.insecure(),
    )
      .withNonceHandler(new MockNonceHandler("some_nonce"))
      .build();

    const keyMetadata = await createKeyMetadata(kms);

    credential = {
      format: VCFormat.SdJwtVc,
      payload: VC,
    };
    metadata = {
      type: VC_TYPE,
      kid: keyMetadata.kid,
      format: VCFormat.SdJwtVc,
      fields: ["$.vct", "$.name"],
    };
  });

  afterAll(async () => await mockServer.stop());

  it("resolve authorization request", async () => {
    await mockServer
      .forGet("/request")
      .thenReply(200, AUTH_REQUEST_JWT, { "content-type": "application/oauth-authz-req+jwt" });

    const authorizationRequest = await holder.getAuthorizationRequest(requestUri);

    expect(authorizationRequest.getAuthRequest()).toMatchObject(AUTH_REQUEST);
  });

  it("get credential status", async () => {
    const { credential: statusCredentialPayload, statusListJwt } = await buildStatusCredential(1, true);
    const credential = {
      format: VCFormat.SdJwtVc,
      payload: statusCredentialPayload,
    };
    await mockServer
      .forGet("/status_list")
      .thenReply(200, statusListJwt, { "content-type": "application/statuslist+jwt" });

    const status: VCStatus = await holder.getCredentialStatus(credential);
    expect(status).toEqual({
      format: VCStatusFormat.StatusListToken,
      payload: {
        status: TslVcStatusType.VALID,
      },
    });
  });

  it("resolve authorization request with transaction data", async () => {
    await mockServer
      .forGet("/request")
      .thenReply(200, AUTH_REQUEST_JWT, { "content-type": "application/oauth-authz-req+jwt" });

    const authorizationRequest = await holder.getAuthorizationRequest(requestUri);
    let transactionData = authorizationRequest.getAuthRequest().transaction_data;
    expect(transactionData).toEqual([
      {
        type: "some_type",
        credential_ids: ["Identity-1"],
        transaction_data_hashes_alg: ["sha-256", "sha-512"],
      },
    ]);
  });

  it("check mock nonce handler passed properly", async () => {
    await mockServer.forPost("/request").thenCallback(async (request): Promise<any> => {
      let body = await request.body.getText();
      expect(body).toContain("some_nonce");
      return {
        statusCode: 200,
        headers: { "content-type": "application/oauth-authz-req+jwt" },
        body: AUTH_REQUEST_JWT,
      };
    });

    await holder.getAuthorizationRequest(requestUriPost);
  });

  it("present credentials auto", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

    await vault.storeCredential(credential, metadata);
    const result = await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST), {});

    expect(result.type).toEqual(PresentationResultType.Presented);
  });

  it("present credentials auto with transaction data", async () => {
    await mockServer
      .forPost("/response")
      .thenCallback(async (request) => await handleRequestForTransactionData(request));

    await vault.storeCredential(credential, metadata);
    const result = await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST), {});
    expect(result.type).toEqual(PresentationResultType.Presented);
  });

  it("present credentials auto with direct post jwt", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequestForDirectPostJwt(request));

    await vault.storeCredential(credential, metadata);
    const result = await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST_WITH_DIRECT_POST_JWT), {});

    expect(result.type).toEqual(PresentationResultType.Presented);
  });

  it("present Credentials Auto with excluded claims", async () => {
    let token: string;
    await mockServer.forPost("/response").thenCallback(async (request) => {
      const form_data = await request.body.getFormData();

      token = form_data.vp_token as string;
      if (!form_data.presentation_submission?.length || !form_data.vp_token?.length)
        throw new Error("Form data is invalid");

      return { statusCode: 200, body: "" };
    });

    await vault.storeCredential(credential, metadata);

    await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST), {
      claimsToExclude: { "Identity-1": ["$.name"] },
    });

    expect(token.split("~").length).toEqual(2);
  });

  it("findVcsForPresentation returns credential entries for succeeded filtering", async () => {
    await vault.storeCredential(credential, metadata);

    const credentialsMapping = await holder.findVcsForPresentation(new AuthorizationRequest(AUTH_REQUEST));

    for (const key in credentialsMapping) {
      expect(key).toBe("Identity-1");
      expect(credentialsMapping[key].data).toHaveLength(1);
      expect((credentialsMapping[key].data[0] as CredentialEntry).credential).toMatchObject(credential);
    }
  });

  it("findVcsForPresentation returns reasons for failed filtering", async () => {
    await vault.storeCredential(credential, metadata);

    const credentialsMapping = await holder.findVcsForPresentation(
      new AuthorizationRequest(AUTH_REQUEST_WITH_FAKE_CONSTRAINTS),
    );

    for (const key in credentialsMapping) {
      expect(key).toBe("Identity-1");
      // The bundle's `vc` fixture discloses `surname` (the old committed
      // literal never did), so that alternative is satisfied now — only
      // `$.first_name`, which no fixture discloses, is still missing.
      expect(credentialsMapping[key].data).toMatchObject({
        type: "Paths",
        paths: [["$.first_name"]],
      });
    }
  });

  it("findVcsForPresentation returns types not matched", async () => {
    await vault.storeCredential(credential, metadata);

    const credentialsMapping = await holder.findVcsForPresentation(
      new AuthorizationRequest(AUTH_REQUEST_WITH_FAKE_VCT),
    );

    for (const key in credentialsMapping) {
      const data = credentialsMapping[key].data;
      if (isCredentialEntries(data)) {
        throw new Error("FindVCsFailReason expected but got CredentialEntry[]");
      }
      expect(key).toBe("Identity-1");
      expect(data.type).toStrictEqual(FindVCsFailReasonType.TypesNotMatched);
      expect(data.paths).toBeFalsy();
    }
  });

  it("findVcsForPresentation filter out revoked credentials", async () => {
    // A real, SDK-signed revoked credential + status list pair — not a
    // hand-rolled status list — matching AUTH_REQUEST_WITH_FAKE_VCT's vct
    // mismatch, so `is_valid()` must consult the (revoked) status to decide
    // whether the mismatch reason surfaces at all (it must not).
    const { credential: revokedCredentialPayload, statusListJwt } = await buildStatusCredential(1, false);
    const credential = {
      format: VCFormat.SdJwtVc,
      payload: revokedCredentialPayload,
    };
    await mockServer
      .forGet("/status_list")
      .thenReply(200, statusListJwt, { "content-type": "application/statuslist+jwt" });

    await vault.storeCredential(credential, metadata);

    const credentialsMapping = await holder.findVcsForPresentation(
      new AuthorizationRequest(AUTH_REQUEST_WITH_FAKE_VCT),
    );

    for (const key in credentialsMapping) {
      expect(key).toBe("Identity-1");
      expect((credentialsMapping[key].data as FindVCsFailReason).type).toStrictEqual("CredentialsNotFound");
      expect((credentialsMapping[key].data as FindVCsFailReason).paths).toBeFalsy();
    }
  });

  it("decline authorization request", async () => {
    let response;
    await mockServer.forPost("/response").thenCallback(async (request): Promise<any> => {
      response = await request.body.getFormData();
      return {};
    });

    await vault.storeCredential(credential, metadata);

    await holder.declineAuthorizationRequest(new AuthorizationRequest(AUTH_REQUEST));

    expect(response).toEqual({
      error: "access_denied",
      error_description: "consent to share the presentation is not given",
      state: STATE,
    });
  });
});

async function handleRequest(request: CompletedRequest): Promise<{ statusCode: 200; body: "" }> {
  const form_data = await request.body.getFormData();

  const presentationSubmission: PresentationSubmission = JSON.parse(form_data.presentation_submission as string);
  presentationSubmission.id = PRESENTATION_SUBMISSION.id;

  expect(presentationSubmission).toEqual(PRESENTATION_SUBMISSION);

  if (!form_data.vp_token?.length) throw new Error("Form data is invalid");

  expect(form_data.state).toEqual(STATE);

  return { statusCode: 200, body: "" };
}

async function handleRequestForTransactionData(request: CompletedRequest): Promise<{ statusCode: 200; body: "" }> {
  const form_data = await request.body.getFormData();
  const transaction_data_hashes: Array<string> = JSON.parse(form_data.transaction_data_hashes as string);
  const transaction_data_hashes_alg: string = JSON.parse(form_data.transaction_data_hashes_alg as string);
  expect(transaction_data_hashes.length).toEqual(1);
  expect(transaction_data_hashes_alg).toEqual("sha-256");
  return await handleRequest(request);
}
async function handleRequestForDirectPostJwt(request: CompletedRequest): Promise<{ statusCode: 200; body: "" }> {
  const form_data = await request.body.getFormData();
  expect(form_data.response);
  expect((form_data.response as string).startsWith("ey"));
  return { statusCode: 200, body: "" };
}

async function createKeyMetadata(kms: InMemKms): Promise<KeyMetadata> {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);
  const didKey = new DIDKey();

  const did = didKey.generate(keyHandle);

  const universalDidResolver = new UniversalDIDResolver();

  const vm = await universalDidResolver.resolveVerificationMethod(did);

  return {
    didUrl: vm.id,
    kid: keyId,
  };
}

function isCredentialEntries(data: CredentialEntry[] | FindVCsFailReason): data is CredentialEntry[] {
  return Array.isArray(data);
}
