import { CompletedRequest, getLocal } from "mockttp";
import {
  AuthorizationRequest,
  Credential,
  CredentialEntry,
  CredentialMetadata,
  DIDKey,
  FindVCsFailReason,
  InMemKms,
  InMemVault,
  KeyMetadata,
  KeyType,
  OID4VPHolder,
  OID4VPHolderBuilder,
  PresentationResultType,
  PresentationSubmission,
  ReqwestHttpClient, TslVcStatusType,
  UniversalDIDResolver,
  VCFormat,
  VCStatus,
  VCStatusFormat,
} from "agent-sdk";
import {
  AUTH_REQUEST,
  AUTH_REQUEST_WITH_FAKE_VCT,
  AUTH_REQUEST_JWT,
  AUTH_REQUEST_WITH_DIRECT_POST_JWT,
  PRESENTATION_SUBMISSION,
  STATE,
  VC,
  VC_TYPE,
  VC_WITH_STATUS,
  AUTH_REQUEST_WITH_FAKE_CONSTRAINTS,
  STATUS_LIST_JWT,
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

    const authorizationRequest = await holder.getAuthorizationRequest(
      "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaer1d3Hpdg6RH7KRhWXRtzpijEm8GtaVQn7BtSw7DiW72E&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest",
    );

    expect(authorizationRequest.getAuthRequest()).toMatchObject(AUTH_REQUEST);
  });

  it("get credential status", async () => {
    const credential = {
      format: VCFormat.SdJwtVc,
      payload: VC_WITH_STATUS,
    };
    await mockServer
      .forGet("/status_list")
      .thenReply(200, STATUS_LIST_JWT, { "content-type": "application/statuslist+jwt" });

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

    const authorizationRequest = await holder.getAuthorizationRequest(
      "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaer1d3Hpdg6RH7KRhWXRtzpijEm8GtaVQn7BtSw7DiW72E&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest",
    );
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

    await holder.getAuthorizationRequest(
      "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaer1d3Hpdg6RH7KRhWXRtzpijEm8GtaVQn7BtSw7DiW72E&request_uri_method=post&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest",
    );
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

  // TODO: enable this test after fixing the direct post jwt issue
  // it("present credentials auto with direct post jwt", async () => {
  //   await mockServer.forPost("/response").thenCallback(async (request) => await handleRequestForDirectPostJwt(request));
  //
  //   await vault.storeCredential(credential, metadata);
  //   const result = await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST_WITH_DIRECT_POST_JWT), {});
  //
  //   expect(result.type).toEqual(PresentationResultType.Presented);
  // });

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
      expect(credentialsMapping[key].data).toMatchObject({
        type: "Paths",
        paths: [["$.first_name"], ["$.surname", "$.last_name"]],
      });
    }
  });

  it("findVcsForPresentation returns types not matched", async () => {
    await vault.storeCredential(credential, metadata);

    const credentialsMapping = await holder.findVcsForPresentation(
      new AuthorizationRequest(AUTH_REQUEST_WITH_FAKE_VCT),
    );

    for (const key in credentialsMapping) {
      expect(key).toBe("Identity-1");
      expect((credentialsMapping[key].data as FindVCsFailReason).type).toStrictEqual("TypesNotMatched");
      expect((credentialsMapping[key].data as FindVCsFailReason).paths).toBeFalsy();
    }
  });

  it("findVcsForPresentation filter out revoked credentials", async () => {
    const credential = {
      format: VCFormat.SdJwtVc,
      payload: VC_WITH_STATUS,
    };
    const statusListJwt =
      "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZVVDemI0RHMyRU44anVRRnJEclNoVjZBd1cxTjlZdlJ3WHdZUWdGeGVpdk1KI3pEbmFlVUN6YjREczJFTjhqdVFGckRyU2hWNkF3VzFOOVl2UndYd1lRZ0Z4ZWl2TUoifQ.eyJzdGF0dXNfbGlzdCI6eyJiaXRzIjoxLCJsc3QiOiJlTnBqWVdCZ0FBQUFGQUFGIn0sInN1YiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9zdGF0dXNfbGlzdCIsImlhdCI6MTc1MzA1NDIzOCwiX3NkX2FsZyI6InNoYS0yNTYifQ.ZW5jcnlwdGVkX3Rlc3RfdmFsdWU~";
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
