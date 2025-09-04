import { CompletedRequest, getLocal } from "mockttp";
import {
  AuthorizationRequest,
  Credential,
  CredentialEntry,
  CredentialMetadata,
  DIDKey,
  InMemKms,
  InMemVault,
  KeyMetadata,
  KeyType,
  OID4VPHolder,
  OID4VPHolderBuilder,
  PresentationSubmission,
  ReqwestHttpClient,
  UniversalDIDResolver,
  VCFormat,
} from "agent-sdk";
import {
  AUTH_REQUEST,
  AUTH_REQUEST_FAKE,
  AUTH_REQUEST_JWT,
  AUTH_REQUEST_JWT_WITH_TRANSACTION_DATA,
  AUTH_REQUEST_WITH_DIRECT_POST_JWT,
  AUTH_REQUEST_WITH_TRANSACTION_DATA,
  CLIENT_ID_AS_URL_SAFE,
  PRESENTATION_DEFINITION_FAKE,
  PRESENTATION_SUBMISSION,
  STATE,
  VC,
  VC_TYPE,
  VC_WITH_STATUS,
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
    holder = await new OID4VPHolderBuilder(kms, vault, "client_id", ReqwestHttpClient.insecure())
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
      "openid4vp://?client_id=did%3Akey%3AzDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest",
    );
    expect(authorizationRequest.getAuthRequest()).toEqual(AUTH_REQUEST);
  });

  it("resolve authorization request with transaction data", async () => {
    await mockServer
      .forGet("/request")
      .thenReply(200, AUTH_REQUEST_JWT_WITH_TRANSACTION_DATA, { "content-type": "application/oauth-authz-req+jwt" });

    const authorizationRequest = await holder.getAuthorizationRequest(
      `openid4vp://?client_id=${CLIENT_ID_AS_URL_SAFE}&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest`,
    );
    console.log(authorizationRequest.getAuthRequest());
    let transactionData = authorizationRequest.getAuthRequest().transaction_data;
    expect(transactionData).toEqual([
      {
        type: "type1",
        credential_ids: ["Identity-1"],
        transaction_data_hashes_alg: ["sha-256"],
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
      "openid4vp://?client_id=did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri_method=post&request_uri=http://localhost:9001/request",
    );
  });

  it("present credentials auto", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

    await vault.storeCredential(credential, metadata);
    const result = await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST), {});

    expect(result).toBeFalsy();
  });

  it("present credentials auto with transaction data", async () => {
    await mockServer
      .forPost("/response")
      .thenCallback(async (request) => await handleRequestForTransactionData(request));

    await vault.storeCredential(credential, metadata);
    const result = await holder.presentCredentialsAuto(
      new AuthorizationRequest(AUTH_REQUEST_WITH_TRANSACTION_DATA),
      {},
    );

    expect(result).toBeFalsy();
  });

  it("present credentials auto with direct post jwt", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequestForDirectPostJwt(request));

    await vault.storeCredential(credential, metadata);
    const result = await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST_WITH_DIRECT_POST_JWT), {});

    expect(result).toBeFalsy();
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

    const credentialsMapping = await holder.findVcsForPresentation(new AuthorizationRequest(AUTH_REQUEST_FAKE));

    for (const key in credentialsMapping) {
      expect(key).toBe("Identity-1");
      expect(credentialsMapping[key].data).toHaveLength(1);
      expect(credentialsMapping[key].data[0]).toHaveLength(1);
      expect(credentialsMapping[key].data[0][0]).toMatchObject({
        paths: ["$.vct"],
        type: "const",
        value: "https://credentials.example.com/identity_credential_1",
      });
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

    const credentialsMapping = await holder.findVcsForPresentation(new AuthorizationRequest(AUTH_REQUEST_FAKE));

    for (const key in credentialsMapping) {
      expect(key).toBe("Identity-1");
      expect(credentialsMapping[key].data).toHaveLength(PRESENTATION_DEFINITION_FAKE.input_descriptors.length);
      expect(credentialsMapping[key].data[0]).toHaveLength(
        PRESENTATION_DEFINITION_FAKE.input_descriptors[0].constraints.fields.length,
      );
      expect(credentialsMapping[key].data[0]).toMatchObject([
        {
          paths: ["$.vct"],
          type: "const",
          value: "https://credentials.example.com/identity_credential_1",
        },
        {
          paths: ["$.name"],
          type: null,
          value: null,
        },
      ]);
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
      state: "eea7b48e-1866-41b4-beae-03b95d41670c",
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
