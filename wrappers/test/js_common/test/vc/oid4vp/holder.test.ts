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
  PRESENTATION_SUBMISSION,
  STATE,
  VC,
  VC_TYPE,
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
    holder = await new OID4VPHolderBuilder(kms, vault, "client_id")
      .withHttpClient(ReqwestHttpClient.insecure())
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

    const authorizationRequest = await holder.getAuthorizationRequest(
      "openid4vp://?client_id=did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri_method=post&request_uri=http://localhost:9001/request",
    );
  });

  it("present credentials auto", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

    await vault.storeCredential(credential, metadata);
    const result = await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST), {});

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
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

    await vault.storeCredential(credential, metadata);

    const credentialsMapping = await holder.findVcsForPresentation(new AuthorizationRequest(AUTH_REQUEST));

    for (const key in credentialsMapping) {
      expect(key).toBe("Identity-1");
      expect(credentialsMapping[key].data).toHaveLength(1);
      expect((credentialsMapping[key].data[0] as CredentialEntry).credential).toMatchObject(credential);
    }
  });

  it("findVcsForPresentation returns reasons for failed filtering", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

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
