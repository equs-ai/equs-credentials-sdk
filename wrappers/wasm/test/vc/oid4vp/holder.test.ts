import { CompletedRequest, getLocal } from "mockttp";
import {
  Credential,
  CredentialEntry,
  CredentialMetadata,
  DIDKey,
  HttpClient,
  InMemKms,
  InMemVault,
  KeyMetadata,
  OID4VPHolder,
  OID4VPHolderBuilder,
  UniversalDIDResolver,
} from "../../../pkg";
import { AUTH_REQUEST, AUTH_REQUEST_JWT, PRESENTATION_SUBMISSION, STATE, VC, VC_TYPE } from "./fixtures";
import { PresentationSubmission } from "../../../../types";
import { KeyType, VCFormat } from "../../../types";

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
    holder = await new OID4VPHolderBuilder(kms, vault, "client_id").withHttpClient(HttpClient.insecure()).build();

    let keyMetadata = await createKeyMetadata(kms);

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

  test("resolve Authorization request", async () => {
    await mockServer
      .forGet("/request")
      .thenReply(200, AUTH_REQUEST_JWT, { "content-type": "application/oauth-authz-req+jwt" });

    const authorizationRequest = await holder.getAuthorizationRequest(
      "openid4vp://?client_id=did%3Akey%3AzDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest",
    );
    expect(authorizationRequest).toEqual(AUTH_REQUEST);
  });

  test("present Credentials Auto", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

    await vault.storeCredential(credential, metadata);

    const result = await holder.presentCredentialsAuto(AUTH_REQUEST);

    expect(result).toBeUndefined();
  });

  test("present Credentials", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

    await vault.storeCredential(credential, metadata);

    let credentialsMapping = await holder.findVcsForPresentation(AUTH_REQUEST);
    let credentialMapping: Record<string, CredentialEntry> = Object.entries(credentialsMapping).reduce(
      (acc, [key, values]) => {
        acc[key] = values[0];
        return acc;
      },
      {},
    );

    const result = await holder.presentCredentials(AUTH_REQUEST, credentialMapping);

    expect(result).toBeUndefined();
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
