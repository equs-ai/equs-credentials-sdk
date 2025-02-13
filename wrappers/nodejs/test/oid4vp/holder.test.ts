import { CompletedRequest, getLocal } from "mockttp";
import {
  Credential,
  CredentialMetadata,
  inMemKms,
  inMemVault,
  KeyMetadata,
  NativeKms,
  NativeVault,
  Oid4VpHolder,
  OID4VPHolderBuilder,
  VCFormat,
} from "../../";
import { AUTH_REQUEST, AUTH_REQUEST_JWT, STATE, VC, VC_TYPE } from "./fixtures";
import { createDidAndKeyMetadata } from "../utils/utils";

describe("OID4VP Holder: ", () => {
  const mockServer = getLocal();

  let kms: NativeKms;
  let vault: NativeVault;
  let holder: Oid4VpHolder;

  let keyMetadata: KeyMetadata;
  let credential: Credential;
  let metadata: CredentialMetadata;

  beforeEach(async () => {
    await mockServer.start(9001);
    kms = inMemKms();
    vault = inMemVault();
    holder = await new OID4VPHolderBuilder(kms, vault, "client_id").build();

    keyMetadata = (await createDidAndKeyMetadata(kms)).keyMetadata;
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

  afterEach(async () => await mockServer.stop());

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

    const result = await holder.presentCredentialsAuto(AUTH_REQUEST, {});

    expect(result).toBeNull();
  });

  test("present Credentials Auto with excluded claims", async () => {
    let token: string;
    await mockServer.forPost("/response").thenCallback(async (request) => {
      const form_data = await request.body.getFormData();

      token = form_data.vp_token as string;
      if (!form_data.presentation_submission?.length || !form_data.vp_token?.length)
        throw new Error("Form data is invalid");

      return { statusCode: 200, body: "" };
    });

    await vault.storeCredential(credential, metadata);

    await holder.presentCredentialsAuto(AUTH_REQUEST, {
      claimsToExclude: { "Identity-1": ["$.name"] },
    });

    expect(token.split("~").length).toEqual(2);
  });

  test("present Credentials", async () => {
    await mockServer.forPost("/response").thenCallback(async (request) => await handleRequest(request));

    await vault.storeCredential(credential, metadata);

    let mapping = await holder.findVcsForPresentation(AUTH_REQUEST);

    const result = await holder.presentCredentials(AUTH_REQUEST, mapping, {});

    expect(result).toBeNull();
  });
});

async function handleRequest(request: CompletedRequest): Promise<{ statusCode: 200; body: "" }> {
  const form_data = await request.body.getFormData();

  if (!form_data.presentation_submission?.length || !form_data.vp_token?.length)
    throw new Error("Form data is invalid");

  expect(form_data.state).toEqual(STATE);

  return { statusCode: 200, body: "" };
}
