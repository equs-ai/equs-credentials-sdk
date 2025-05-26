import { getLocal } from "mockttp";
import {
  AuthorizationRequest,
  Credential,
  CredentialMetadata,
  InMemKms,
  InMemVault,
  KeyMetadata,
  Kms,
  OID4VPHolder,
  OID4VPHolderBuilder,
  ReqwestHttpClient,
  VCFormat,
} from "../../";
import { AUTH_REQUEST, VC, VC_TYPE } from "./fixtures";
import { createDidAndKeyMetadata } from "../utils";

describe("OID4VP Holder: ", () => {
  const mockServer = getLocal();

  let kms: Kms;
  let vault: InMemVault;
  let holder: OID4VPHolder;

  let keyMetadata: KeyMetadata;
  let credential: Credential;
  let metadata: CredentialMetadata;

  beforeEach(async () => {
    await mockServer.start(9001);
    kms = new InMemKms();
    vault = new InMemVault();
    holder = await new OID4VPHolderBuilder(kms, vault, "client_id")
      .withHttpClient(ReqwestHttpClient.insecure())
      .build();

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

    await holder.presentCredentialsAuto(new AuthorizationRequest(AUTH_REQUEST), {
      claimsToExclude: { "Identity-1": ["$.name"] },
    });

    expect(token.split("~").length).toEqual(2);
  });
});
