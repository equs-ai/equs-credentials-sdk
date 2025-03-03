import {
  ACCESS_TOKEN,
  ACCESS_TOKEN_RESPONSE,
  AUTH_SERVER_METADATA,
  CODE_RESPONSE,
  CRED_DEF_ID,
  CRED_OFFER,
  CRED_OFFER_WITH_AUTH_GRANT,
  CRED_OFFER_WITH_PRE_AUTH_GRANT,
  CRED_RESPONSE,
  ISSUER_METADATA,
  SCOPE,
  SD_JWT_CREDS,
} from "./fixtures";
import {getLocal} from "mockttp";
import {
  HttpClient,
  InMemKms,
  InMemVault,
  KeyMetadata,
  resolveMetadata,
  VCFormat,
  IssuerDiscovery,
  OID4VCIHolderBuilder, KeyType, DIDKey, UniversalDIDResolver,
} from "agent-sdk";

describe("OID4VCI Holder: ", () => {
  const mockServer = getLocal();
  mockServer.start(9000);

  beforeEach(async () => {
    mockServer.reset();
    await mockServer.forGet("/.well-known/openid-credential-issuer").thenJson(200, ISSUER_METADATA);
    await mockServer.forGet("/auth/.well-known/openid-configuration").thenJson(200, AUTH_SERVER_METADATA);
  });

  afterAll(async () => await mockServer.stop());

  test("retrieve Issuer Metadata", async () => {
    const vciHolder = await buildHolder();

    const issuerMetadata = vciHolder.getIssuerMetadata();

    expect(issuerMetadata).toMatchObject(ISSUER_METADATA);
  });

  test("authorize using auth code", async () => {
    await mockServer.forPost("/auth/par/request").thenJson(201, CODE_RESPONSE);
    await mockServer.forPost("/auth/token").thenJson(200, ACCESS_TOKEN_RESPONSE);

    const vciHolder = await buildHolder();

    const token_response = await vciHolder.authzCodeFlowWithScope(SCOPE, async (url) => {
      expect(url).toEqual("http://localhost:9000/auth?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Acode&client_id=client_id")

      return "code"
    });

    expect(token_response).toEqual(ACCESS_TOKEN_RESPONSE);
  });

  test("get access token by using resolved credential offer with pre-authorized code grant", async () => {
    await mockServer.forPost("/auth/token").thenJson(200, ACCESS_TOKEN_RESPONSE);

    const vciHolder = await buildHolder();

    const token_response = await vciHolder.getAccessToken(
      CRED_OFFER_WITH_PRE_AUTH_GRANT,
      async (authorization_flow) => {
        expect(authorization_flow.type).toEqual("preauthorized");
        return "code";
      },
    );

    expect(token_response).toEqual(ACCESS_TOKEN_RESPONSE);
  });

  test("get access token by using resolved credential offer with authorization code grant", async () => {
    await mockServer.forPost("/auth/par/request").thenJson(201, CODE_RESPONSE);
    await mockServer.forPost("/auth/token").thenJson(200, ACCESS_TOKEN_RESPONSE);

    const vciHolder = await buildHolder();

    const token_response = await vciHolder.getAccessToken(CRED_OFFER_WITH_AUTH_GRANT, async (authorization_flow) => {
      expect(authorization_flow.type).toEqual("authorize");
      expect(authorization_flow["url"]).toBeDefined();
      return "code";
    });

    expect(token_response).toEqual(ACCESS_TOKEN_RESPONSE);
  });

  test("request Credential", async () => {
    // todo fix test with removing native kms
    // return;
    await mockServer.forPost("/credential").thenJson(200, CRED_RESPONSE);

    const kms = new InMemKms();
    const vciHolder = await buildHolder(kms);
    const nonce = {
      value: "KB50VOm9I-kPLT9mAACV8g",
      expires_in: 86400,
      created: 1728732136,
    };
    const {keyMetadata} = await createDidAndKeyMetadata(kms);

    const cred_response = await vciHolder.requestCredential(ACCESS_TOKEN, CRED_DEF_ID, nonce, keyMetadata);

    expect(cred_response).toMatchObject({
      data: {
        credential: {
          format: VCFormat.SdJwtVc,
          payload: SD_JWT_CREDS,
        },
        notification_id: "1111",
      },
      nonce_data: {
        value: "0GtZieAoAL_3Zafyn6TgCA",
        expires_in: 86440,
      },
    });
  });

  test("store Credential", async () => {
    const vault = new InMemVault();
    const kms = new InMemKms();
    const vciHolder = await buildHolder(kms, vault);

    const credential = {
      format: VCFormat.SdJwtVc,
      payload: SD_JWT_CREDS,
    };

    const {keyMetadata} = await createDidAndKeyMetadata(kms);

    const metadata = await resolveMetadata(credential, keyMetadata)

    await vciHolder.storeCredential(credential, metadata);

    const criteria = ["$.vct"];
    const credentialEntries = await vault.findCredentials(criteria);

    expect(credentialEntries).toEqual([{credential, kid: keyMetadata.kid, id: credentialEntries[0].id}]);
  });
});

async function buildHolder(kms = new InMemKms(), vault = new InMemVault()) {
  return await new OID4VCIHolderBuilder(kms, vault, "client_id", IssuerDiscovery.from_offer(CRED_OFFER))
    .withHttpClient(HttpClient.insecure())
    .build();
}

export type DidAndKeyMetadata = {
  did: string;
  keyMetadata: KeyMetadata;
};

export async function createDidAndKeyMetadata(kms: InMemKms): Promise<DidAndKeyMetadata> {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);
  const didKey = new DIDKey();

  const did = didKey.generate(keyHandle);

  const universalDidResolver = new UniversalDIDResolver();

  const vm = await universalDidResolver.resolveVerificationMethod(did);

  const keyMetadata: KeyMetadata = {
    did_url: vm.id,
    kid: keyId,
  };

  return {did, keyMetadata};
}
