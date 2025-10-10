import { getLocal } from "mockttp";
import {
  CredentialExtraVerification,
  DIDKey,
  InMemKms,
  InMemVault,
  IssuerDiscovery,
  KeyMetadata,
  KeyType,
  OID4VCIHolderBuilder,
  ProofOfPossessionMetadataBuilder,
  ProofOfPossessionNotBefore,
  ReqwestHttpClient,
  resolveMetadata,
  UniversalDIDResolver,
  VCFormat,
} from "agent-sdk";
import { Utils } from "./fixtures";

describe("OID4VCI Holder: ", () => {
  const mockServer = getLocal();
  const port = 9000;
  const utils = new Utils({ issuerUrlPort: port });

  beforeAll(async () => {
    await mockServer.start(port);
  });

  beforeEach(async () => {
    mockServer.reset();
    await mockServer.forGet("/.well-known/openid-credential-issuer").thenJson(200, utils.issuerMetadata);
    await mockServer.forGet("/auth/.well-known/openid-configuration").thenJson(200, utils.authServerMetadata);
  });

  afterAll(async () => {
    await mockServer.stop();
  });

  it("retrieve Issuer Metadata", async () => {
    const vciHolder = await buildHolder(utils);

    const issuerMetadata = vciHolder.getIssuerMetadata();

    expect(issuerMetadata).toMatchObject(utils.issuerMetadata);
  });

  it("authorize using auth code", async () => {
    await mockServer.forPost("/auth/par/request").thenJson(201, utils.codeResponse);
    await mockServer.forPost("/auth/token").thenJson(200, utils.accessTokenResponse);

    const vciHolder = await buildHolder(utils);

    const token_response = await vciHolder.authzCodeFlowWithScope(utils.scope, async (url) => {
      expect(url).toEqual(
        `http://localhost:${utils.issuerEndpointPort}/auth?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Acode&client_id=client_id`,
      );

      return "code";
    });

    expect(token_response).toEqual(utils.accessTokenResponse);
  });

  it("get access token by using resolved credential offer with pre-authorized code grant", async () => {
    await mockServer.forPost("/auth/token").thenJson(200, utils.accessTokenResponse);

    const vciHolder = await buildHolder(utils);

    const token_response = await vciHolder.getAccessToken(
      utils.credOfferWithPreAuthGrant,
      async (authorization_flow) => {
        expect(authorization_flow.type).toEqual("preauthorized");
        return "code";
      },
    );

    expect(token_response).toEqual(utils.accessTokenResponse);
  });

  it("get access token by using resolved credential offer with authorization code grant", async () => {
    await mockServer.forPost("/auth/par/request").thenJson(201, utils.codeResponse);
    await mockServer.forPost("/auth/token").thenJson(200, utils.accessTokenResponse);

    const vciHolder = await buildHolder(utils);

    const token_response = await vciHolder.getAccessToken(utils.credOfferWithAuthGrant, async (authorization_flow) => {
      expect(authorization_flow.type).toEqual("authorize");
      expect(authorization_flow["url"]).toBeDefined();
      return "code";
    });

    expect(token_response).toEqual(utils.accessTokenResponse);
  });

  it("request Credential", async () => {
    await mockServer.forPost("/credential").thenJson(200, utils.credResponse);
    await mockServer.forPost("/nonce").thenJson(201, utils.nonceResponse);

    const kms = new InMemKms();
    const vciHolder = await buildHolder(utils, kms);
    const { keyMetadata } = await createDidAndKeyMetadata(kms);

    const cred_response = await vciHolder.requestCredential(utils.accessToken, utils.credDefId, [keyMetadata]);

    expect(cred_response).toMatchObject({
      data: {
        credentials: [
          {
            format: VCFormat.SdJwtVc,
            payload: utils.sdJWTCreds,
          },
        ],
        notification_id: "1111",
      },
    });
  });

  it("request multiple Credentials - Batch issuance", async () => {
    await mockServer.forPost("/credential").thenJson(200, utils.batchCredResponse);
    await mockServer.forPost("/nonce").thenJson(201, utils.nonceResponse);

    const kms = new InMemKms();
    const vciHolder = await buildHolder(utils, kms);
    const didAndKeyMetadata1 = await createDidAndKeyMetadata(kms);
    const didAndKeyMetadata2 = await createDidAndKeyMetadata(kms);

    const cred_response = await vciHolder.requestCredential(utils.accessToken, utils.credDefId, [
      didAndKeyMetadata1.keyMetadata,
      didAndKeyMetadata2.keyMetadata,
    ]);

    expect(cred_response).toMatchObject({
      data: {
        credentials: [
          {
            format: VCFormat.SdJwtVc,
            payload: utils.sdJWTCreds,
          },
          {
            format: VCFormat.SdJwtVc,
            payload: utils.sdJWTCreds,
          },
        ],
        notification_id: "1111",
      },
    });
  });

  it("verifies Issued Credential extra", async () => {
    const vault = new InMemVault();
    const kms = new InMemKms();
    const vciHolder = await buildHolder(utils, kms, vault);

    const credential = {
      format: VCFormat.SdJwtVc,
      payload: utils.sdJWTCreds,
    };

    try {
      await vciHolder.verifyCredentialExtra(credential);
    } catch (e) {
      console.log(e);
    }
  });

  it("store Credential", async () => {
    const vault = new InMemVault();
    const kms = new InMemKms();
    const vciHolder = await buildHolder(utils, kms, vault);

    const credential = {
      format: VCFormat.SdJwtVc,
      payload: utils.sdJWTCreds,
    };

    const keyMetadata: KeyMetadata = {
      kid: "1",
      didUrl:
        "did:key:zDnaenpntCkXnDCnaDk62LxNqPc4CMd32fbhiVsZV5KpPTG2c#zDnaenpntCkXnDCnaDk62LxNqPc4CMd32fbhiVsZV5KpPTG2c",
    };

    const metadata = await resolveMetadata(credential, keyMetadata);

    await vciHolder.storeCredential(credential, metadata);

    const criteria = ["$.vct"];
    const credentialEntries = await vault.findCredentials(criteria);

    expect(credentialEntries).toEqual([{ credential, kid: keyMetadata.kid, id: credentialEntries[0].id }]);
  });
});

async function buildHolder(utils: Utils, kms = new InMemKms(), vault = new InMemVault()) {
  return await new OID4VCIHolderBuilder(
    kms,
    vault,
    "client_id",
    IssuerDiscovery.fromOffer(utils.credOffer),
    ReqwestHttpClient.insecure(),
  )
    .withPop(
      new ProofOfPossessionMetadataBuilder()
        .withLifetime(300)
        .withNotBefore(ProofOfPossessionNotBefore.leeway(10))
        .build(),
    )
    .withCredentialExtraVerification([CredentialExtraVerification.CredentialIssuerIdentifier])
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
    didUrl: vm.id,
    kid: keyId,
  };

  return { did, keyMetadata };
}
