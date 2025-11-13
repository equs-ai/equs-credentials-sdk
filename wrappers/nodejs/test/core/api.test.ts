import {
  _UniversalDIDResolver,
  Alg,
  createHolder,
  createIssuer,
  createStatusIssuer,
  createVerifier,
  CredentialEntry,
  HolderBinder,
  HttpClient,
  HttpRequest,
  HttpResponse,
  KeyType,
  OID4VCIStatusIssuerBuilder,
  PresentationRestrictionValue,
  ReqwestHttpClient,
  resolveMetadata,
  VcCoreHolder,
  VcCoreIssuer,
  VcCoreStatusIssuer,
  VcCoreVerifier,
  VCStatusesDataFormat,
} from "../../";
import { jwtDecode } from "jwt-decode";
import { Utils } from "./utils";
import { MockKeyHandle } from "./mockKeyHandle";
import { MockKms } from "./mockKms";
import { getLocal } from "mockttp";

describe("VC::Core", () => {
  const mockServer = getLocal();
  const port = 9001;

  const utils = new Utils();
  let statusIssuer: VcCoreStatusIssuer;
  let issuer: VcCoreIssuer;
  let holder: VcCoreHolder;

  beforeAll(async () => {
    await mockServer.start(port);
  });

  beforeEach(async () => {
    statusIssuer = createStatusIssuer(utils.kms, await utils.getStatusIssuerMetadata());
    issuer = createIssuer(utils.kms, await utils.getIssuerMetadata(), new _UniversalDIDResolver());
    holder = createHolder(
      utils.kms,
      utils.vault,
      {
        clientId: "wallet-dev",
        pop: {
          lifetime: 300,
        },
      },
      new _UniversalDIDResolver(),
      ReqwestHttpClient.insecure(),
    );

    const statusList = await statusIssuer.issueStatusList("test_status_list", {
      format: VCStatusesDataFormat.StatusListToken,
      payload: {
        statuses: {
          "1": 0, // 'Valid' (0) status for the VC with index 1
        },
      },
    });
    await mockServer
      .forGet("/status_list")
      .thenReply(200, statusList.payload.jwt, { "content-type": "application/statuslist+jwt" });
  });

  describe("StatusIssuer", () => {
    it("issue status list", async () => {
      const result = await statusIssuer.issueStatusList("test_status_list", {
        format: VCStatusesDataFormat.StatusListToken,
        payload: {
          statuses: {
            "1": 0, // 'VALID' (0) status for the VC with index 1
            "2": 1, // 'INVALID' (1)
            "3": 2, // 'SUSPENDED' (2)
            "4": 3, // 'APPSPECIFIC' (3)
          },
        },
      });

      const decoded = jwtDecode(result.payload.jwt);

      expect(decoded).toMatchObject({
        sub: "http://localhost:9001/status_list",
        status_list: { lst: "eNqbwMwABgAEnQCU", bits: 2 },
      });
      expect(decoded.iat).toBeDefined();
    });
  });

  describe("StatusIssuerBuilder", () => {
    it("test status issuer builder", async () => {
      const payload = Uint8Array.from(Buffer.from("cmF3X3Rlc3RfdmFsdWU=", "base64"));
      const signature = Uint8Array.from(Buffer.from("ZW5jcnlwdGVkX3Rlc3RfdmFsdWU=", "base64"));
      const publicKey = Array.from(
        Buffer.from("huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg", "base64"),
      );
      const jwk = JSON.stringify({
        crv: "P-256",
        kid: "618d228e-4767-4aa2-8683-c35c86d7025c",
        kty: "EC",
        x: "huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs",
        y: "4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg",
      });

      let kms = new MockKms(
        KeyType.P256,
        "some_string",
        new MockKeyHandle(Alg.ES256, payload, signature, publicKey, jwk),
      );
      let metadata = await utils.getStatusIssuerMetadata();
      let statusIssuerFromBuilder = new OID4VCIStatusIssuerBuilder(kms, metadata).build();
      const result = await statusIssuerFromBuilder.issueStatusList("test_status_list", {
        format: VCStatusesDataFormat.StatusListToken,
        payload: {
          statuses: {
            "2": 1, // 'INVALID' (1) status for the VC with index 2
          },
        },
      });
      expect(result).toMatchObject({ format: 0, payload: { jwt: expect.any(String) } });
    });
  });

  describe("Issuer", () => {
    it("issue credential", async () => {
      const result = await issuer.issueCredential(
        {
          credDefId: utils.scope,
          protocolData: undefined,
          credOfferId: undefined,
          proof: {
            format: "jwt",
            proof:
              "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVxTnJnR1RBV3FVVlNVRnFvWFh3bjhONThVc2JLRVpDeUUyWlk5ZFRHS3B3cyN6RG5hZXFOcmdHVEFXcVVWU1VGcW9YWHduOE41OFVzYktFWkN5RTJaWTlkVEdLcHdzIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QifQ.eyJhdWQiOiJodHRwczovL2lzc3Vlci1iYWNrZW5kLmNvbSIsIm5iZiI6MTczNTkwMTAzNCwiaWF0IjoxNzM1OTAxMDM0LCJleHAiOjY2MTQ4NTE1MTQsIm5vbmNlIjoiS0I1MFZPbTlJLWtQTFQ5bUFBQ1Y4ZyJ9.2flsRA_XKGFm4JBpvRHkV3QKLMo81OawQHL1YQdwVRo3OnZeugQJevWz8q-_lD-fo6U9_z_KuLNt9tQr_5A5Iw",
          },
        },
        utils.claims,
        utils.nonce,
        utils.credStatusInfo,
      );

      const decoded = jwtDecode<typeof utils.claims>(result.payload);

      expect(decoded).toMatchObject({ date: "09/09/1989", address: "221B Baker Street" });
      expect(decoded).toMatchObject({ status: { status_list: { idx: 1, uri: "http://localhost:9001/status_list" } } });
    });

    it("offer credential", async () => {
      const result = issuer.offerCredential(utils.scope, undefined);

      expect(result).toMatchObject({
        issuerId: "https://issuer-backend.com",
        credDefId: utils.scope,
        content: {
          payload: {
            cred_def_id: utils.scope,
            format: "SdJwtVc",
            claims: {},
          },
        },
      });
    });
  });

  describe("Holder", () => {
    it("request credential", async () => {
      const result = await holder.requestCredential(
        await utils.getCredentialOffer(),
        utils.nonce,
        await utils.getKeyMetadata(),
      );

      expect(result.proof.proof).toBeDefined();
    });

    it("store credential", async () => {
      const keyMetadata = await utils.getKeyMetadata();
      const credentialRequest = await holder.requestCredential(
        await utils.getCredentialOffer(),
        utils.nonce,
        keyMetadata,
      );
      const credential = await issuer.issueCredential(
        credentialRequest,
        utils.claims,
        utils.nonce,
        utils.credStatusInfo,
      );
      const metadata = await resolveMetadata(credential, keyMetadata);
      const result = await holder.storeCredential(credential, metadata);
      expect(result).toBeDefined();
    });

    it("verify credential", async () => {
      const credentialRequest = await holder.requestCredential(
        await utils.getCredentialOffer(),
        utils.nonce,
        await utils.getKeyMetadata(),
      );
      const credential = await issuer.issueCredential(
        credentialRequest,
        utils.claims,
        utils.nonce,
        utils.credStatusInfo,
      );
      const result = await holder.verifyCredential(credential);
      expect(result).toBeUndefined();
    });

    it("find vcs for presentation", async () => {
      const keyMetadata = await utils.getKeyMetadata();
      const temp_store_map = "https://credentials.example.com/identity_credential";
      const credentialRequest = await holder.requestCredential(
        await utils.getCredentialOffer(),
        utils.nonce,
        keyMetadata,
      );
      const credential = await issuer.issueCredential(
        credentialRequest,
        utils.claims,
        utils.nonce,
        utils.credStatusInfo,
      );
      const metadata = await resolveMetadata(credential, keyMetadata);
      await holder.storeCredential(credential, { ...metadata, type: temp_store_map });

      const result = await holder.findVcsForPresentation({
        ...utils.presentationInput,
        restrictions: [
          {
            fields: ["$.vct"],
            value: PresentationRestrictionValue.withString(temp_store_map),
            optional: false,
          },
          {
            fields: ["$.surname"],
            optional: false,
          },
        ],
      });
      expect((result.data[0] as CredentialEntry).credential?.payload).toBeDefined();
    });

    it("create presentation auto", async () => {
      await requestAndStoreCredential(holder, issuer, utils);
      const holder_binder: HolderBinder = {
        nonce: utils.nonce,
        verifierId: utils.verifierId,
      };
      const result = await holder.createPresentationAuto(holder_binder, utils.presentationInput);
      const decoded = jwtDecode<typeof utils.claims>(result.payload);

      expect(decoded).toMatchObject({ address: "221B Baker Street", date: "09/09/1989" });
    });

    it("create presentation", async () => {
      await requestAndStoreCredential(holder, issuer, utils);
      const credentialEntry = await holder.findVcsForPresentation(utils.presentationInput);
      const holder_binder: HolderBinder = {
        nonce: utils.nonce,
        verifierId: utils.verifierId,
      };
      const result = await holder.createPresentation(
        holder_binder,
        utils.presentationInput,
        credentialEntry.data[0] as CredentialEntry,
      );
      const decoded = jwtDecode<typeof utils.claims>(result.payload);

      expect(decoded).toMatchObject({ address: "221B Baker Street", date: "09/09/1989" });
    });
  });

  describe("Verifier", () => {
    let verifier: VcCoreVerifier;
    beforeEach(async () => {
      verifier = createVerifier(utils.verifierId, new _UniversalDIDResolver());
    });

    it.each([
      [1, "VALID", null],
      [2, "INVALID", null],
      [3, "SUSPENDED", null],
      [4, "APPSPECIFIC", 3],
    ])("verify presentation and VC status", async (statusListIdx: number, status: string, value?: number) => {
      await utils.truncateVault();
      await requestAndStoreCredential(holder, issuer, utils, statusListIdx);

      const holder_binder: HolderBinder = {
        nonce: utils.nonce,
        verifierId: utils.verifierId,
      };
      const presentation = await holder.createPresentationAuto(holder_binder, utils.presentationInput);

      const result = await verifier.verifyPresentation(holder_binder, presentation, ReqwestHttpClient.insecure());

      expect(result).toMatchObject({
        address: "221B Baker Street",
        date: "09/09/1989",
        vct: "https://credentials.example.com/identity_credential",
        surname: "Doe",
      });

      const client: HttpClient = {
        asyncCall: async (_: HttpRequest): Promise<HttpResponse> => {
          // Status list is generated with the following statuses (token index - status):
          // 1 - VALID
          // 2 - INVALID
          // 3 - SUSPENDED
          // 4 - APPSPECIFIC (value - 3)
          const status_list_jwt =
            "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZVp4QmJlVFdBYlhOcXlHZER4dDJXRTZjbzNteHU0VllEOHlieXlkdjhkQnh4I3pEbmFlWnhCYmVUV0FiWE5xeUdkRHh0MldFNmNvM214dTRWWUQ4eWJ5eWR2OGRCeHgifQ.eyJzdGF0dXNfbGlzdCI6eyJsc3QiOiJlTnFid013QUJnQUVuUUNVIiwiYml0cyI6Mn0sInN1YiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9zdGF0dXNfbGlzdCIsImlhdCI6MTc2MzAyNTYyMywiX3NkX2FsZyI6InNoYS0yNTYifQ.lCOpC_53MXw4mShUwGtLbxh3Ha-qFNiRohPTZWo2XyCkBVSWn2daxEjSXM048p2DN8LAo61fcgAA69BGvcf5WQ~";

          return {
            statusCode: 200,
            body: status_list_jwt,
            headers: { "content-type": "application/statuslist+jwt" },
          };
        },
      };

      const vc_status = await verifier.obtainCredentialStatus(presentation, client);
      if (value) {
        expect(vc_status).toMatchObject({ payload: { status, value } });
      } else {
        expect(vc_status).toMatchObject({ payload: { status } });
      }
    });
  });
});

async function requestAndStoreCredential(
  holder: VcCoreHolder,
  issuer: VcCoreIssuer,
  utils: Utils,
  statusListIdx: number = 1,
): Promise<void> {
  const keyMetadata = await utils.getKeyMetadata();
  const offer = issuer.offerCredential(utils.scope);
  const credentialRequest = await holder.requestCredential(offer, utils.nonce, keyMetadata);
  let statusInfo = utils.credStatusInfo;
  statusInfo.payload.idx = statusListIdx;
  const credential = await issuer.issueCredential(credentialRequest, utils.claims, utils.nonce, statusInfo);
  const metadata = await resolveMetadata(credential, keyMetadata);
  await holder.storeCredential(credential, metadata);
}
