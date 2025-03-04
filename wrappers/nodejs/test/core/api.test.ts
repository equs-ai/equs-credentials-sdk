import {
  createHolder,
  createStatusIssuer,
  createIssuer,
  createVerifier,
  PresentationRestrictionValueType,
  resolveMetadata,
  VcCoreHolder,
  VcCoreIssuer,
  VcCoreVerifier,
  VcCoreStatusIssuer,
  VCStatusesDataFormat,
  HttpClient,
  HttpRequest,
  HttpResponse,
} from "../../";
import { jwtDecode } from "jwt-decode";
import { Utils } from "./utils";

describe("VC::Core", () => {
  const utils = new Utils();
  let statusIssuer: VcCoreStatusIssuer;
  let issuer: VcCoreIssuer;
  let holder: VcCoreHolder;

  beforeEach(async () => {
    statusIssuer = createStatusIssuer(utils.kms, await utils.getStatusIssuerMetadata());
    issuer = createIssuer(utils.kms, await utils.getIssuerMetadata());
    holder = createHolder(utils.kms, utils.vault, { clientId: "wallet-dev" });
  });

  describe("StatusIssuer", () => {
    it("issue status list", async () => {
      const result = await statusIssuer.issueStatusList("test_status_list", {
        format: VCStatusesDataFormat.StatusListToken,
        payload: {
          statuses: {
            "2": 1, // 'INVALID' (1) status for the VC with index 2
          },
        },
      });

      const decoded = jwtDecode(result.payload.jwt);

      expect(decoded).toMatchObject({
        sub: "http://localhost/status_list",
        status_list: { lst: "eNpjYWBgAAAAFAAF", bits: 1 },
      });
      expect(decoded.iat).toBeDefined();
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
      expect(decoded).toMatchObject({ status: { status_list: { idx: 1, uri: "http://example.com/status_list" } } });
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
            value: {
              type: PresentationRestrictionValueType.String,
              value: temp_store_map,
            },
            optional: false,
          },
          {
            fields: ["$.surname"],
            optional: false,
          },
        ],
      });
      expect(result[0].credential.payload).toBeDefined();
    });

    it("create presentation auto", async () => {
      await requestAndStoreCredential(holder, issuer, utils);
      const result = await holder.createPresentationAuto(utils.nonce, utils.verifierId, utils.presentationInput);
      const decoded = jwtDecode<typeof utils.claims>(result.payload);

      expect(decoded).toMatchObject({ address: "221B Baker Street", date: "09/09/1989" });
    });

    it("create presentation", async () => {
      await requestAndStoreCredential(holder, issuer, utils);
      const credentialEntry = await holder.findVcsForPresentation(utils.presentationInput);

      const result = await holder.createPresentation(
        utils.nonce,
        utils.verifierId,
        utils.presentationInput,
        credentialEntry[0],
      );
      const decoded = jwtDecode<typeof utils.claims>(result.payload);

      expect(decoded).toMatchObject({ address: "221B Baker Street", date: "09/09/1989" });
    });
  });

  describe("Verifier", () => {
    let verifier: VcCoreVerifier;
    beforeEach(async () => {
      verifier = createVerifier(utils.verifierId);
    });

    it("verify presentation and VC status", async () => {
      await requestAndStoreCredential(holder, issuer, utils);

      const presentation = await holder.createPresentationAuto(utils.nonce, utils.verifierId, utils.presentationInput);

      const result = await verifier.verifyPresentation(utils.nonce, presentation);

      expect(result).toMatchObject({
        address: "221B Baker Street",
        date: "09/09/1989",
        vct: "https://credentials.example.com/identity_credential",
        surname: "Doe",
      });

      const client: HttpClient = {
        asyncCall: async (_: HttpRequest): Promise<HttpResponse> => {
          // status list is generated with all indexes with status value 'VALID'
          // except the value for index 2 which is 'INVALID'
          const status_list_jwt =
            "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZXV4SHU2R3VGWUE0QVIxcWZiRkpLQUMxVmlHRVBnTTFmV0NTRDJETEVObmVBI3pEbmFldXhIdTZHdUZZQTRBUjFxZmJGSktBQzFWaUdFUGdNMWZXQ1NEMkRMRU5uZUEifQ.eyJzdGF0dXNfbGlzdCI6eyJiaXRzIjoxLCJsc3QiOiJlTnBqWVdCZ0FBQUFGQUFGIn0sInN1YiI6Imh0dHA6Ly9leGFtcGxlLmNvbS9zdGF0dXNfbGlzdCIsImlhdCI6MTczOTIxMTcxNSwiX3NkX2FsZyI6InNoYS0yNTYifQ.rkJzhn4WEUHAbxcrNl4VWDee8UV5tTLMGvqEVGC60H-NmWI-4F-lj8p4aImHwyW5B8iEN5myfp8mcLliFVeuNA~";

          return {
            statusCode: 200,
            body: status_list_jwt,
            headers: { "content-type": "application/statuslist+jwt" },
          };
        },
      };

      const vc_status = await verifier.obtainCredentialStatus(presentation, client);
      expect(vc_status).toMatchObject({ payload: { status: "VALID" } });
    });
  });
});

async function requestAndStoreCredential(holder: VcCoreHolder, issuer: VcCoreIssuer, utils: Utils): Promise<void> {
  const keyMetadata = await utils.getKeyMetadata();
  const offer = issuer.offerCredential(utils.scope);
  const credentialRequest = await holder.requestCredential(offer, utils.nonce, keyMetadata);
  const credential = await issuer.issueCredential(credentialRequest, utils.claims, utils.nonce, utils.credStatusInfo);
  const metadata = await resolveMetadata(credential, keyMetadata);
  await holder.storeCredential(credential, metadata);
}
