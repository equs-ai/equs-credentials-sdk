import {
  Alg,
  CredentialDefinition,
  CredentialDefinitionFormat,
  CredentialEntry,
  DelegationParams,
  HolderMetadata,
  InMemKms,
  InMemVault,
  IssuerMetadata,
  ReqwestHttpClient,
  UniversalDIDResolver,
  VcCoreHolder,
  VcCoreIssuer,
  VCFormat,
} from "../../../";
import { createDidAndKeyMetadata } from "../../utils";

const ISSUER_ID = "https://example.issuer.org";
const CRED_DEF_ID = "CRED_DEF_ID";
const VCT = "https://issuer.example/cred_schema";

describe("VcCoreHolder: createDelegatedCredential", () => {
  it("produces a dSD-JWT grant ending with '~' for an SD-JWT entry", async () => {
    const didResolver = new UniversalDIDResolver();
    const httpClient = ReqwestHttpClient.insecure();

    const issuerKms = new InMemKms();
    const { keyMetadata: issuerKeyMetadata } = await createDidAndKeyMetadata(issuerKms);

    const issuerMetadata: IssuerMetadata = {
      issuerId: ISSUER_ID,
      credDefs: [
        {
          credDefId: CRED_DEF_ID,
          format: VCFormat.SdJwtVc,
          claims: {},
          supportedProofs: { Jwt: ["ES256"] },
          supportedSigningAlgs: [Alg.ES256],
          protocolData: {
            format: CredentialDefinitionFormat.SdJwt,
            payload: {
              vct: VCT,
              disclosures: ["$.givenName", "$.familyName"],
            },
          },
          keyMetadata: issuerKeyMetadata,
        } satisfies CredentialDefinition,
      ],
    };

    const issuer = new VcCoreIssuer(issuerKms, issuerMetadata, didResolver);

    const holderKms = new InMemKms();
    const { keyMetadata: holderKeyMetadata } = await createDidAndKeyMetadata(holderKms);

    const holderMetadata: HolderMetadata = {
      clientId: "wallet-dev",
      pop: { lifetime: 300 },
    };
    const holder = new VcCoreHolder(holderKms, new InMemVault(), holderMetadata, didResolver, httpClient);

    const offer = issuer.offerCredential(CRED_DEF_ID);
    const request = await holder.requestCredential(offer, null, holderKeyMetadata);
    const credential = await issuer.issueCredential(request, {
      givenName: "Jane",
      familyName: "Smith",
      birthDate: "1978-07-17",
    });

    const entry: CredentialEntry = {
      credential,
      kid: holderKeyMetadata.kid,
      id: "entry-1",
    };
    const params: DelegationParams = {
      delegatePayloads: [{ scope: "purchase" }],
      binding: "IssuerJwtHash",
    };

    const grant = await holder.createDelegatedCredential(entry, params);

    expect(grant.endsWith("~")).toBe(true);
  });

  it("rejects a CredentialEntry whose credential is not an SD-JWT", async () => {
    const didResolver = new UniversalDIDResolver();
    const httpClient = ReqwestHttpClient.insecure();

    const holderKms = new InMemKms();
    const { keyMetadata: holderKeyMetadata } = await createDidAndKeyMetadata(holderKms);

    const holderMetadata: HolderMetadata = {
      clientId: "wallet-dev",
      pop: { lifetime: 300 },
    };
    const holder = new VcCoreHolder(holderKms, new InMemVault(), holderMetadata, didResolver, httpClient);

    const entry: CredentialEntry = {
      credential: { format: VCFormat.LdpVc, payload: "{}" },
      kid: holderKeyMetadata.kid,
      id: "entry-2",
    };
    const params: DelegationParams = {
      delegatePayloads: [{ scope: "purchase" }],
      binding: "IssuerJwtHash",
    };

    await expect(holder.createDelegatedCredential(entry, params)).rejects.toThrow();
  });
});
