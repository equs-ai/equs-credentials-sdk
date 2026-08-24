import {
  Alg,
  CredentialDefinitionFormat,
  DIDKey,
  InMemKms,
  InMemVault,
  KeyType,
  ProofOfPossessionNotBefore,
  ReqwestHttpClient,
  UniversalDIDResolver,
  VcCoreHolder,
  VcCoreIssuer,
  VCFormat,
} from "equs-sdk";
import { jwtDecode } from "jwt-decode";

const NONCE = "pop_nbf_test_nonce";
const SCOPE = "pop_nbf_test_cred";

async function createKeyMetadata(kms: InMemKms) {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);
  const did = new DIDKey().generate(keyHandle);
  const vm = await new UniversalDIDResolver().resolveVerificationMethod(did);
  return { didUrl: vm.id, kid: keyId };
}

async function buildFixtures() {
  const kms = new InMemKms();
  const vault = new InMemVault();
  const resolver = new UniversalDIDResolver();
  const issuerKeyMetadata = await createKeyMetadata(kms);

  const issuer = new VcCoreIssuer(
    kms,
    {
      issuerId: "https://example.com",
      credDefs: [
        {
          credDefId: SCOPE,
          format: VCFormat.SdJwtVc,
          claims: {},
          supportedProofs: { Jwt: ["ES256"] },
          supportedSigningAlgs: [Alg.ES256],
          display: undefined,
          protocolData: {
            format: CredentialDefinitionFormat.SdJwt,
            payload: {
              vct: "https://example.com/test_cred",
              disclosures: [],
              lifetime: 3600 * 1000,
            },
          },
          keyMetadata: issuerKeyMetadata,
        },
      ],
      protocolData: undefined,
    },
    resolver,
  );

  const holderKeyMetadata = await createKeyMetadata(kms);
  const offer = issuer.offerCredential(SCOPE, undefined);

  return { kms, vault, resolver, holderKeyMetadata, offer };
}

type PopPayload = { iat: number; nbf: number };

describe("ProofOfPossessionNotBefore strategies", () => {
  it("AsIssuedAt: nbf equals iat", async () => {
    const { kms, vault, resolver, holderKeyMetadata, offer } = await buildFixtures();

    const holder = new VcCoreHolder(
      kms,
      vault,
      { clientId: "test-client", pop: { lifetime: 300, notBefore: ProofOfPossessionNotBefore.asIssuedAt() } },
      resolver,
      ReqwestHttpClient.insecure(),
    );

    const credReq = await holder.requestCredential(offer, NONCE, holderKeyMetadata);
    const { iat, nbf } = jwtDecode<PopPayload>(credReq.proof.proof);

    expect(nbf).toBe(iat);
  });

  it("Delay: nbf equals iat plus delay seconds", async () => {
    const delaySecs = 60;
    const { kms, vault, resolver, holderKeyMetadata, offer } = await buildFixtures();

    const holder = new VcCoreHolder(
      kms,
      vault,
      { clientId: "test-client", pop: { lifetime: 300, notBefore: ProofOfPossessionNotBefore.delay(delaySecs) } },
      resolver,
      ReqwestHttpClient.insecure(),
    );

    const credReq = await holder.requestCredential(offer, NONCE, holderKeyMetadata);
    const { iat, nbf } = jwtDecode<PopPayload>(credReq.proof.proof);

    expect(nbf).toBe(iat + delaySecs);
  });

  it("Leeway: nbf equals iat minus leeway seconds", async () => {
    const leewaySecs = 30;
    const { kms, vault, resolver, holderKeyMetadata, offer } = await buildFixtures();

    const holder = new VcCoreHolder(
      kms,
      vault,
      { clientId: "test-client", pop: { lifetime: 300, notBefore: ProofOfPossessionNotBefore.leeway(leewaySecs) } },
      resolver,
      ReqwestHttpClient.insecure(),
    );

    const credReq = await holder.requestCredential(offer, NONCE, holderKeyMetadata);
    const { iat, nbf } = jwtDecode<PopPayload>(credReq.proof.proof);

    expect(nbf).toBe(iat - leewaySecs);
  });

  it("Fixed: nbf equals the provided fixed timestamp in seconds", async () => {
    const fixedDate = new Date("2030-01-01T00:00:00.000Z");
    const fixedSec = Math.floor(fixedDate.getTime() / 1000);
    const { kms, vault, resolver, holderKeyMetadata, offer } = await buildFixtures();

    const holder = new VcCoreHolder(
      kms,
      vault,
      { clientId: "test-client", pop: { lifetime: 300, notBefore: ProofOfPossessionNotBefore.fixed(fixedDate) } },
      resolver,
      ReqwestHttpClient.insecure(),
    );

    const credReq = await holder.requestCredential(offer, NONCE, holderKeyMetadata);
    const { nbf } = jwtDecode<PopPayload>(credReq.proof.proof);

    expect(nbf).toBe(fixedSec);
  });
});
