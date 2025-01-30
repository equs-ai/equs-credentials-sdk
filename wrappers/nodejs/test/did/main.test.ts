import { createUniversalDidResolver, DIDKey, DIDVerificationMethod, inMemKms, KeyHandle, KeyType } from "../../index";
import { Utils } from "./utils";

describe("DID: ", () => {
  let did: string;
  let keyHandle: KeyHandle;
  const utils = new Utils();

  beforeEach(async () => {
    const kms = inMemKms();
    const key = await kms.create(KeyType.Ed25519);
    const nativeKeyHandle = await kms.get(key);
    const didKey = new DIDKey();

    keyHandle = {
      alg: nativeKeyHandle.alg(),
      jwk: nativeKeyHandle.jwk(),
      pubKey: nativeKeyHandle.pubKey(),
      sign: nativeKeyHandle.sign,
      verify: nativeKeyHandle.verify,
    };

    did = didKey.generate(keyHandle);
  });

  test("Value", async () => {
    expect(did).toEqual(expect.stringContaining("did:key:"));
  });

  describe("Universal Resolver: ", () => {
    const resolver = createUniversalDidResolver();

    test("Resolve verification method", async () => {
      const result = await resolver.resolveVerificationMethod(did);
      expect(result).toEqual(
        expect.objectContaining({
          id: expect.stringContaining("did:key:"),
          controller: expect.stringContaining("did:key:"),
          type: "Multikey",
          publicKeyMultibase: expect.stringMatching("^z[1-9A-HJ-NP-Za-km-z]+$"),
        } as DIDVerificationMethod),
      );
    });

    test("Resolve method", async () => {
      const result = await resolver.resolve(did);
      expect(result).toEqual(utils.didResolution);
    });
  });
});
