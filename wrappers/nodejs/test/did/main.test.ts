import { DIDKey, DIDVerificationMethod, InMemKms, KeyHandle, KeyType, UniversalDIDResolver } from "../../";
import { Utils } from "./utils";
import { MockDID } from "./custom";

describe("DID: ", () => {
  let did: string;
  let keyHandle: KeyHandle;
  const utils = new Utils();

  beforeEach(async () => {
    const kms = new InMemKms();
    const key = await kms.create(KeyType.Ed25519);
    const nativeKeyHandle = await kms.get(key);
    const didKey = new DIDKey();

    keyHandle = {
      alg: nativeKeyHandle.alg,
      jwk: nativeKeyHandle.jwk,
      pubKey: nativeKeyHandle.pubKey,
      sign: nativeKeyHandle.sign,
      verify: nativeKeyHandle.verify,
    };

    did = didKey.generate(keyHandle);
  });

  it("Value", async () => {
    expect(did).toEqual(expect.stringContaining("did:key:"));
  });

  describe("Custom Resolver: ", () => {
    it("Success flow", async () => {
      const resolver = new UniversalDIDResolver();
      resolver.addResolver(new MockDID("mock"));
      resolver.addResolver(new MockDID("anothermock"));
      const result1 = await resolver.resolve("did:mock:12345");
      const result2 = await resolver.resolve("did:anothermock:456789");
      expect(result1.document).toEqual(utils.mockDidResolution("mock"));
      expect(result2.document).toEqual(utils.mockDidResolution("anothermock"));
    });

    it("Multiple addition of same method", async () => {
      try {
        const customResolver = new MockDID("mock");
        const resolver = new UniversalDIDResolver();
        resolver.addResolver(customResolver);
        resolver.addResolver(customResolver);
      } catch (error) {
        expect(error.toString()).toBe("Error: Method already exists: mock");
        return;
      }
      throw new Error("Custom Resolver: Multiple addition of same method failed to resolve collision of method names");
    });
  });
});
