import { AskarKms, AskarStorage, KeyMethod } from "../index";
import { Alg, KeyType } from "@equstng/agent-sdk";

describe("Askar KMS: ", () => {
  let kms: AskarKms;
  let storage: AskarStorage;

  beforeAll(async () => {
    storage = await AskarStorage.create(
      {
        dbUrl: "sqlite://:memory:",
        keyMethod: KeyMethod.DeriveKey,
        passKey: "test_key",
        profile: "test",
      },
      false,
    );
    await storage.createProfile("test_profile");
    kms = new AskarKms(storage, "test_profile");
  }, 10000);

  afterAll(async () => {
    await storage.close();
  });

  test("generate and get Key", async () => {
    const cases = [
      { type_: KeyType.P256, alg: Alg.ES256 },
      { type_: KeyType.Ed25519, alg: Alg.EdDSA },
    ];
    for (const test_case of cases) {
      const kid = await kms.create(test_case.type_);
      const key = await kms.get(kid);

      expect(key.alg).toEqual(test_case.alg);
      expect(key.jwk).toBeDefined();
      expect(key.pubKey).toBeDefined();

      const byPubKey = await kms.getByPublicKey(Uint8Array.from(key.pubKey));
      expect(key).toEqual(byPubKey);
    }
  });

  test("sign and verify", async () => {
    const keyTypes = [KeyType.P256, KeyType.Ed25519];
    for (const keyType of keyTypes) {
      const kid = await kms.create(keyType);
      const key = await kms.get(kid);

      const encoder = new TextEncoder();
      const msg = encoder.encode("message");
      const signature = await key.sign(msg);
      const verified = await key.verify(msg, signature);

      expect(verified).toBeUndefined();
    }
  });
});
