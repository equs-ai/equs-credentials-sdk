import { DIDKey, InMemKms, KeyType } from "agent-sdk";

describe("did:key: ", () => {
  test("generate DID with InMem KeyHandle", async () => {
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);

    const didKey = new DIDKey();

    const did = didKey.generate(keyHandle);

    expect(did.startsWith("did:key")).toBeTruthy();
  });

  test("generate DID with NOT an instance of InMem KeyHandle", async () => {
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);

    const didKey = new DIDKey();

    const did = didKey.generate({
      alg: keyHandle.alg,
      jwk: keyHandle.jwk,
      sign(payload: Uint8Array): Promise<Uint8Array> {
        return keyHandle.sign(payload);
      },
      verify(data: Uint8Array, signature: Uint8Array): Promise<void> {
        return keyHandle.verify(data, signature);
      },
    });

    expect(did.startsWith("did:key")).toBeTruthy();
  });
});
