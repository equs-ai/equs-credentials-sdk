import { DIDKey, InMemKms, KeyType } from "agent-sdk";

describe("did:key: ", () => {
  test("generate DID", async () => {
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);

    const didKey = new DIDKey();

    const did = didKey.generate(keyHandle);

    expect(did.startsWith("did:key")).toBeTruthy();
  });
});
