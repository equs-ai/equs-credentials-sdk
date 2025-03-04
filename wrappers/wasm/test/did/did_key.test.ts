import { DIDKey, InMemKms } from "../../pkg";
import { KeyType } from "../../types";

describe("did:key: ", () => {
  test("generate DID", async () => {
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);

    const didKey = new DIDKey();

    let did = didKey.generate(keyHandle);

    expect(did.startsWith("did:key")).toBeTruthy();
  });
});
