import { InMemKms } from "../../pkg";
import { Alg, KeyType } from "../../types";

describe("InMemKMS: ", () => {
  test("Sign and Verify", async () => {
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);
    const keyHandleByPublicKey = await kms.getByPublicKey(keyHandle.pubKey);

    expect(keyHandleByPublicKey.alg).toEqual(Alg.ES256);
    expect(keyHandleByPublicKey.jwk).toEqual(keyHandle.jwk);

    const text = "example text";
    const text_bytes = Buffer.from(text, "utf-8");

    const signature = await keyHandle.sign(text_bytes);

    await keyHandle.verify(text_bytes, signature);
  });
});
