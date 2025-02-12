import { NativeNonceGenerator, wrapJsNonceGenerator } from "../";

describe("Nonce: ", () => {
  test("generate Nonce", async () => {
    const nonceGenerator = createNonceGenerator();

    const nonce = await nonceGenerator.generate();

    expect(nonce).toEqual("nOnce");
  });

  test("generate Nonce with expiration", async () => {
    const nonceGenerator = createNonceGenerator();

    const nonce = await nonceGenerator.withExpiration(3600);

    expect(nonce.nonce).toEqual("nOnce");
    expect(nonce.expiresIn).toEqual(3600);
  });
});

function createNonceGenerator(): NativeNonceGenerator {
  return wrapJsNonceGenerator({
    async generate() {
      return "nOnce";
    },
  });
}
