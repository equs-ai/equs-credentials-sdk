import { NonceGenerator, NonceGeneratorTestHelper } from "../";

describe("Nonce: ", () => {
  const NONCE = "nOnce";

  function mockNonceGenerator() {
    return new MockNonceGenerator(NONCE);
  }

  class MockNonceGenerator implements NonceGenerator {
    constructor(private readonly nonce: string) {
      this.generate = this.generate.bind(this);
    }

    async generate(): Promise<string> {
      return this.nonce;
    }
  }

  test("generate Nonce", async () => {
    const nonceGenerator = new NonceGeneratorTestHelper(mockNonceGenerator());
    const nonce = await nonceGenerator.generate();
    expect(nonce).toEqual("nOnce");
  });
});
