import { NonceHandler, NonceHandlerTestHelper } from "../";

describe("Nonce: ", () => {
  const NONCE = "nOnce";

  function mockNonceGenerator() {
    return new MockNonceHandler(NONCE);
  }

  class MockNonceHandler implements NonceHandler {
    constructor(private readonly nonce: string) {
      this.generate = this.generate.bind(this);
      this.validate = this.validate.bind(this);
    }

    async generate(): Promise<string> {
      return this.nonce;
    }

    async validate(nonce: string): Promise<boolean> {
      return true;
    }
  }

  test("generate Nonce", async () => {
    const nonceGenerator = new NonceHandlerTestHelper(mockNonceGenerator());
    const nonce = await nonceGenerator.generate();
    expect(nonce).toEqual("nOnce");
  });
});
