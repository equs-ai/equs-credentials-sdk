import { NonceHandler, NonceHandlerTestHelper } from "../";

describe("Nonce: ", () => {
  const NONCE = "nOnce";

  function mockNonceGenerator() {
    return new MockNonceHandler(NONCE);
  }

  class MockNonceHandler implements NonceHandler {
    readonly invalidated: Array<Array<string>> = [];

    constructor(private readonly nonce: string) {
      this.generate = this.generate.bind(this);
      this.validate = this.validate.bind(this);
      this.invalidate = this.invalidate.bind(this);
    }

    async generate(): Promise<string> {
      return this.nonce;
    }

    async validate(nonce: string): Promise<boolean> {
      return true;
    }

    async invalidate(nonces: Array<string>): Promise<void> {
      this.invalidated.push(nonces);
    }
  }

  it("generate Nonce", async () => {
    const nonceGenerator = new NonceHandlerTestHelper(mockNonceGenerator());
    const nonce = await nonceGenerator.generate();
    expect(nonce).toEqual("nOnce");
  });

  it("invalidate Nonce hands every nonce to the handler", async () => {
    const handler = mockNonceGenerator();
    const nonceGenerator = new NonceHandlerTestHelper(handler);

    await nonceGenerator.invalidate([NONCE, "other"]);

    expect(handler.invalidated).toEqual([[NONCE, "other"]]);
  });
});
