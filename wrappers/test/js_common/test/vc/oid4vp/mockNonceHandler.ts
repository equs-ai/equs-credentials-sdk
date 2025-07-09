import { NonceHandler } from "agent-sdk";

export class MockNonceHandler implements NonceHandler {
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
