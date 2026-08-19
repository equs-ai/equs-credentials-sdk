import { NonceHandler } from "agent-sdk";

export class MockNonceHandler implements NonceHandler {
  /** The nonces of each `invalidate` call, in call order. */
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
