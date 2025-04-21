import { NonceHandler } from "../..";

class WrappedNonceGenerator {
  constructor(private readonly nonceHandler: NonceHandler) {
    this.generate = this.generate.bind(this);
    this.validate = this.validate.bind(this);
  }

  async generate(): Promise<string> {
    return await this.nonceHandler.generate();
  }

  async validate(nonce: string): Promise<boolean> {
    return await this.nonceHandler.validate(nonce);
  }
}

export function contextEnsuredNonceGenerator(nonceGenerator: NonceHandler): NonceHandler {
  return new WrappedNonceGenerator(nonceGenerator);
}
