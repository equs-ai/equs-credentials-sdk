import { NonceHandler } from "../..";

class WrappedNonceHandler {
  constructor(private readonly nonceHandler: NonceHandler) {
    this.generate = this.generate.bind(this);
    this.validate = this.validate.bind(this);
    this.invalidate = this.invalidate.bind(this);
  }

  async generate(): Promise<string> {
    return await this.nonceHandler.generate();
  }

  async validate(nonce: string): Promise<boolean> {
    return await this.nonceHandler.validate(nonce);
  }

  async invalidate(nonces: Array<string>): Promise<void> {
    return await this.nonceHandler.invalidate(nonces);
  }
}

export function contextEnsuredNonceHandler(nonceGenerator: NonceHandler): NonceHandler {
  return new WrappedNonceHandler(nonceGenerator);
}
