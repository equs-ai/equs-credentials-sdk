import { NonceGenerator } from "../..";

class WrappedNonceGenerator {
  constructor(private readonly nonceGenerator: NonceGenerator) {
    this.generate = this.generate.bind(this);
  }

  async generate(): Promise<string> {
    return await this.nonceGenerator.generate();
  }
}

export function contextEnsuredNonceGenerator(nonceGenerator: NonceGenerator): NonceGenerator {
  return new WrappedNonceGenerator(nonceGenerator);
}
