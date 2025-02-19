import { NativeNonceGenerator, NonceGenerator } from "../..";

class WrappedNonceGenerator {
  constructor(private readonly nonceGenerator: NonceGenerator) {
    this.generate = this.generate.bind(this);
  }

  async generate(): Promise<string> {
    return await this.nonceGenerator.generate();
  }
}

export function contextEnsuredNonceGenerator(
  nonceGenerator: NativeNonceGenerator | NonceGenerator,
): NativeNonceGenerator | NonceGenerator {
  return nonceGenerator instanceof NativeNonceGenerator ? nonceGenerator : new WrappedNonceGenerator(nonceGenerator);
}
