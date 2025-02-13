import { Alg as AskarAlg, InternalAskarKeyHandle } from "../../binary";
import { Alg, KeyHandle } from "@equstng/agent-sdk";

export class ASDKKeyHandle implements KeyHandle {
  constructor(private readonly innerKeyHandle: InternalAskarKeyHandle) {}

  get alg(): Alg {
    const alg = this.innerKeyHandle.alg;
    switch (alg) {
      case AskarAlg.EdDSA:
        return Alg.EdDSA;
      case AskarAlg.ES256:
        return Alg.ES256;
      default:
        throw new Error("Unsupported algorithm");
    }
  }

  get jwk(): string | undefined {
    return this.innerKeyHandle.jwk ?? undefined;
  }

  get pubKey(): number[] {
    return this.innerKeyHandle.pubKey;
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    return await this.innerKeyHandle.sign(payload);
  }

  async verify(data: Uint8Array, signature: Uint8Array): Promise<void> {
    return await this.innerKeyHandle.verify(data, signature);
  }
}
