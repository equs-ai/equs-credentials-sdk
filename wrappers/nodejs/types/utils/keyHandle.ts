import { Alg, KeyHandle } from "../..";

export class WrappedKeyHandle implements KeyHandle {
  constructor(private readonly keyHandle: KeyHandle) {
    this.sign = this.sign.bind(this);
    this.verify = this.verify.bind(this);
  }

  get alg(): Alg {
    return this.keyHandle.alg;
  }

  get jwk(): string | undefined {
    return this.keyHandle.jwk;
  }

  get pubKey(): number[] | undefined {
    return this.keyHandle.pubKey;
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    return await this.keyHandle.sign(payload);
  }

  async verify(data: Uint8Array, signature: Uint8Array): Promise<void> {
    return await this.keyHandle.verify(data, signature);
  }
}
