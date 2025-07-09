import { Alg, KeyHandle } from "../../binary";

export class MockKeyHandle implements KeyHandle {
  readonly pubKey: KeyHandle["pubKey"];

  constructor(
    readonly alg: Alg,
    private readonly expected_payload: Uint8Array,
    private readonly expected_signature: Uint8Array,
    pubKey?: number[] | Uint8Array,
    readonly jwk?: string,
  ) {
    this.pubKey = pubKey as KeyHandle["pubKey"];
    this.sign = this.sign.bind(this);
    this.verify = this.verify.bind(this);
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    return this.expected_signature;
  }

  async verify(data: Uint8Array, signature: Uint8Array): Promise<void> {}
}
