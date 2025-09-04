import { KeyHandle, KeyType, Kms } from "../../binary";
import { MockKeyHandle } from "./mockKeyHandle";

export class MockKms implements Kms {
  constructor(
    private readonly expectedKeyType: KeyType,
    private readonly kid: string,
    private readonly keyHandle: MockKeyHandle,
  ) {
    this.create = this.create.bind(this);
    this.get = this.get.bind(this);
    this.getByPublicKey = this.getByPublicKey.bind(this);
  }

  async create(kt: KeyType): Promise<string> {
    expect(kt).toBe(KeyType.P256);
    return this.kid;
  }

  async get(kid: string): Promise<KeyHandle> {
    expect(kid).toContain("P256");
    return this.keyHandle;
  }

  async getByPublicKey(pk: Uint8Array): Promise<KeyHandle> {
    expect(pk).toHaveBeenCalledWith(expect.any(Uint8Array));
    return this.keyHandle;
  }
}
