import { KeyHandle, KeyType, Kms } from "agent-sdk";
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

  async get(_kid: string): Promise<KeyHandle> {
    return this.keyHandle;
  }

  async getByPublicKey(_pk: Uint8Array): Promise<KeyHandle> {
    return this.keyHandle;
  }
}
