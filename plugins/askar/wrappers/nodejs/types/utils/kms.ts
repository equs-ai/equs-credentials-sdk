import {
  AskarStorage,
  InternalAskarKms,
  KeyType as AskarKeyType,
} from "../../binary";
import { KeyHandle, KeyType, Kms } from "@equstng/agent-sdk";
import { ASDKKeyHandle } from "./keyHandle";

export class AskarKms implements Kms {
  private readonly internalKms: InternalAskarKms;
  constructor(private readonly storage: AskarStorage) {
    this.internalKms = new InternalAskarKms(this.storage);
  }

  async create(kt: KeyType): Promise<string> {
    const keyType = this.convertKeyTypeToAskarKeyType(kt);
    return await this.internalKms.create(keyType);
  }

  async get(kid: string): Promise<KeyHandle> {
    const keyHandle = await this.internalKms.get(kid);
    return new ASDKKeyHandle(keyHandle);
  }

  async getByPublicKey(pk: Array<number>): Promise<KeyHandle> {
    const keyHandle = await this.internalKms.getByPublicKey(pk);
    return new ASDKKeyHandle(keyHandle);
  }

  async closeKms(): Promise<void> {
    return await this.internalKms.closeKms();
  }

  private convertKeyTypeToAskarKeyType(keyType: KeyType): AskarKeyType {
    switch (keyType) {
      case KeyType.Ed25519:
        return AskarKeyType.Ed25519;
      case KeyType.P256:
        return AskarKeyType.P256;
    }
  }
}
