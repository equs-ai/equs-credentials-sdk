import { KeyHandle, KeyType, Kms } from "../..";
import { WrappedKeyHandle } from "./keyHandle";

class WrappedKms {
  constructor(private readonly kms: Kms) {
    this.create = this.create.bind(this);
    this.get = this.get.bind(this);
    this.getByPublicKey = this.getByPublicKey.bind(this);
    if (kms.decrypt) {
      this.decrypt = this.decrypt.bind(this);
    }
  }

  async create(kt: KeyType): Promise<string> {
    return await this.kms.create(kt);
  }

  async get(kid: string): Promise<KeyHandle> {
    const keyHandle = await this.kms.get(kid);
    return new WrappedKeyHandle(keyHandle);
  }

  async getByPublicKey(pk: Uint8Array): Promise<KeyHandle> {
    const keyHandle = await this.kms.getByPublicKey(pk);
    return new WrappedKeyHandle(keyHandle);
  }

  async decrypt(jwe: string): null | Promise<Record<string, any>> {
    if (this.kms.decrypt) {
      return this.kms.decrypt(jwe);
    } else {
      return null;
    }
  }
}

export function contextEnsuredKms(kms: Kms): Kms {
  return new WrappedKms(kms);
}
