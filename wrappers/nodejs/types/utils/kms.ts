import { KeyHandle, KeyType, Kms, NativeKms } from "../../binary";

class WrappedKms {
  constructor(private readonly kms: Kms) {
    this.create = this.create.bind(this);
    this.get = this.get.bind(this);
    this.getByPublicKey = this.getByPublicKey.bind(this);
  }

  async create(kt: KeyType): Promise<string> {
    return await this.kms.create(kt);
  }

  async get(kid: string): Promise<KeyHandle> {
    return await this.kms.get(kid);
  }

  async getByPublicKey(pk: Array<number>): Promise<KeyHandle> {
    return await this.kms.getByPublicKey(pk);
  }
}

export function contextEnsuredKms(kms: NativeKms | Kms): NativeKms | Kms {
  return kms instanceof NativeKms ? kms : new WrappedKms(kms);
}
