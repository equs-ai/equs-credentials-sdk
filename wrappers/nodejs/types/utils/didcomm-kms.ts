import { DIDCommKms, ECDH1PUParams, ECDHESParams, KeyHandle, KeyType } from "../..";
import { WrappedKeyHandle } from "./keyHandle";

class WrappedDIDCommKms implements DIDCommKms {
  constructor(protected readonly kms: DIDCommKms) {
    this.create = this.create.bind(this);
    this.get = this.get.bind(this);
    this.getByPublicKey = this.getByPublicKey.bind(this);
    this.deriveEcdhes = this.deriveEcdhes.bind(this);
    this.deriveEcdh1Pu = this.deriveEcdh1Pu.bind(this);
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

  async deriveEcdhes(params: ECDHESParams): Promise<number[]> {
    return await this.kms.deriveEcdhes(params);
  }

  async deriveEcdh1Pu(params: ECDH1PUParams): Promise<number[]> {
    return await this.kms.deriveEcdh1Pu(params);
  }
}

export function contextEnsuredDIDCommKms(kms: DIDCommKms): DIDCommKms {
  return new WrappedDIDCommKms(kms);
}
