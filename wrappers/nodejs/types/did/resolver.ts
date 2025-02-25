import { _UniversalDIDResolver, DIDResolution, DIDResolver, DIDVerificationMethod } from "../..";

export class UniversalDIDResolver implements _UniversalDIDResolver {
  private readonly inner: _UniversalDIDResolver;

  constructor() {
    this.inner = new _UniversalDIDResolver();
  }

  async resolveVerificationMethod(did: string): Promise<DIDVerificationMethod> {
    return await this.inner.resolveVerificationMethod(did);
  }

  async resolve(did: string): Promise<DIDResolution> {
    return await this.inner.resolve(did);
  }

  addResolver(didResolver: DIDResolver): void {
    didResolver.resolveRepresentation = didResolver.resolveRepresentation.bind(didResolver);
    this.inner.addResolver(didResolver);
  }
}
