import { _UniversalDIDResolver, DIDResolution, DIDResolver, DIDVerificationMethod, ReqwestHttpClient } from "../..";

export class UniversalDIDResolver implements _UniversalDIDResolver {
  private readonly inner: _UniversalDIDResolver;

  constructor(params?: { inner?: _UniversalDIDResolver }) {
    this.inner = params?.inner ?? new _UniversalDIDResolver();
  }

  static withHttpClient(httpClient: ReqwestHttpClient): UniversalDIDResolver {
    return new UniversalDIDResolver({ inner: _UniversalDIDResolver.withHttpClient(httpClient) });
  }

  async resolveVerificationMethod(did: string): Promise<DIDVerificationMethod> {
    return await this.inner.resolveVerificationMethod(did);
  }

  async resolve(did: string): Promise<DIDResolution> {
    return await this.inner.resolve(did);
  }

  addResolver(resolver: DIDResolver): void {
    resolver.resolveRepresentation = resolver.resolveRepresentation.bind(resolver);
    this.inner.addResolver(resolver);
  }
}
