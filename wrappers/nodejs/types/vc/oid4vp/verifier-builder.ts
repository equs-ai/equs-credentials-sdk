import {
  buildVpVerifier,
  ClientMetadata,
  contextEnsuredKms,
  contextEnsuredNonceHandler,
  DIDResolver,
  KeyMetadata,
  Kms,
  NonceHandler,
  ReqwestHttpClient,
} from "../../../";
import { OID4VPVerifier } from "./verifier";

export class OID4VPVerifierBuilder {
  private readonly kms: Kms;
  private readonly nonceHandler: NonceHandler;
  private readonly keyMetadata: KeyMetadata;
  private readonly clientId: string;
  private clientMetadata?: ClientMetadata;
  private httpClient?: ReqwestHttpClient;
  private didResolver?: DIDResolver;
  private trustedRootCertificates?: Array<Uint8Array>;

  constructor(kms: Kms, NonceHandler: NonceHandler, keyMetadata: KeyMetadata, clientId: string) {
    this.kms = kms;
    this.nonceHandler = NonceHandler;
    this.keyMetadata = keyMetadata;
    this.clientId = clientId;
  }

  withClientMetadata(clientMetadata: ClientMetadata): this {
    this.clientMetadata = clientMetadata;
    return this;
  }

  withHttpClient(httpClient: ReqwestHttpClient): this {
    this.httpClient = httpClient;
    return this;
  }

  withDidResolver(didResolver: DIDResolver): this {
    this.didResolver = didResolver;
    return this;
  }

  addTrustedRootCertificate(pemBytes: Uint8Array): this {
    if (!this.trustedRootCertificates) {
      this.trustedRootCertificates = [];
    }

    this.trustedRootCertificates.push(pemBytes);
    return this;
  }

  async build(): Promise<OID4VPVerifier> {
    const inner = await buildVpVerifier(
      contextEnsuredKms(this.kms),
      contextEnsuredNonceHandler(this.nonceHandler),
      this.keyMetadata,
      this.clientId,
      this.clientMetadata,
      this.httpClient,
      this.didResolver,
      this.trustedRootCertificates,
    );
    return new OID4VPVerifier(inner);
  }
}
