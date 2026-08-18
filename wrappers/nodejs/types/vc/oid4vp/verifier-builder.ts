import {
  buildVpVerifier,
  ClientId,
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
  private readonly clientId: ClientId;
  private clientMetadata?: ClientMetadata;
  private httpClient?: ReqwestHttpClient;
  private didResolver?: DIDResolver;
  private trustedRootCertificates?: Array<Uint8Array>;
  private x509CertificateChain?: Uint8Array;

  constructor(kms: Kms, NonceHandler: NonceHandler, keyMetadata: KeyMetadata, clientId: ClientId) {
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

  /**
   * Sets the X.509 certificate chain emitted in the `x5c` header of the signed
   * Authorization Request Object.
   *
   * Required when the verifier's client id has an X.509 prefix; unused with any
   * other prefix. The leaf certificate must derive the configured client id —
   * its Subject Alternative Name for `x509_san_dns:<dns-name>`, its hash for
   * `x509_hash:<hash>` — and must certify the signing key of `keyMetadata`,
   * since the wallet checks the request signature against it. Both are enforced
   * when the request is built.
   *
   * @param {Uint8Array} pemBytes - a PEM-encoded, leaf-first certificate chain.
   */
  withX509CertificateChain(pemBytes: Uint8Array): this {
    this.x509CertificateChain = pemBytes;
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
      this.x509CertificateChain,
    );
    return new OID4VPVerifier(inner);
  }
}
