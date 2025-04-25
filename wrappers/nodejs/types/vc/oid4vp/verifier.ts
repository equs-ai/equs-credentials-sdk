import {
  buildVpVerifier,
  ClientMetadata,
  contextEnsuredKms,
  contextEnsuredNonceHandler,
  HttpClient,
  KeyMetadata,
  Kms,
  NonceHandler,
  OID4VPVerifier,
} from "../../../";

export class OID4VPVerifierBuilder {
  private readonly kms: Kms;
  private readonly nonceHandler: NonceHandler;
  private readonly keyMetadata: KeyMetadata;
  private readonly clientId: string;
  private clientMetadata?: ClientMetadata;
  private httpClient?: HttpClient;

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

  withHttpClient(httpClient: HttpClient): this {
    this.httpClient = httpClient;
    return this;
  }

  async build(): Promise<OID4VPVerifier> {
    return await buildVpVerifier(
      contextEnsuredKms(this.kms),
      contextEnsuredNonceHandler(this.nonceHandler),
      this.keyMetadata,
      this.clientId,
      this.clientMetadata,
      this.httpClient,
    );
  }
}
