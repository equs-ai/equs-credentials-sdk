import {
  buildVpVerifier,
  ClientMetadata,
  contextEnsuredKms,
  contextEnsuredNonceGenerator,
  HttpClient,
  KeyMetadata,
  Kms,
  NonceGenerator,
  OID4VPVerifier,
} from "../../../";

export class OID4VPVerifierBuilder {
  private readonly kms: Kms;
  private readonly nonceGenerator: NonceGenerator;
  private readonly keyMetadata: KeyMetadata;
  private readonly clientId: string;
  private clientMetadata?: ClientMetadata;
  private httpClient?: HttpClient;

  constructor(kms: Kms, nonceGenerator: NonceGenerator, keyMetadata: KeyMetadata, clientId: string) {
    this.kms = kms;
    this.nonceGenerator = nonceGenerator;
    this.keyMetadata = keyMetadata;
    this.clientId = clientId;
  }

  withClientMetadata(clientMetadata: ClientMetadata): void {
    this.clientMetadata = clientMetadata;
  }

  withHttpClient(httpClient: HttpClient): void {
    this.httpClient = httpClient;
  }

  async build(): Promise<OID4VPVerifier> {
    return await buildVpVerifier(
      contextEnsuredKms(this.kms),
      contextEnsuredNonceGenerator(this.nonceGenerator),
      this.keyMetadata,
      this.clientId,
      this.clientMetadata,
      this.httpClient,
    );
  }
}
