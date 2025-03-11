import {
  buildVpVerifier,
  ClientMetadata,
  contextEnsuredKms,
  contextEnsuredNonceGenerator,
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

  constructor(kms: Kms, nonceGenerator: NonceGenerator, keyMetadata: KeyMetadata, clientId: string) {
    this.kms = kms;
    this.nonceGenerator = nonceGenerator;
    this.keyMetadata = keyMetadata;
    this.clientId = clientId;
  }

  withClientMetadata(clientMetadata: ClientMetadata): void {
    this.clientMetadata = clientMetadata;
  }

  async build(): Promise<OID4VPVerifier> {
    return await buildVpVerifier(
      contextEnsuredKms(this.kms),
      contextEnsuredNonceGenerator(this.nonceGenerator),
      this.keyMetadata,
      this.clientId,
      this.clientMetadata,
    );
  }
}
