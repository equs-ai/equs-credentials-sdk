import {
  buildVpVerifier,
  ClientMetadata,
  KeyMetadata,
  Kms,
  NativeKms,
  NativeNonceGenerator,
  NonceGenerator,
  OID4VPVerifier,
} from "../../../";
import { contextEnsuredKms } from "../../utils";
import { contextEnsuredNonceGenerator } from "../../utils/nonce-generator";

export class OID4VPVerifierBuilder {
  private readonly kms: NativeKms | Kms;
  private readonly nonceGenerator: NativeNonceGenerator | NonceGenerator;
  private readonly keyMetadata: KeyMetadata;
  private readonly clientId: string;
  private clientMetadata?: ClientMetadata;

  constructor(
    kms: NativeKms | Kms,
    nonceGenerator: NativeNonceGenerator | NonceGenerator,
    keyMetadata: KeyMetadata,
    clientId: string,
  ) {
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
