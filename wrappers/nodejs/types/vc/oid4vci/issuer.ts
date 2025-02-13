import {
  buildVciIssuer,
  Duration,
  KeyMetadata,
  Kms,
  NativeKms,
  NativeNonceGenerator,
  NonceGenerator,
  OID4VCIIssuer,
  OID4VCIIssuerMetadata,
  TokenValidation,
  TokenValidationEnum,
} from "../../../";
import { contextEnsuredKms } from "../../utils";
import { contextEnsuredNonceGenerator } from "../../utils/nonce-generator";

export class OID4VCIIssuerBuilder {
  private readonly kms: NativeKms | Kms;
  private readonly nonceGenerator: NativeNonceGenerator | NonceGenerator;
  private readonly issuerMetadata: OID4VCIIssuerMetadata;
  private readonly keyMetadata: KeyMetadata;
  private tokenValidation?: TokenValidation;
  private clockSkew?: Duration;
  private dedicatedKeys: Record<string, KeyMetadata>;

  constructor(
    kms: NativeKms | Kms,
    nonceGenerator: NativeNonceGenerator | NonceGenerator,
    issuerMetadata: OID4VCIIssuerMetadata,
    keyMetadata: KeyMetadata,
  ) {
    this.kms = kms;
    this.nonceGenerator = nonceGenerator;
    this.issuerMetadata = issuerMetadata;
    this.keyMetadata = keyMetadata;
    this.dedicatedKeys = {};
  }

  tokenValidationIntrospect(url: string, header?: string | undefined): void {
    this.tokenValidation = { type: TokenValidationEnum.Introspect, url, header };
  }

  tokenValidationJwks(url: string): void {
    this.tokenValidation = { type: TokenValidationEnum.Jwks, url };
  }

  withClockSkew(duration: number): void {
    this.clockSkew = { seconds: duration, nanoseconds: 0 };
  }

  withDedicatedKeyMetadata(credentialConfigurationId: string, keyMetadata: KeyMetadata): void {
    this.dedicatedKeys = {
      [credentialConfigurationId]: keyMetadata,
    };
  }

  async build(): Promise<OID4VCIIssuer> {
    return await buildVciIssuer(
      contextEnsuredKms(this.kms),
      contextEnsuredNonceGenerator(this.nonceGenerator),
      this.issuerMetadata,
      this.keyMetadata,
      this.tokenValidation,
      this.clockSkew,
      this.dedicatedKeys || {},
    );
  }
}
