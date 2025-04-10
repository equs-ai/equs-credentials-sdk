import {
  buildVciIssuer,
  contextEnsuredKms,
  contextEnsuredNonceGenerator,
  Duration,
  KeyMetadata,
  Kms,
  NonceGenerator,
  OID4VCIIssuer,
  OID4VCIIssuerMetadata,
  TokenValidation,
  TokenValidationEnum,
} from "../../..";

export class OID4VCIIssuerBuilder {
  private readonly kms: Kms;
  private readonly nonceGenerator: NonceGenerator;
  private readonly issuerMetadata: OID4VCIIssuerMetadata;
  private readonly keyMetadata: KeyMetadata;
  private tokenValidation?: TokenValidation;
  private clockSkew?: Duration;
  private dedicatedKeys: Record<string, KeyMetadata>;

  constructor(
    kms: Kms,
    nonceGenerator: NonceGenerator,
    issuerMetadata: OID4VCIIssuerMetadata,
    keyMetadata: KeyMetadata,
  ) {
    this.kms = kms;
    this.nonceGenerator = nonceGenerator;
    this.issuerMetadata = issuerMetadata;
    this.keyMetadata = keyMetadata;
    this.dedicatedKeys = {};
  }

  tokenValidationIntrospect(url: string, header?: string | undefined): this {
    this.tokenValidation = {
      type: TokenValidationEnum.Introspect,
      url,
      header,
    };
    return this;
  }

  tokenValidationJwks(url: string): this {
    this.tokenValidation = { type: TokenValidationEnum.Jwks, url };
    return this;
  }

  withClockSkew(duration: number): this {
    this.clockSkew = { seconds: duration, nanoseconds: 0 };
    return this;
  }

  withDedicatedKeyMetadata(credentialConfigurationId: string, keyMetadata: KeyMetadata): this {
    this.dedicatedKeys = {
      [credentialConfigurationId]: keyMetadata,
    };
    return this;
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
