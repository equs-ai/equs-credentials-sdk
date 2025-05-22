import {
  buildVciIssuer,
  contextEnsuredKms,
  contextEnsuredNonceHandler,
  Duration,
  KeyMetadata,
  Kms,
  NonceHandler,
  OID4VCIIssuer,
  OID4VCIIssuerMetadata,
  TokenValidation,
  TokenValidationEnum,
} from "../../..";

export class OID4VCIIssuerBuilder {
  private readonly kms: Kms;
  private readonly issuerMetadata: OID4VCIIssuerMetadata;
  private readonly keyMetadata: KeyMetadata;
  private nonceHandler?: NonceHandler;
  private tokenValidation?: TokenValidation;
  private clockSkew?: Duration;
  private dedicatedKeys: Record<string, KeyMetadata>;
  private credentialLifetimes: Record<string, Duration>;
  private defaultCredentialLifetime?: Duration;

  constructor(kms: Kms, issuerMetadata: OID4VCIIssuerMetadata, keyMetadata: KeyMetadata) {
    this.kms = kms;
    this.issuerMetadata = issuerMetadata;
    this.keyMetadata = keyMetadata;
    this.dedicatedKeys = {};
    this.credentialLifetimes = {};
  }

  withNonceHandler(nonceHandler: NonceHandler): this {
    this.nonceHandler = nonceHandler;
    return this;
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

  withCredentialLifetime(credentialConfigurationId: string, duration: number): this {
    this.credentialLifetimes = {
      [credentialConfigurationId]: { seconds: duration, nanoseconds: 0 },
    };

    return this;
  }

  withDefaultCredentialLifetime(duration: number): this {
    this.defaultCredentialLifetime = { seconds: duration, nanoseconds: 0 };

    return this;
  }

  async build(): Promise<OID4VCIIssuer> {
    return await buildVciIssuer(
      contextEnsuredKms(this.kms),
      this.nonceHandler ? contextEnsuredNonceHandler(this.nonceHandler) : null,
      this.issuerMetadata,
      this.keyMetadata,
      this.tokenValidation,
      this.clockSkew,
      this.dedicatedKeys || {},
      this.defaultCredentialLifetime,
      this.credentialLifetimes,
    );
  }
}
