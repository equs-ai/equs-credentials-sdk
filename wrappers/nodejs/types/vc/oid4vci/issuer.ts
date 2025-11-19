import {
  buildVciIssuer,
  contextEnsuredKms,
  contextEnsuredNonceHandler,
  CredentialLifetime,
  Duration,
  KeyMetadata,
  Kms,
  NonceHandler,
  OID4VCIIssuer,
  OID4VCIIssuerMetadata,
  ReqwestHttpClient,
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
  private dedicatedKeys: Map<string, KeyMetadata>;
  private credentialLifetimes: Map<string, CredentialLifetime>;
  private defaultCredentialLifetime?: CredentialLifetime;
  private httpClient: ReqwestHttpClient;

  constructor(kms: Kms, issuerMetadata: OID4VCIIssuerMetadata, keyMetadata: KeyMetadata) {
    this.kms = kms;
    this.issuerMetadata = issuerMetadata;
    this.keyMetadata = keyMetadata;
    this.dedicatedKeys = new Map();
    this.credentialLifetimes = new Map();
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
    this.dedicatedKeys.set(credentialConfigurationId, keyMetadata);
    return this;
  }

  withCredentialLifetime(credentialConfigurationId: string, lifetime: CredentialLifetime): this {
    this.credentialLifetimes.set(credentialConfigurationId, lifetime);
    return this;
  }

  withDefaultCredentialLifetime(lifetime: CredentialLifetime): this {
    this.defaultCredentialLifetime = lifetime;
    return this;
  }

  withHttpClient(httpClient: ReqwestHttpClient): this {
    this.httpClient = httpClient;
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
      Object.fromEntries(this.dedicatedKeys.entries()),
      this.defaultCredentialLifetime,
      Object.fromEntries(this.credentialLifetimes.entries()),
      undefined,
      this.httpClient,
    );
  }
}
