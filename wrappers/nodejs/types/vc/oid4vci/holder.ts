import {
  buildVciHolder,
  contextEnsuredKms,
  contextEnsuredVault,
  Duration,
  JsIssuerDiscovery,
  Kms,
  OID4VCIHolder,
  ProofOfPossessionMetadata,
  ProofOfPossessionNotBefore,
  ProofOfPossessionNotBeforeStrategy,
  ReqwestHttpClient,
  Vault,
} from "../../..";

export class OID4VCIHolderBuilder {
  private redirectUrl?: string;
  private pop: ProofOfPossessionMetadata;

  constructor(
    private readonly kms: Kms,
    private readonly vault: Vault,
    private readonly clientId: string,
    private readonly issuerDiscovery: JsIssuerDiscovery,
    private readonly httpClient: ReqwestHttpClient,
  ) {}

  withRedirectUrl(redirectUrl: string): this {
    this.redirectUrl = redirectUrl;
    return this;
  }

  withPop(pop: ProofOfPossessionMetadata): this {
    this.pop = pop;
    return this;
  }

  async build(): Promise<OID4VCIHolder> {
    return await buildVciHolder(
      contextEnsuredKms(this.kms),
      contextEnsuredVault(this.vault),
      this.clientId,
      this.issuerDiscovery,
      this.redirectUrl,
      this.httpClient,
      this.pop,
    );
  }
}
