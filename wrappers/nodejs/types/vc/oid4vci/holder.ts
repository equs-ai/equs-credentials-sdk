import {
  buildVciHolder,
  contextEnsuredKms,
  contextEnsuredVault,
  HttpClient,
  JsIssuerDiscovery,
  Kms,
  OID4VCIHolder,
  Vault,
} from "../../..";

export class OID4VCIHolderBuilder {
  private readonly kms: Kms;
  private readonly vault: Vault;
  private readonly clientId: string;
  private readonly issuerDiscovery: JsIssuerDiscovery;
  private redirectUrl?: string;
  private httpClient?: HttpClient;

  constructor(kms: Kms, vault: Vault, clientId: string, issuerDiscovery: JsIssuerDiscovery) {
    this.kms = kms;
    this.vault = vault;
    this.clientId = clientId;
    this.issuerDiscovery = issuerDiscovery;
  }

  withRedirectUrl(redirectUrl: string): this {
    this.redirectUrl = redirectUrl;
    return this;
  }

  withHttpClient(httpClient: HttpClient): this {
    this.httpClient = httpClient;
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
      undefined,
    );
  }
}
