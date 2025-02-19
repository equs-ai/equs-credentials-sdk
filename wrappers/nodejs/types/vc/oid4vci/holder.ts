import {
  buildVciHolder,
  contextEnsuredKms,
  contextEnsuredVault,
  JsIssuerDiscovery,
  Kms,
  NativeKms,
  NativeVault,
  OID4VCIHolder,
  Vault,
} from "../../..";

export class OID4VCIHolderBuilder {
  private readonly kms: NativeKms | Kms;
  private readonly vault: NativeVault | Vault;
  private readonly clientId: string;
  private readonly issuerDiscovery: JsIssuerDiscovery;
  private redirectUrl?: string;

  constructor(kms: NativeKms | Kms, vault: NativeVault | Vault, clientId: string, issuerDiscovery: JsIssuerDiscovery) {
    this.kms = kms;
    this.vault = vault;
    this.clientId = clientId;
    this.issuerDiscovery = issuerDiscovery;
  }

  withRedirectUrl(redirect_url: string): void {
    this.redirectUrl = redirect_url;
  }

  async build(): Promise<OID4VCIHolder> {
    return await buildVciHolder(
      contextEnsuredKms(this.kms),
      contextEnsuredVault(this.vault),
      this.clientId,
      this.issuerDiscovery,
      this.redirectUrl,
    );
  }
}
