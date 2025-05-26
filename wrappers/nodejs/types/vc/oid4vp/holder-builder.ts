import {
  buildVpHolder,
  contextEnsuredKms,
  contextEnsuredVault,
  HttpClient,
  Kms,
  OID4VPHolder,
  Vault,
  WalletMetadata,
} from "../../..";

export class OID4VPHolderBuilder {
  private readonly kms: Kms;
  private readonly vault: Vault;
  private readonly clientId: string;
  private walletMetadata?: WalletMetadata;
  private httpClient?: HttpClient;

  constructor(kms: Kms, vault: Vault, clientId: string) {
    this.kms = kms;
    this.vault = vault;
    this.clientId = clientId;
  }

  withWalletMetadata(walletMetadata: WalletMetadata): this {
    this.walletMetadata = walletMetadata;
    return this;
  }

  withHttpClient(client: HttpClient): this {
    this.httpClient = client;
    return this;
  }

  async build(): Promise<OID4VPHolder> {
    const holder = await buildVpHolder(
      contextEnsuredKms(this.kms),
      contextEnsuredVault(this.vault),
      this.clientId,
      this.walletMetadata,
      this.httpClient,
      undefined,
    );
    return new OID4VPHolder(holder);
  }
}
