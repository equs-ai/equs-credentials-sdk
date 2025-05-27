import {
  buildVpHolder,
  contextEnsuredKms,
  contextEnsuredVault,
  Kms,
  OID4VPHolder,
  ReqwestHttpClient,
  Vault,
  WalletMetadata,
} from "../../..";

export class OID4VPHolderBuilder {
  private readonly kms: Kms;
  private readonly vault: Vault;
  private readonly clientId: string;
  private walletMetadata?: WalletMetadata;
  private httpClient?: ReqwestHttpClient;

  constructor(kms: Kms, vault: Vault, clientId: string) {
    this.kms = kms;
    this.vault = vault;
    this.clientId = clientId;
  }

  withWalletMetadata(walletMetadata: WalletMetadata): this {
    this.walletMetadata = walletMetadata;
    return this;
  }

  withHttpClient(client: ReqwestHttpClient): this {
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
