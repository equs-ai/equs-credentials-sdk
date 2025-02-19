import {
  buildVpHolder,
  contextEnsuredKms,
  contextEnsuredVault,
  Kms,
  NativeKms,
  NativeVault,
  OID4VPHolder,
  Vault,
  WalletMetadata,
} from "../../..";

export class OID4VPHolderBuilder {
  private readonly kms: NativeKms | Kms;
  private readonly vault: NativeVault | Vault;
  private readonly clientId: string;
  private walletMetadata?: WalletMetadata;

  constructor(kms: NativeKms | Kms, vault: NativeVault | Vault, clientId: string) {
    this.kms = kms;
    this.vault = vault;
    this.clientId = clientId;
  }

  withWalletMetadata(walletMetadata: WalletMetadata): void {
    this.walletMetadata = walletMetadata;
  }

  async build(): Promise<OID4VPHolder> {
    return await buildVpHolder(
      contextEnsuredKms(this.kms),
      contextEnsuredVault(this.vault),
      this.clientId,
      this.walletMetadata,
    );
  }
}
