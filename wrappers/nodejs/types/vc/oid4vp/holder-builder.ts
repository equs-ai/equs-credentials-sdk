import {
  buildVpHolder,
  contextEnsuredKms,
  contextEnsuredNonceHandler,
  contextEnsuredVault,
  DIDResolver,
  Duration,
  Kms,
  NonceHandler,
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
  private popLifetime?: Duration;
  private didResolver?: DIDResolver;
  private nonceHandler?: NonceHandler;

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

  withDidResolver(didResolver: DIDResolver): this {
    this.didResolver = didResolver;
    return this;
  }
  /// Sets custom NonceHandler for the holder.
  ///
  /// This NonceHandler is used to generate 'wallet_nonce' and to validate it
  /// during fetching AuthorizationRequest via reference.
  /// Details can be found here: https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#name-request-uri-method-post
  /// If not provided, wallet nonce is not handled
  ///
  /// # Arguments
  ///
  /// * `nonceHandler` - an implementation of NonceHandler interface.
  withNonceHandler(nonceHandler: NonceHandler): this {
    this.nonceHandler = nonceHandler;
    return this;
  }

  withPopLifetime(popLifetime: Duration): this {
    this.popLifetime = popLifetime;
    return this;
  }
  async build(): Promise<OID4VPHolder> {
    const holder = await buildVpHolder(
      contextEnsuredKms(this.kms),
      contextEnsuredVault(this.vault),
      this.clientId,
      this.walletMetadata,
      this.httpClient,
      this.popLifetime,
      this.didResolver,
      this.nonceHandler ? contextEnsuredNonceHandler(this.nonceHandler) : null,
    );
    return new OID4VPHolder(holder);
  }
}
