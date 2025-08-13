import {
  buildVpHolder,
  contextEnsuredKms,
  contextEnsuredNonceHandler,
  contextEnsuredVault,
  DIDResolver,
  Kms,
  NonceHandler,
  OID4VPHolder,
  ReqwestHttpClient,
  Vault,
  WalletMetadata,
} from "../../..";

export class OID4VPHolderBuilder {
  private walletMetadata?: WalletMetadata;
  private didResolver?: DIDResolver;
  private nonceHandler?: NonceHandler;

  constructor(
    private readonly kms: Kms,
    private readonly vault: Vault,
    private readonly clientId: string,
    private readonly httpClient: ReqwestHttpClient,
  ) {}

  withWalletMetadata(walletMetadata: WalletMetadata): this {
    this.walletMetadata = walletMetadata;
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

  async build(): Promise<OID4VPHolder> {
    const holder = await buildVpHolder(
      contextEnsuredKms(this.kms),
      contextEnsuredVault(this.vault),
      this.clientId,
      this.walletMetadata,
      this.httpClient,
      undefined,
      this.didResolver,
      this.nonceHandler ? contextEnsuredNonceHandler(this.nonceHandler) : null,
    );
    return new OID4VPHolder(holder);
  }
}
