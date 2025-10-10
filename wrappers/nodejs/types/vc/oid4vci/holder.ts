import {
  buildVciHolder,
  contextEnsuredKms,
  contextEnsuredVault,
  CredentialExtraVerification,
  JsIssuerDiscovery,
  Kms,
  OID4VCIHolder,
  ProofOfPossessionMetadata,
  ReqwestHttpClient,
  Vault,
} from "../../..";

export class OID4VCIHolderBuilder {
  private redirectUrl?: string;
  private pop: ProofOfPossessionMetadata;
  private credentialExtraVerification?: Array<CredentialExtraVerification>;

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

  withCredentialExtraVerification(options: Array<CredentialExtraVerification>): this {
    this.credentialExtraVerification = options;
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
      this.credentialExtraVerification
    );
  }
}
