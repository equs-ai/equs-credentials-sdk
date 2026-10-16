import {
  _VcCoreIssuer,
  Claims,
  Credential,
  CredentialOffer,
  CredentialOfferData,
  CredentialRequest,
  CredentialStatusInfo,
  IssuerMetadata,
  Kms,
  UnsignedCredential,
} from "../../..";
import { UniversalDIDResolver } from "../../did";
import { contextEnsuredKms } from "../../utils";

export class VcCoreIssuer {
  private readonly inner: _VcCoreIssuer;

  constructor(kms: Kms, metadata: IssuerMetadata, didResolver: UniversalDIDResolver) {
    this.inner = new _VcCoreIssuer(contextEnsuredKms(kms), metadata, didResolver.inner);
  }

  offerCredential(credDefId: string, protocolData?: CredentialOfferData | null): CredentialOffer {
    return this.inner.offerCredential(credDefId, protocolData);
  }

  async issueCredential(
    credentialRequest: CredentialRequest,
    claims: Claims,
    nonce?: string | null,
    statusInfo?: CredentialStatusInfo | null,
  ): Promise<Credential> {
    return this.inner.issueCredential(credentialRequest, claims, nonce, statusInfo);
  }

  async prepareCredential(
    credentialRequest: CredentialRequest,
    claims: Claims,
    nonce?: string | null,
    statusInfo?: CredentialStatusInfo | null,
  ): Promise<UnsignedCredential> {
    return this.inner.prepareCredential(credentialRequest, claims, nonce, statusInfo);
  }
}
