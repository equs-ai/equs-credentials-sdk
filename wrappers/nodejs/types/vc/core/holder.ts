import {
  _VcCoreHolder,
  Credential,
  CredentialEntry,
  CredentialMetadata,
  CredentialOffer,
  CredentialRequest,
  CredentialsFindResult,
  DelegationParams,
  HolderBinder,
  HolderMetadata,
  KeyMetadata,
  Kms,
  Presentation,
  PresentationInput,
  ReqwestHttpClient,
  VCStatus,
  Vault,
} from "../../..";
import { UniversalDIDResolver } from "../../did";
import { contextEnsuredKms, contextEnsuredVault } from "../../utils";

export class VcCoreHolder {
  private readonly inner: _VcCoreHolder;

  constructor(
    kms: Kms,
    vault: Vault,
    metadata: HolderMetadata,
    didResolver: UniversalDIDResolver,
    httpClient: ReqwestHttpClient,
  ) {
    this.inner = new _VcCoreHolder(
      contextEnsuredKms(kms),
      contextEnsuredVault(vault),
      metadata,
      didResolver.inner,
      httpClient,
    );
  }

  async requestCredential(
    credentialOffer: CredentialOffer,
    nonce: string | null | undefined,
    keyMetadata: KeyMetadata,
  ): Promise<CredentialRequest> {
    return this.inner.requestCredential(credentialOffer, nonce, keyMetadata);
  }

  async storeCredential(credential: Credential, metadata: CredentialMetadata): Promise<string> {
    return this.inner.storeCredential(credential, metadata);
  }

  async verifyCredential(credential: Credential): Promise<void> {
    return this.inner.verifyCredential(credential);
  }

  async createPresentationAuto(
    holderBinder: HolderBinder | null | undefined,
    presentationInput: PresentationInput,
  ): Promise<Presentation> {
    return this.inner.createPresentationAuto(holderBinder, presentationInput);
  }

  async findVcsForPresentation(presentationInput: PresentationInput): Promise<CredentialsFindResult> {
    return this.inner.findVcsForPresentation(presentationInput);
  }

  async createPresentation(
    holderBinder: HolderBinder | null | undefined,
    presentationInput: PresentationInput,
    credential: CredentialEntry,
  ): Promise<Presentation> {
    return this.inner.createPresentation(holderBinder, presentationInput, credential);
  }

  async getCredentialStatus(credential: Credential): Promise<VCStatus | null> {
    return this.inner.getCredentialStatus(credential);
  }

  async createDelegatedCredential(credentialEntry: CredentialEntry, params: DelegationParams): Promise<string> {
    return this.inner.createDelegatedCredential(credentialEntry, params);
  }
}
