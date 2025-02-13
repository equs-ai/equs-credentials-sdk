import { Credential, CredentialEntry, CredentialMetadata, NativeVault, Vault } from "../../binary";

class WrappedVault implements Vault {
  constructor(private readonly vault: Vault) {
    this.storeCredential = this.storeCredential.bind(this);
    this.deleteCredential = this.deleteCredential.bind(this);
    this.findCredentials = this.findCredentials.bind(this);
    this.getCredential = this.getCredential.bind(this);
    this.getCredentials = this.getCredentials.bind(this);
    this.findCredentials = this.findCredentials.bind(this);
  }

  async storeCredential(credential: Credential, metadata: CredentialMetadata): Promise<string> {
    return await this.vault.storeCredential(credential, metadata);
  }

  async deleteCredential(id: string): Promise<void> {
    return await this.vault.deleteCredential(id);
  }

  async findCredentials(criteria: Array<string>): Promise<Array<CredentialEntry>> {
    return await this.vault.findCredentials(criteria);
  }

  async getCredential(id: string): Promise<CredentialEntry | null> {
    return await this.vault.getCredential(id);
  }

  async getCredentials(): Promise<Array<CredentialEntry>> {
    return await this.vault.getCredentials();
  }
}

export function contextEnsuredVault(vault: NativeVault | Vault): NativeVault | Vault {
  return vault instanceof NativeVault ? vault : new WrappedVault(vault);
}
