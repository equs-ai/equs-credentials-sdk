import { VCFormat, Credential, CredentialEntry, CredentialMetadata, Vault, VaultTestHelper } from "equs-credentials-sdk";
import { Fixtures } from "./fixtures";

describe("Vault: ", () => {
  const credentialId = "cred:12345";

  const sdJwt: Credential = {
    format: VCFormat.SdJwtVc,
    payload: Fixtures.SDJWTVCPayload,
  };

  const sdJwtMetadata = {
    type: "vc_type",
    kid: "kid",
    format: VCFormat.SdJwtVc,
    fields: ["$.vct", "$.name"],
  };

  const credentialEntries: Array<CredentialEntry> = [
    {
      credential: sdJwt,
      kid: "kid",
      id: credentialId,
    },
  ];

  it("Delete Credential", async () => {
    await new VaultTestHelper(mockVault()).deleteCredential(credentialId);
  });

  it("Get Credential", async () => {
    const credential = await new VaultTestHelper(mockVault()).getCredential(credentialId);

    expect(credential).toEqual(credentialEntries[0]);
  });

  it("Get credential with non-existent credential ID", async () => {
    const credential = await new VaultTestHelper(mockVault()).getCredential("cred:9876");

    expect(credential).toBeFalsy();
  });

  it("Get Credentials", async () => {
    const credentials = await new VaultTestHelper(mockVault()).getCredentials();

    expect(credentials).toEqual(credentialEntries);
  });

  it("find Credentials", async () => {
    const credentials = await new VaultTestHelper(mockVault()).findCredentials(sdJwtMetadata.fields);

    expect(credentials).toEqual(credentialEntries);
  });

  it("Store Credential", async () => {
    const credentials = await new VaultTestHelper(mockVault()).storeCredential(sdJwt, sdJwtMetadata);

    expect(credentials).toEqual(credentialId);
  });

  function mockVault() {
    return new MockVault(credentialId, sdJwtMetadata.fields, credentialEntries, sdJwtMetadata);
  }
});

class MockVault implements Vault {
  constructor(
    private readonly credentialId: string,
    private readonly criteria: Array<string>,
    private readonly credentialEntries: Array<CredentialEntry>,
    private readonly metadata: CredentialMetadata,
  ) {
    this.deleteCredential = this.deleteCredential.bind(this);
    this.findCredentials = this.findCredentials.bind(this);
    this.getCredential = this.getCredential.bind(this);
    this.getCredentials = this.getCredentials.bind(this);
    this.storeCredential = this.storeCredential.bind(this);
  }

  async deleteCredential(id: string): Promise<void> {
    expect(id).toEqual(this.credentialId);
  }

  async findCredentials(criteria: Array<string>): Promise<Array<CredentialEntry>> {
    expect(criteria).toEqual(this.criteria);

    return this.credentialEntries;
  }

  async getCredential(id: string): Promise<CredentialEntry | null> {
    if (id != this.credentialId || this.credentialEntries.length == 0) {
      return null;
    }

    return this.credentialEntries[0];
  }

  async getCredentials(): Promise<Array<CredentialEntry>> {
    return this.credentialEntries;
  }

  async storeCredential(credential: Credential, metadata: CredentialMetadata): Promise<string> {
    expect(credential).toEqual(this.credentialEntries[0].credential);
    expect(metadata).toEqual(this.metadata);

    return this.credentialId;
  }
}
