import { VCFormat } from "../types";
import { Credential, CredentialEntry, CredentialMetadata, Vault, VaultTestHelper } from "../pkg";

const SD_JWT_VC =
  "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~";

describe("Vault: ", () => {
  const credentialId = "cred:12345";

  const sdJwt: Credential = {
    format: VCFormat.SdJwtVc,
    payload: SD_JWT_VC,
  };

  const sdJwtMetadata = {
    type: "vc_type",
    kid: "kid",
    format: VCFormat.SdJwtVc,
    fields: ["$.vct", "$.name"],
  };

  const credentialEntries: Array<CredentialEntry> = [{
    credential: sdJwt,
    kid: "kid",
    id: credentialId,
  }];

  test("Delete Credential", async () => {
    await new VaultTestHelper(mockVault()).deleteCredential(credentialId);
  });

  test("Get Credential", async () => {
    const credential = await new VaultTestHelper(mockVault()).getCredential(credentialId);

    expect(credential).toEqual(credentialEntries[0]);
  });

  test("Get credential with non-existent credential ID", async () => {
    const credential = await new VaultTestHelper(mockVault()).getCredential("cred:9876");

    expect(credential).toBeUndefined();
  });

  test("Get Credentials", async () => {
    const credentials = await new VaultTestHelper(mockVault()).getCredentials();

    expect(credentials).toEqual(credentialEntries);
  });

  test("find Credentials", async () => {
    const credentials = await new VaultTestHelper(mockVault()).findCredentials(sdJwtMetadata.fields);

    expect(credentials).toEqual(credentialEntries);
  });

  test("Store Credential", async () => {
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