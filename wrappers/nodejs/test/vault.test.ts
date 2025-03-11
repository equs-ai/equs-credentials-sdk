import { Alg, Credential, CredentialEntry, CredentialMetadata, Vault, VaultTestHelper, VCFormat } from "../";

const CREDENTIAL_DATA = {
  id: "test",
  credential: {
    format: VCFormat.SdJwtVc,
    payload:
      "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiYkRUUnZtNS1Zbi1IRzdjcXBWUjVPVlJJ" +
      "WHNTYUJrNTdKZ2lPcV9qMVZJNCIsImV0M1VmUnlsd1ZyZlhkUEt6Zzc5aGNqRDFJdHpvUTlvQm9YUkd0TW9zRmsiLCJ6V2ZaTlMxOUF0Yl" +
      "JTVGJvN3NKUm4wQlpRdldSZGNob0M3VVphYkZyalk4Il0sIl9zZF9hbGciOiJzaGEtMjU2In0.n27NCtnuwytlBYtUNjgkesDP_7gN7bha" +
      "LhWNL4SWT6MaHsOjZ2ZMp987GgQRL6ZkLbJ7Cd3hlePHS84GBXPuvg~WyI1ZWI4Yzg2MjM0MDJjZjJlIiwiZmlyc3RuYW1lIiwiSm9obiJ" +
      "d~WyJjNWMzMWY2ZWYzNTg4MWJjIiwibGFzdG5hbWUiLCJEb2UiXQ~WyJmYTlkYTUzZWJjOTk3OThlIiwic3NuIiwiMTIzLTQ1LTY3ODkiX" +
      "Q~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MTAwNjk3MjIsImF1ZCI6ImRpZDpleGFtcGxlOjEyMyIsIm5vbmN" +
      "lIjoiazh2ZGYwbmQ2Iiwic2RfaGFzaCI6Il8tTmJWSzNmczl3VzNHaDNOUktSNEt1NmZDMUwzN0R2MFFfalBXd0ppRkUifQ.pqw2OB5IA5" +
      "ya9Mxf60hE3nr2gsJEIoIlnuCa4qIisijHbwg3WzTDFmW2SuNvK_ORN0WU6RoGbJx5uYZh8k4EbA",
  },
  metadata: {
    type: "personal",
    format: VCFormat.SdJwtVc,
    kid: "kid",
    alg: Alg.ES256,
    fields: ["firstname"],
  },
};

function mockVault() {
  return new MockVault(CREDENTIAL_DATA);
}

class MockVault implements Vault {
  constructor(private readonly data: { id: string; credential: Credential; metadata: CredentialMetadata }) {
    this.storeCredential = this.storeCredential.bind(this);
    this.deleteCredential = this.deleteCredential.bind(this);
    this.findCredentials = this.findCredentials.bind(this);
    this.getCredential = this.getCredential.bind(this);
    this.getCredentials = this.getCredentials.bind(this);
  }

  async storeCredential(credential: Credential, metadata: CredentialMetadata): Promise<string> {
    expect(credential).toEqual(this.data.credential);
    expect(metadata).toEqual(this.data.metadata);
    return this.data.id;
  }

  async deleteCredential(id: string): Promise<void> {
    expect(id).toEqual(this.data.id);
    return;
  }

  async findCredentials(criteria: Array<string>): Promise<Array<CredentialEntry>> {
    return [{ credential: CREDENTIAL_DATA.credential, id: this.data.id, kid: this.data.metadata.kid }];
  }

  async getCredential(id: string): Promise<CredentialEntry | null> {
    return { credential: CREDENTIAL_DATA.credential, id: this.data.id, kid: this.data.metadata.kid };
  }

  async getCredentials(): Promise<Array<CredentialEntry>> {
    return [{ credential: CREDENTIAL_DATA.credential, id: this.data.id, kid: this.data.metadata.kid }];
  }
}

describe("Vault: ", () => {
  const data = CREDENTIAL_DATA;
  test("store credential", async () => {
    const vault = new VaultTestHelper(mockVault());
    const id = await vault.storeCredential(data.credential, data.metadata);
    expect(id).toEqual(data.id);
  });

  test("delete Credential", async () => {
    const vault = new VaultTestHelper(mockVault());
    const entry = await vault.deleteCredential(data.id);

    expect(entry).toBeUndefined();
  });

  test("get Credential", async () => {
    const vault = new VaultTestHelper(mockVault());
    const entry = await vault.getCredential(data.id);

    expect(entry).toEqual({ credential: data.credential, kid: data.metadata.kid, id: data.id });
  });

  test("find Credentials", async () => {
    const vault = new VaultTestHelper(mockVault());

    const entries = await vault.findCredentials(["format"]);
    expect(entries).toEqual([{ credential: data.credential, kid: data.metadata.kid, id: data.id }]);
  });

  test("get Credentials", async () => {
    const vault = new VaultTestHelper(mockVault());

    const entries = await vault.getCredentials();
    expect(entries).toEqual([{ credential: data.credential, kid: data.metadata.kid, id: data.id }]);
  });
});
