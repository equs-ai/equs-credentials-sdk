import { Alg, wrapJsVault, VCFormat, Vault, CredentialFilter } from "../index";

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
    tags: [{ key: "firstname", value: "John" }],
  },
};

describe("Vault: ", () => {
  test("store Credential", async () => {
    const data = CREDENTIAL_DATA;
    const vault = await wrapJsVault(mockVault(data));

    const id = await vault.storeCredential(data.credential, data.metadata);

    expect(id).toEqual(data.id);
  });

  test("get Credential", async () => {
    const data = CREDENTIAL_DATA;
    const vault = await wrapJsVault(mockVault(data));

    const entry = await vault.getCredential(data.id);

    expect(entry).toEqual({ credential: data.credential, kid: data.metadata.kid, id: data.id });
  });

  test("find Credentials", async () => {
    const vault = await wrapJsVault(mockVault(CREDENTIAL_DATA));

    await vault.findCredentials([CredentialFilter.byFormat("dc+sd-jwt")]);

    return;
  });
});

function mockVault(credential_data): Vault {
  return {
    async storeCredential(credential, metadata) {
      if (
        !(
          credential.format === credential_data.credential.format &&
          credential.payload === credential_data.credential.payload
        )
      )
        throw new Error(`Invalid credential: ${JSON.stringify(credential)}`);

      if (
        !(
          metadata.type === credential_data.metadata.type &&
          metadata.format === credential_data.metadata.format &&
          metadata.kid === credential_data.metadata.kid &&
          metadata.alg === credential_data.metadata.alg
        )
      )
        throw new Error(`Invalid metadata: ${JSON.stringify(metadata)}`);

      return credential_data.id;
    },

    async getCredential(id) {
      if (id !== credential_data.id) throw new Error(`Invalid ID: ${id}`);

      return {
        credential: credential_data.credential,
        kid: credential_data.metadata.kid,
        id: credential_data.id,
      };
    },

    async getCredentials() {
      return [
        {
          credential: credential_data.credential,
          kid: credential_data.metadata.kid,
          id: credential_data.id,
        },
      ];
    },

    async findCredentials(criteria: CredentialFilter[]) {
      const value = await criteria[0].value();
      if (!(value.type === "Format" && value.format === "dc+sd-jwt"))
        throw new Error(`Invalid criteria: ${JSON.stringify(criteria)}`);

      return [
        {
          credential: credential_data.credential,
          kid: credential_data.metadata.kid,
          id: credential_data.id,
        },
      ];
    },
  };
}
