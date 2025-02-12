import {AskarStorage, AskarVault, KeyMethod} from "../index";
import {Alg, VCFormat} from "@equstng/agent-sdk";

const CREDENTIAL_DATA = {
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

describe("Askar Vault: ", () => {
  const dbUrl = "sqlite://:memory:"
  let vault: AskarVault
  let credId: string

  beforeAll(async () => {
    const storage = await AskarStorage.create({dbUrl: "sqlite://:memory:", keyMethod: KeyMethod.DeriveKey, passKey: "test_key", profile: "test"}, false)
    vault = new AskarVault(storage);

    const data = CREDENTIAL_DATA;
    credId = await vault.storeCredential(data.credential, data.metadata);

  }, 10000);

  afterAll(async () => {
    await vault.closeVault();
    await AskarStorage.remove(dbUrl);
  });

  test("store with different profile and passkey", async () => {
    const storage2 = await AskarStorage.create({dbUrl: dbUrl, keyMethod: KeyMethod.DeriveKey, passKey: "test_key_2", profile: "test2"}, false)
    const vault2 = new AskarVault(storage2);

    const data = CREDENTIAL_DATA;
    let credId2 = await vault2.storeCredential(data.credential, data.metadata);

    const entry2 = await vault2.getCredential(credId2);
    expect(entry2).toEqual({ credential: data.credential, kid: data.metadata.kid, id: credId2});

    const entry = await vault.getCredential(credId);
    expect(entry).toEqual({ credential: data.credential, kid: data.metadata.kid, id: credId});
    }, 20000);

  test("get Credential", async () => {
    const data = CREDENTIAL_DATA;
    const entry = await vault.getCredential(credId);

    expect(entry).toEqual({ credential: data.credential, kid: data.metadata.kid, id: credId});
  });

  test("get All Credentials", async () => {
    const data = CREDENTIAL_DATA;
    const entry = await vault.getCredentials();

    expect(entry.length).toEqual(1);
    expect(entry[0]).toEqual({ credential: data.credential, kid: data.metadata.kid, id: credId });
  });

  test("find Credentials", async () => {
    const data = CREDENTIAL_DATA;
    let entry = await vault.findCredentials(data.metadata.fields);

    expect(entry.length).toEqual(1);
    expect(entry[0]).toEqual({ credential: data.credential, kid: data.metadata.kid, id: credId});
    return;
  });

  test("delete credential", async () => {
    await vault.deleteCredential(credId);

    let credentialEntry = await vault.getCredential(credId);
    expect(credentialEntry).toBeNull();
  });
});
