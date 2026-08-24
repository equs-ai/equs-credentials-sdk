import { AskarStorage, AskarVault, KeyMethod } from "../index";
import { Alg, VCFormat } from "@equs/equs-sdk";
import * as assert from "node:assert";

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
  const dbUrl = "sqlite://:memory:";
  let vault: AskarVault;
  let credId: string;
  let storage: AskarStorage;

  beforeEach(async () => {
    storage = await AskarStorage.create(
      {
        dbUrl: "sqlite://:memory:",
        keyMethod: KeyMethod.DeriveKey,
        passKey: "test_key",
        profile: "test",
      },
      false,
    );
    await storage.createProfile("test_profile");
    vault = new AskarVault(storage, "test_profile");

    const data = CREDENTIAL_DATA;
    credId = await vault.storeCredential(data.credential, data.metadata);
  }, 10000);

  afterEach(async () => {
    await storage.close();
    await AskarStorage.remove(dbUrl);
  });

  test("store with different profile and passkey", async () => {
    const storage2 = await AskarStorage.create(
      {
        dbUrl: dbUrl,
        keyMethod: KeyMethod.DeriveKey,
        passKey: "test_key_2",
        profile: "test2",
      },
      false,
    );
    await storage2.createProfile("test_profile");
    const vault2 = new AskarVault(storage2, "test_profile");

    const data = CREDENTIAL_DATA;
    let credId2 = await vault2.storeCredential(data.credential, data.metadata);

    const entry2 = await vault2.getCredential(credId2);
    expect(entry2).toEqual({
      credential: data.credential,
      kid: data.metadata.kid,
      id: credId2,
    });

    const entry = await vault.getCredential(credId);
    expect(entry).toEqual({
      credential: data.credential,
      kid: data.metadata.kid,
      id: credId,
    });
  }, 20000);

  test("multiple vaults with singleton storage", async () => {
    const storage = await AskarStorage.create(
      {
        dbUrl: dbUrl,
        keyMethod: KeyMethod.DeriveKey,
        passKey: "test_key_2",
        profile: "test",
      },
      false,
    );

    const profile1 = "test_profile_1";
    const profile2 = "test_profile_2";
    const profile3 = "test_profile_3";
    const profile4 = "test_profile_4";

    await storage.createProfile(profile1);
    await storage.createProfile(profile2);
    await storage.createProfile(profile3);
    await storage.createProfile(profile4);
    const vault1 = new AskarVault(storage, profile1);
    const vault2 = new AskarVault(storage, profile2);
    const vault3 = new AskarVault(storage, profile3);
    const vault4 = new AskarVault(storage, profile4);

    const data = CREDENTIAL_DATA;
    let credId1 = await vault1.storeCredential(data.credential, data.metadata);
    let credId2 = await vault2.storeCredential(data.credential, data.metadata);
    let credId3 = await vault3.storeCredential(data.credential, data.metadata);
    let credId4 = await vault4.storeCredential(data.credential, data.metadata);

    const entry1 = await vault1.getCredential(credId1);
    const entry2 = await vault2.getCredential(credId2);
    const entry3 = await vault3.getCredential(credId3);
    const entry4 = await vault4.getCredential(credId4);

    await storage.removeProfile(profile1);
    await storage.removeProfile(profile2);

    await vault1.getCredential(credId1).catch((e) => {
      expect(e.message).toMatch(
        "Credential resolving error: Profile not found",
      );
    });
    await vault2.getCredential(credId2).catch((e) => {
      expect(e.message).toMatch(
        "Credential resolving error: Profile not found",
      );
    });
    await vault3.getCredential(credId3).then((entry) => {
      expect(entry).toEqual({
        credential: data.credential,
        kid: data.metadata.kid,
        id: credId3,
      });
    });
    await vault4.getCredential(credId4).then((entry) => {
      expect(entry).toEqual({
        credential: data.credential,
        kid: data.metadata.kid,
        id: credId4,
      });
    });
  });

  test("get Credential", async () => {
    const data = CREDENTIAL_DATA;
    const entry = await vault.getCredential(credId);

    expect(entry).toEqual({
      credential: data.credential,
      kid: data.metadata.kid,
      id: credId,
    });
  });

  test("get All Credentials", async () => {
    const data = CREDENTIAL_DATA;
    const entry = await vault.getCredentials();

    expect(entry.length).toEqual(1);
    expect(entry[0]).toEqual({
      credential: data.credential,
      kid: data.metadata.kid,
      id: credId,
    });
  });

  test("get with options", async () => {
    const data = CREDENTIAL_DATA;

    const credIds = [];

    for (let i = 0; i < 10; i++) {
      const credId = await vault.storeCredential(
        data.credential,
        data.metadata,
      );
      credIds.push(credId);
    }

    let entry = await vault.getWithOptions([], { offset: 8, limit: 4 });

    expect(entry.length).toEqual(3);
    expect(entry[0]).toEqual({
      credential: data.credential,
      kid: data.metadata.kid,
      id: expect.stringContaining("dc+sd-jwt:"),
    });
    return;
  });

  test("find Credentials", async () => {
    const data = CREDENTIAL_DATA;
    let entry = await vault.findCredentials(data.metadata.fields);

    expect(entry.length).toEqual(1);
    expect(entry[0]).toEqual({
      credential: data.credential,
      kid: data.metadata.kid,
      id: credId,
    });
    return;
  });

  test("delete credential", async () => {
    await vault.deleteCredential(credId);

    let credentialEntry = await vault.getCredential(credId);
    expect(credentialEntry).toBeNull();
  });

  test("counting all credential works ", async () => {
    const data = CREDENTIAL_DATA;
    const numCredentials = 10;
    const credIds = [];

    for (let i = 1; i < numCredentials; i++) {
      data.metadata.kid = i.toString();
      const id = await vault.storeCredential(data.credential, data.metadata);
      credIds.push(id);
    }

    let expected = await vault.countAll("dc+sd-jwt");
    expect(expected).toEqual(numCredentials);

    const deletedCredentials = 5;
    for (let i = 1; i <= deletedCredentials; i++) {
      await vault.deleteCredential(credIds[i]);
    }

    expected = await vault.countAll();
    expect(expected).toEqual(5);
  });
});
