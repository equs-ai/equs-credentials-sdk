import {AskarStorage, AskarStorageConfig, KeyMethod} from "../index";

describe("Askar Storage: ", () => {
  let config: AskarStorageConfig

  beforeAll(async () => {
    config = {dbUrl: "sqlite://test.db", keyMethod: KeyMethod.DeriveKey, passKey: "test_key", profile: "test"}
    await AskarStorage.create(config, false)
  }, 10000);


  test("open, close and recreate", async () => {
    // Check opening
    let storage = await AskarStorage.open(config);
    let profile = "test2";
    profile = await storage.createProfile(profile);

    // Check closing
    await storage.close();
    storage.removeProfile(profile).catch((e) => {
      expect(e.message).toEqual("Backend error\nCaused by: attempted to acquire a connection on a closed pool")
    });

    // Check recreation
    storage = await AskarStorage.create(config, true)
    storage.changeActiveProfile(profile)
        .catch((e) => expect(e.message).toEqual("Profile not found"));

    await AskarStorage.remove(config.dbUrl);
  }, 20000);

  test("remove and open", async () => {
    await AskarStorage.create(config, true)

    await AskarStorage.remove(config.dbUrl);
    AskarStorage.open(config).catch((e) => expect(e.message).toEqual("The requested database path was not found"));

  }, 20000);

  test("create, remove and update active profile", async () => {
    const storage = await AskarStorage.create(config, true);

    // Check creation of a new profile
    let profile = "test2";
    profile = await storage.createProfile(profile);

    // Check updating active profile
    await storage.changeActiveProfile(profile);
    const activeProfile = storage.getActiveProfile();
    expect(activeProfile).toEqual(profile);

    // Check removing profile
    const removed = await storage.removeProfile(activeProfile);
    expect(removed).toEqual(true);
    storage.changeActiveProfile(activeProfile)
        .catch((e) => expect(e.message).toEqual("Session profile has been removed"));

    await AskarStorage.remove(config.dbUrl);
  }, 20000);

});
