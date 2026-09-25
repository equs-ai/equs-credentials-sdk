import { Credential, CredentialEntry, InMemVault, VCFormat } from "equs-credentials-sdk";
import { VC_TYPE } from "../vc/oid4vp/fixtures";
import { token } from "../bundle";

const SD_JWT_VC = token("vc");
describe("InMemVault: ", () => {
  it("store, get and delete credential", async () => {
    const vault = new InMemVault();

    const sdJwt: Credential = {
      format: VCFormat.SdJwtVc,
      payload: SD_JWT_VC,
    };

    const sdJwtMetadata = {
      type: VC_TYPE,
      kid: "kid",
      format: VCFormat.SdJwtVc,
      fields: ["$.vct", "$.name"],
    };

    const cred_id = await vault.storeCredential(sdJwt, sdJwtMetadata);

    const credEntry: CredentialEntry = {
      credential: sdJwt,
      kid: sdJwtMetadata.kid,
      id: cred_id,
    };

    const credential = await vault.getCredential(cred_id);

    expect(credential).toEqual(credEntry);

    const credentials = await vault.getCredentials();

    expect(credentials).toEqual([credEntry]);

    const foundCredentials = await vault.findCredentials(["$.vct", "$.name"]);

    expect(foundCredentials).toEqual([credEntry]);

    await vault.deleteCredential(cred_id);

    const emptyCredentials = await vault.getCredentials();

    expect(emptyCredentials).toEqual([]);
  });
  it("get with pagination", async () => {
    const vault = new InMemVault();

    const sdJwt: Credential = {
      format: VCFormat.SdJwtVc,
      payload: SD_JWT_VC,
    };

    const sdJwtMetadata = {
      type: VC_TYPE,
      kid: "kid",
      format: VCFormat.SdJwtVc,
      fields: ["$.vct", "$.name"],
    };

    for (let i = 0; i < 10; i++) {
      await vault.storeCredential(sdJwt, sdJwtMetadata);
    }
    const credentials = await vault.getCredentials({ offset: 8, limit: 4 });
    expect(credentials.length).toEqual(2);
  });
});
