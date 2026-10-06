import { Credential, FixtureKey, fixtureDidKey, parseClaims, VCFormat } from "equs-credentials-sdk";
import { Fixtures } from "./fixtures";

describe("Utils: ", () => {
  it("parse_claims", async () => {
    const credential: Credential = {
      format: VCFormat.SdJwtVc,
      payload: Fixtures.SDJWTVCPayload,
    };
    const result = await parseClaims(credential);
    expect(result).toMatchObject({
      name: "John",
      iat: 1728882611,
      vct: "https://credentials.example.com/identity_credential",
      sub: fixtureDidKey(FixtureKey.Holder),
      iss: fixtureDidKey(FixtureKey.Issuer),
      exp: 1760418611,
      nbf: 1728882611,
    });
  });
});
