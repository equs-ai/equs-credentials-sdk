import { Credential, parseClaims, VCFormat } from "agent-sdk";
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
      sub: "did:key:zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM",
      iss: "did:key:zDnaexeh3T1CziWWSEeWpyuTkXqiT5ikiCw5iZQRBv4HXuex6",
      exp: 1760418611,
      nbf: 1728882611,
    });
  });
});
