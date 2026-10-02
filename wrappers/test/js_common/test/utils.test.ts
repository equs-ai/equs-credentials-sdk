import { Credential, parseClaims, VCFormat } from "equs-credentials-sdk";
import { jwtDecode } from "jwt-decode";
import { Fixtures } from "./fixtures";

describe("Utils: ", () => {
  it("parse_claims", async () => {
    const credential: Credential = {
      format: VCFormat.SdJwtVc,
      payload: Fixtures.SDJWTVCPayload,
    };
    const result = await parseClaims(credential);

    // Independent expectation: a naive decode (registered claims only —
    // `name` is behind a disclosure `parseClaims` must merge itself, so it's
    // not visible here) cross-checked against `parseClaims`'s own merge.
    // `name: "John"` is a fixed default the fixture crate's SD-JWT VC
    // builder always discloses; everything else (`sub`/`iss`/timestamps)
    // changes every bundle regeneration. `parseClaims` doesn't surface `cnf`,
    // matching what this test asserted before migration.
    const { _sd, _sd_alg, cnf, ...registeredClaims } = jwtDecode(Fixtures.SDJWTVCPayload) as Record<string, unknown>;
    expect(result).toMatchObject({
      ...registeredClaims,
      name: "John",
    });
  });
});
