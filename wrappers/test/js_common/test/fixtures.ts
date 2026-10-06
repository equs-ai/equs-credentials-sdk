import { FixtureKey, fixtureDidKey, fixtureDidKeyUrl, fixturePublicJwk, fixtureSdJwt } from "equs-credentials-sdk";

export class Fixtures {
  static SDJWTVCPayload = fixtureSdJwt(
    JSON.stringify({ typ: "vc+sd-jwt", alg: "ES256", kid: fixtureDidKeyUrl(FixtureKey.Issuer) }),
    JSON.stringify({
      vct: "https://credentials.example.com/identity_credential",
      sub: fixtureDidKey(FixtureKey.Holder),
      nbf: 1728882611,
      _sd_alg: "sha-256",
      iss: fixtureDidKey(FixtureKey.Issuer),
      iat: 1728882611,
      exp: 1760418611,
      cnf: { jwk: JSON.parse(fixturePublicJwk(FixtureKey.Holder)) },
    }),
    ['["8zQfBB-KqYHuJqnpTDvsUQ", "name", "John"]'],
    FixtureKey.Issuer,
  );
}
