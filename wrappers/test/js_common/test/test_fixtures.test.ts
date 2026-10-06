import { createHash } from "crypto";
import {
  FixtureKey,
  fixtureDidKey,
  fixtureDidKeyUrl,
  fixtureJwe,
  fixtureJwks,
  fixtureJws,
  fixturePublicJwk,
  fixtureSdJwt,
  fixtureSdJwtKb,
} from "equs-credentials-sdk";

const BASE64URL = /^[A-Za-z0-9_-]+$/;

const decode = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

const digest = (input: string) => createHash("sha256").update(input).digest("base64url");

describe("Test fixtures: ", () => {
  it("fixturePublicJwk returns the public key under its kid", () => {
    const jwk = JSON.parse(fixturePublicJwk(FixtureKey.Authz));

    expect(jwk.kty).toEqual("RSA");
    expect(jwk.alg).toEqual("RS256");
    expect(typeof jwk.kid).toEqual("string");
    expect(jwk.d).toBeUndefined();
  });

  it("fixtureJws returns three base64url parts", () => {
    const token = fixtureJws(
      JSON.stringify({ alg: "ES256", typ: "JWT" }),
      JSON.stringify({ iss: "me" }),
      FixtureKey.Issuer,
    );

    const parts = token.split(".");
    expect(parts).toHaveLength(3);
    parts.forEach((part) => expect(part).toMatch(BASE64URL));
    expect(decode(parts[0])).toEqual({ alg: "ES256", typ: "JWT" });
    expect(decode(parts[1])).toEqual({ iss: "me" });
  });

  it("fixtureSdJwt ends with ~ and digests the disclosure into _sd", () => {
    const token = fixtureSdJwt(
      JSON.stringify({ alg: "ES256", typ: "vc+sd-jwt" }),
      JSON.stringify({ vct: "test" }),
      ['["salt", "given_name", "John"]'],
      FixtureKey.Issuer,
    );

    expect(token.endsWith("~")).toBe(true);
    const [jws, disclosure, rest] = token.split("~");
    expect(rest).toEqual("");
    expect(Buffer.from(disclosure, "base64url").toString("utf8")).toEqual('["salt", "given_name", "John"]');
    const payload = decode(jws.split(".")[1]);
    expect(payload.vct).toEqual("test");
    expect(payload._sd).toEqual([digest(disclosure)]);
  });

  it("fixtureSdJwtKb appends a kb+jwt carrying sd_hash", () => {
    const sdJwt = fixtureSdJwt(
      JSON.stringify({ alg: "ES256" }),
      JSON.stringify({ vct: "test" }),
      [],
      FixtureKey.Issuer,
    );

    const presentation = fixtureSdJwtKb(
      sdJwt,
      JSON.stringify({ alg: "ES256", typ: "kb+jwt" }),
      JSON.stringify({ nonce: "n", aud: "a" }),
      FixtureKey.Holder,
    );

    expect(presentation.startsWith(sdJwt)).toBe(true);
    const [header, payload, signature] = presentation.slice(sdJwt.length).split(".");
    expect(decode(header)).toEqual({ alg: "ES256", typ: "kb+jwt" });
    expect(decode(payload)).toEqual({ nonce: "n", aud: "a", sd_hash: digest(sdJwt) });
    expect(signature).toMatch(BASE64URL);
  });

  it("fixtureJwe has five parts with ECDH-ES in the protected header", () => {
    const token = fixtureJwe(
      JSON.stringify({ alg: "ECDH-ES", enc: "A128CBC-HS256", kid: "k", apu: "u", apv: "v" }),
      '{"hello":"world"}',
      FixtureKey.Verifier,
    );

    const parts = token.split(".");
    expect(parts).toHaveLength(5);
    const protectedHeader = decode(parts[0]);
    expect(protectedHeader.alg).toEqual("ECDH-ES");
    expect(protectedHeader.enc).toEqual("A128CBC-HS256");
    expect(protectedHeader.kid).toEqual("k");
    expect(protectedHeader.epk.crv).toEqual("P-256");
  });

  it("fixtureJwks publishes the authz key under the kid of fixturePublicJwk", () => {
    const jwks = JSON.parse(fixtureJwks([FixtureKey.Authz]));

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].alg).toEqual("RS256");
    expect(jwks.keys[0].kid).toEqual(JSON.parse(fixturePublicJwk(FixtureKey.Authz)).kid);
    expect(jwks.keys[0].d).toBeUndefined();
  });

  it("fixtureDidKeyUrl names the verification method of fixtureDidKey", () => {
    const url = fixtureDidKeyUrl(FixtureKey.Holder);

    expect(url.startsWith("did:key:zDna")).toBe(true);
    expect(url).toContain("#");
    expect(url.split("#")[0]).toEqual(fixtureDidKey(FixtureKey.Holder));
  });

  it("rejects malformed JSON", () => {
    expect(() => fixtureJws("{", JSON.stringify({}), FixtureKey.Issuer)).toThrow();
  });
});
