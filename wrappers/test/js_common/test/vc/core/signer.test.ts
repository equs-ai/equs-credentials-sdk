import {
  DIDKey,
  InMemKms,
  KeyType,
  UniversalDIDResolver,
  UnsignedCredential,
  VCCoreCredentialSigner,
  VCFormat,
} from "equs-sdk";

describe("VCCoreCredentialSigner: ", () => {
  const buildSdJwtUnsigned = async () => {
    const kms = new InMemKms();
    const issuerKid = await kms.create(KeyType.P256);
    const issuerKeyHandle = await kms.get(issuerKid);
    const issuerDid = new DIDKey().generate(issuerKeyHandle);
    const verificationMethodId = `${issuerDid}#${issuerDid.split(":").pop()}`;

    const holderKid = await kms.create(KeyType.P256);
    const holderKeyHandle = await kms.get(holderKid);
    const holderDid = new DIDKey().generate(holderKeyHandle);
    const holderJwk = JSON.parse(holderKeyHandle.jwk as string);

    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: issuerDid,
      sub: holderDid,
      vct: "https://example.com/credentials/test",
      iat: now,
      nbf: now,
      exp: now + 60 * 60 * 24 * 365,
      name: "Alice",
    };

    const unsigned: UnsignedCredential = {
      SdJwt: {
        claims,
        disclosure_strategy: "AllLevels",
        holder_key: holderJwk,
        extra_headers: {
          typ: "vc+sd-jwt",
          kid: verificationMethodId,
        },
        issuer_key_id: issuerKid,
      },
    };

    return { kms, unsigned };
  };

  it("signs SD-JWT unsigned credential via externally-tagged wire format", async () => {
    const { kms, unsigned } = await buildSdJwtUnsigned();
    const signer = new VCCoreCredentialSigner(kms, new UniversalDIDResolver());

    const credential = await signer.signCredential(unsigned);

    expect(credential.format).toEqual(VCFormat.SdJwtVc);
    // Compact SD-JWT serialisation: 3 base64url-segments joined by '.' followed by
    // disclosures appended with '~' separators (trailing '~' for no key-binding JWT).
    expect(credential.payload).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~/);
  });

  it("rejects malformed UnsignedCredential payload", async () => {
    const kms = new InMemKms();
    const signer = new VCCoreCredentialSigner(kms, new UniversalDIDResolver());

    await expect(signer.signCredential({ NotAValidVariant: {} } as never)).rejects.toBeDefined();
  });
});
