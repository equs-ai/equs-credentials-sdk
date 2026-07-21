import { DIDWeb, InMemKms, KeyType, VerificationMethodKey, VerificationRelationshipType } from "agent-sdk";

describe("did:web: ", () => {
  const did = "did:web:test.example.com";
  // The key is used for keyAgreement, so it is published as JsonWebKey2020 /
  // publicKeyJwk (rather than multibase) with the JWK `kid` pinned to the
  // verification method id, so a JWE encryptor can address the exact key.
  const expectedDidDoc = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#JsonWebKey2020"],
    id: did,
    authentication: ["did:web:test.example.com#key-0"],
    keyAgreement: ["did:web:test.example.com#key-0"],
    verificationMethod: [
      {
        id: "did:web:test.example.com#key-0",
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: {
          kty: "EC",
          crv: "P-256",
          kid: "did:web:test.example.com#key-0",
          x: "temp_string",
          y: "temp_string",
        },
      },
    ],
  };

  it("generate DID from URL", async () => {
    const url = "https://example.com/users/alice";
    const didWeb = new DIDWeb();

    const did = didWeb.generateDidFromUrl(url);

    expect(did).toEqual("did:web:example.com:users:alice");
  });

  it("generate DID document with InMem KeyHandle", async () => {
    const did = "did:web:test.example.com";
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);
    const didWeb = new DIDWeb();

    const verificationMethodKey = new VerificationMethodKey(keyHandle, [
      VerificationRelationshipType.KeyAgreement,
      VerificationRelationshipType.Authentication,
    ]);

    const did_doc = didWeb.generateDidDocument(did, [verificationMethodKey]);
    // x/y are randomly generated per key; copy them from the actual document.
    const actualJwk = did_doc.verificationMethod[0]["publicKeyJwk"] as { x: string; y: string };
    expectedDidDoc.verificationMethod[0].publicKeyJwk.x = actualJwk.x;
    expectedDidDoc.verificationMethod[0].publicKeyJwk.y = actualJwk.y;

    expect(did_doc).toEqual(expectedDidDoc);
  });

  it("generate DID document with NOT an instance of InMem KeyHandle", async () => {
    const did = "did:web:test.example.com";
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);
    const didWeb = new DIDWeb();

    const verificationMethodKey = new VerificationMethodKey(
      {
        alg: keyHandle.alg,
        jwk: keyHandle.jwk,
        sign(payload: Uint8Array): Promise<Uint8Array> {
          return keyHandle.sign(payload);
        },
        verify(data: Uint8Array, signature: Uint8Array): Promise<void> {
          return keyHandle.verify(data, signature);
        },
      },
      [VerificationRelationshipType.KeyAgreement, VerificationRelationshipType.Authentication],
    );

    const did_doc = didWeb.generateDidDocument(did, [verificationMethodKey]);
    // x/y are randomly generated per key; copy them from the actual document.
    const actualJwk = did_doc.verificationMethod[0]["publicKeyJwk"] as { x: string; y: string };
    expectedDidDoc.verificationMethod[0].publicKeyJwk.x = actualJwk.x;
    expectedDidDoc.verificationMethod[0].publicKeyJwk.y = actualJwk.y;

    expect(did_doc).toEqual(expectedDidDoc);
  });
});
