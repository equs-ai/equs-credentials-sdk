import { DIDWeb, InMemKms, KeyType, VerificationMethodKey, VerificationRelationshipType } from "agent-sdk";

describe("did:web: ", () => {
  const did = "did:web:test.example.com";
  const expectedDidDoc = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019"],
    id: did,
    authentication: ["did:web:test.example.com#key-0"],
    keyAgreement: ["did:web:test.example.com#key-0"],
    verificationMethod: [
      {
        id: "did:web:test.example.com#key-0",
        type: "EcdsaSecp256r1VerificationKey2019",
        controller: did,
        publicKeyMultibase: "temp_string",
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
    expectedDidDoc.verificationMethod[0].publicKeyMultibase = did_doc.verificationMethod[0][
      "publicKeyMultibase"
    ] as string;

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
    expectedDidDoc.verificationMethod[0].publicKeyMultibase = did_doc.verificationMethod[0][
      "publicKeyMultibase"
    ] as string;

    expect(did_doc).toEqual(expectedDidDoc);
  });
});
