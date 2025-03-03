import {
  DIDWeb,
  InMemKms,
  KeyType,
  VerificationMethodKey,
  VerificationRelationshipType
} from "agent-sdk";

describe("did:web: ", () => {
  test("generate DID from URL", async () => {
    const url = "https://example.com/users/alice";
    const didWeb = new DIDWeb();

    let did = didWeb.generateDidFromUrl(url);

    expect(did).toEqual("did:web:example.com:users:alice");
  });

  test("generate DID document", async () => {
    const did = "did:web:test.example.com";
    const kms = new InMemKms();
    const kid = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(kid);
    const didWeb = new DIDWeb();

    const verificationMethodKey = new VerificationMethodKey(keyHandle, [
      VerificationRelationshipType.KeyAgreement,
      VerificationRelationshipType.Authentication,
    ]);

    let expected_did_doc = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019"
      ],
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

    let did_doc = didWeb.generateDidDocument(did, [verificationMethodKey]);
    expected_did_doc.verificationMethod[0].publicKeyMultibase = did_doc.verificationMethod[0][
      "publicKeyMultibase"
      ] as string;

    expect(did_doc).toEqual(expected_did_doc);
  });
});
