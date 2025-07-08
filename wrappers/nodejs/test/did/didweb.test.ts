import { DIDWeb, InMemKms, KeyHandle, KeyType, VerificationMethodKey, VerificationRelationshipType } from "../../";

describe("did:web: ", () => {
  it("generate did document", async () => {
    const did = "did:web:test.example.com";
    const kms = new InMemKms();
    const key = await kms.create(KeyType.P256);
    const nativeKeyHandle = await kms.get(key);
    const didWeb = new DIDWeb();
    let keyHandle: KeyHandle = {
      alg: nativeKeyHandle.alg,
      jwk: nativeKeyHandle.jwk,
      pubKey: nativeKeyHandle.pubKey,
      sign: nativeKeyHandle.sign,
      verify: nativeKeyHandle.verify,
    };
    const verificationMethodKey = new VerificationMethodKey(keyHandle, [
      VerificationRelationshipType.KeyAgreement,
      VerificationRelationshipType.Authentication,
    ]);

    let expected_did_doc = {
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

    let did_doc = didWeb.generateDidDocument(did, [verificationMethodKey]);
    expected_did_doc.verificationMethod[0].publicKeyMultibase = did_doc.verificationMethod[0][
      "publicKeyMultibase"
    ] as string;
    expect(did_doc).toEqual(expected_did_doc);
  });
});
