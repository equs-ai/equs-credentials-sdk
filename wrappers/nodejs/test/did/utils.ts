import { DIDVerificationMethod } from "../../";
import { DIDDocument } from "../../../types";

export class Utils {
  readonly webVerificationMethod = {
    id: expect.stringContaining("did:web:"),
    type: "Ed25519VerificationKey2020",
    controller: expect.stringContaining("did:web:"),
    publicKeyJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: expect.any(String),
    },
  };
  readonly keyVerificationMethod: DIDVerificationMethod = {
    id: expect.stringContaining("did:key:"),
    type: "Ed25519VerificationKey2018",
    controller: expect.stringContaining("did:key:"),
    publicKeyJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: expect.any(String),
    },
  };
  readonly webResolveResponse = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#Ed25519VerificationKey2020"],
    id: expect.stringContaining("did:web:"),
    verificationMethod: [this.webVerificationMethod],
  };
  readonly keyResolveResponse = {
    metadata: {},
    docMetadata: {},
    doc: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        {
          Ed25519VerificationKey2018: "https://w3id.org/security#Ed25519VerificationKey2018",
          publicKeyJwk: {
            "@id": "https://w3id.org/security#publicKeyJwk",
            "@type": "@json",
          },
        },
      ],
      id: expect.stringContaining("did:key:"),
      verificationMethod: [this.keyVerificationMethod],
      authentication: [expect.stringContaining("did:key:")],
      assertionMethod: [expect.stringContaining("did:key:")],
    },
  };

  readonly didResolution = {
    document: {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: expect.stringContaining("did:key:"),
      authentication: [expect.stringContaining("did:key:")],
      assertionMethod: [expect.stringContaining("did:key:")],
      verificationMethod: [
        {
          controller: expect.stringContaining("did:key:"),
          id: expect.stringContaining("did:key:"),
          publicKeyMultibase: expect.stringMatching("^z[1-9A-HJ-NP-Za-km-z]+$"),
          type: "Multikey",
        },
      ],
    },
    metadata: { contentType: "application/did+ld+json" },
    document_metadata: { deactivated: null },
  };

  mockDidResolution(methodName: string): DIDDocument {
    return {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: `did:${methodName}:12345`,
      authentication: [`did:${methodName}:12345#key-1`],
      assertionMethod: [`did:${methodName}:12345#key-1`],
      verificationMethod: [
        {
          controller: `did:${methodName}:12345`,
          id: `did:${methodName}:12345`,
          publicKeyMultibase: "z1BcDfGmZ",
          type: "Multikey",
        },
      ],
    };
  }
}
