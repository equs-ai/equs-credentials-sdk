import { DIDResolution, DIDResolver, ResolutionOptions } from "../../binary";

export class MockDID implements DIDResolver {
  constructor(readonly methodName: string) {}

  async resolveRepresentation(did: string, options: ResolutionOptions): Promise<DIDResolution> {
    return {
      document: {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        id: `did:${this.methodName}:12345`,
        authentication: [`did:${this.methodName}:12345#key-1`],
        assertionMethod: [`did:${this.methodName}:12345#key-1`],
        verificationMethod: [
          {
            controller: `did:${this.methodName}:12345`,
            id: `did:${this.methodName}:12345`,
            publicKeyMultibase: "z1BcDfGmZ",
            type: "Multikey",
          },
        ],
      },
      metadata: { contentType: "application/did+ld+json" },
      document_metadata: { deactivated: false },
    };
  }
}
