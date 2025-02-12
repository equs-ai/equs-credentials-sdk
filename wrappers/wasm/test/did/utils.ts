export class Utils {
  readonly didResolution = {
    document: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1",
      ],
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
    // @ts-ignore
    document_metadata: { deactivated: null },
  };
}
