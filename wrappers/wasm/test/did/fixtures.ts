import { DIDResolution } from "../../pkg";

export class Fixtures {
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
    // @ts-ignore
    document_metadata: { deactivated: null },
  };

  readonly customDidResolution: DIDResolution = {
    document: {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: "did:custom:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
      authentication: ["did:custom:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#key-1"],
      assertionMethod: ["did:custom:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#key-1"],
      verificationMethod: [
        {
          controller: "did:custom:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
          id: "did:custom:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#key-1",
          publicKeyMultibase: "zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
          type: "Multikey",
        },
      ],
    },
    metadata: { contentType: "application/did+ld+json" },
    // @ts-ignore
    document_metadata: { deactivated: null },
  };
}
