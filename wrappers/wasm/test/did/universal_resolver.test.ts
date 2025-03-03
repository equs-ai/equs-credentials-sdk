import {UniversalDIDResolver} from "agent-sdk";
import {Fixtures} from "./fixtures";

describe("DID: ", () => {
  const fixtures = new Fixtures();
  describe("Universal Resolver: ", () => {
    const resolver = new UniversalDIDResolver();

    test("Resolve verification method", async () => {
      const result = await resolver.resolveVerificationMethod(
        "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
      );
      expect(result).toEqual(
        expect.objectContaining({
          id: "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
          type: "Multikey",
          controller:
            "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
          publicKeyMultibase:
            "zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
        }),
      );
    });

    test("Resolve method", async () => {
      const result = await resolver.resolve(
        "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
      );
      expect(result).toEqual(fixtures.didResolution);
    });
  });
});

