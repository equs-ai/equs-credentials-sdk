import { NativeDIDResolver } from "agent-sdk";
import { Utils } from "./utils";

describe("DID: ", () => {
  const utils = new Utils();
  describe("Universal Resolver: ", () => {
    const resolver = new NativeDIDResolver();

    test("Resolve verification method", async () => {
      const result = await resolver.resolve_verification_method(
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
      expect(result).toEqual(utils.didResolution);
    });
  });
});

