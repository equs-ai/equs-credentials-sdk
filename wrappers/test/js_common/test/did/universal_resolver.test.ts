import { Fixtures } from "./fixtures";
import { DIDResolution, DIDResolver, ResolutionOptions, UniversalDIDResolver } from "equs-sdk";

describe("Universal Resolver: ", () => {
  const fixtures = new Fixtures();
  const resolver = new UniversalDIDResolver();

  it("Resolve verification method", async () => {
    const result = await resolver.resolveVerificationMethod(
      "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
    );
    expect(result).toEqual(
      expect.objectContaining({
        id: "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
        type: "Multikey",
        controller: "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
        publicKeyMultibase: "zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
      }),
    );
  });

  it("Resolve method", async () => {
    const result = await resolver.resolve("did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6");
    expect(result).toEqual(fixtures.didResolution);
  });

  it("Resolve custom method", async () => {
    const customResolver = new MockDIDResolver(
      "custom",
      "did:custom:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
      fixtures.customDidResolution,
    );

    resolver.addResolver(customResolver);

    const result = await resolver.resolve("did:custom:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6");
    expect(result).toEqual(fixtures.customDidResolution);
  });
});

class MockDIDResolver implements DIDResolver {
  constructor(
    public readonly methodName: string,
    private readonly did: `did:${string}:${string}`,
    private readonly didResolution: DIDResolution,
  ) {}

  async resolveRepresentation(did: `did:${string}:${string}`, _: ResolutionOptions): Promise<DIDResolution> {
    expect(did).toEqual(this.did);

    return this.didResolution;
  }
}
