import Testing
@testable import Asdk

let DID = "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6"
let DOCUMENT = "{" +
"\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/multikey/v1\"]," +
"\"id\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"," +
"\"authentication\":[\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"]," +
"\"assertionMethod\":[\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"]," +
"\"verificationMethod\":[{\"id\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"," +
"\"type\":\"Multikey\"," +
"\"controller\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"," +
"\"publicKeyMultibase\":\"zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"}]" +
"}"

@Test func testResolve() async throws { 
    let universalDidResolver = UniversalDidResolver()
    
    let expected = DidResolution(
        document: DOCUMENT,
        documentMetadata: DidDocMetadata(deactivated: nil),
        metadata: DidMetadata(contentType: "application/did+ld+json")
    )
    
    let actual = try await universalDidResolver.resolve(did: DID)
    
    #expect(actual == expected)
}

@Test func testResolveVerificationMethod() async throws {
    let universalDidResolver = UniversalDidResolver()
    
    let expected = VerificationMethod(
        id: "\(DID)#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
        type: "Multikey",
        controller: DID,
        properties: ["publicKeyMultibase": "zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6"]
    )
    
    let actual = try await universalDidResolver.resolveVerificationMethod(did: DID)!
    
    #expect(actual == expected)
}
