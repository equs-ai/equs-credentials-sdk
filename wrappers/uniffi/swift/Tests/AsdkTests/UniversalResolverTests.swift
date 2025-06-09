import Testing
@testable import Asdk


@Suite(.serialized) class UniversalDidResolverTests {


    @Test func customResolversSucceed() async throws {
        
        let mockDIDResolver = MockDIDResolver(method: "mock")
        let anotherMockDIDResolver = MockDIDResolver(method: "anothermock")
        let universalDidResolver = try UniversalDidResolver(resolvers: [mockDIDResolver, anotherMockDIDResolver])

        let result1 = try await universalDidResolver.resolve(did: "did:mock:12345")
        let result2 = try await universalDidResolver.resolve(did: "did:anothermock:12345")

        #expect(didResolutionDocument(method: "mock") == result1.document)
        #expect(didResolutionDocument(method: "anothermock") == result2.document)
    }

    @Test func multipleAdditionOfSameDidMethodFails() async throws {
        let mockDIDResolver = MockDIDResolver(method: "mock")
    
        do {
            _ = try UniversalDidResolver(resolvers: [mockDIDResolver, mockDIDResolver])
            #expect(Bool(false), "Expected Universal did resolver error to be thrown")
        } catch let error as Asdk.Error {
            switch error {
            case .DidResolver(let message):
                #expect(message.contains("Method already exists: mock"))
            default:
                #expect(Bool(false), "Unexpected Asdk.Error case: \(error)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error type: \(error)")
        }
    }

    
    @Test func resolve() async throws {
        let universalDidResolver = try! UniversalDidResolver(resolvers: nil)

        let expected = DidResolution(
            document: DOCUMENT,
            documentMetadata: DidDocMetadata(deactivated: nil),
            metadata: DidMetadata(contentType: "application/did+ld+json")
        )

        let actual = try await universalDidResolver.resolve(did: DID)

        #expect(actual == expected)
    }

    @Test func resolveVerificationMethod() async throws {
        let universalDidResolver = try! UniversalDidResolver(resolvers: nil)

        let expected = VerificationMethod(
            id: "\(DID)#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
            type: "Multikey",
            controller: DID,
            properties: ["publicKeyMultibase": "zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6"]
        )

        let actual = try await universalDidResolver.resolveVerificationMethod(did: DID)!

        #expect(actual == expected)
    }
    
}



final class MockDIDResolver : Asdk.DidResolver {
    private let method: String
    
    init(method: String) {
        self.method = method
    }
    
    func resolveRepresentation(did: String, options: Asdk.DidResolutionOptions) async throws -> Asdk.DidResolution {
        return Asdk.DidResolution(
            document: didResolutionDocument(method: self.methodName()),
            documentMetadata: DidDocMetadata(
                deactivated: nil
            ),
            metadata: Asdk.DidMetadata(
                contentType: "application/did+ld+json"
            )
        )
    }
    
    func methodName() -> String {
        self.method
    }
    
}

func didResolutionDocument(method: String) -> String {
    return "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/multikey/v1\"],\"id\":\"did:\(method):12345\",\"authentication\":[\"did:\(method):12345#key-1\"],\"assertionMethod\":[\"did:\(method):12345#key-1\"],\"verificationMethod\":[{\"id\":\"did:\(method):12345\",\"type\":\"Multikey\",\"controller\":\"did:\(method):12345\",\"publicKeyMultibase\":\"z1BcDfGmZ\"}]}"
}

let DID = "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6"
let DOCUMENT =
	"{"
	+ "\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/multikey/v1\"],"
	+ "\"id\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\","
	+ "\"authentication\":[\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"],"
	+ "\"assertionMethod\":[\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"],"
	+ "\"verificationMethod\":[{\"id\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\","
	+ "\"type\":\"Multikey\","
	+ "\"controller\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\","
	+ "\"publicKeyMultibase\":\"zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"}]" + "}"
