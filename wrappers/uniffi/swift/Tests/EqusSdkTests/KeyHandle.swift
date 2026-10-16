import Testing
import Foundation
import Swifter
@testable import EqusSdk

@Suite(.serialized) class KeyHandleTests {


    @Test func getAlg() async throws {
        
        let keyHandle = self.mockKeyHandler()
        let alg = keyHandle.alg()

        #expect(EqusSdk.Alg.es256 == alg)
    }

    @Test func getPublicKey() async throws {
        
        let keyHandle = self.mockKeyHandler()
        let pubKey = try keyHandle.pubKey()

        #expect("testKey".data(using: .utf8)! == pubKey)
    } 

    @Test func getJwk() async throws {
        
        let keyHandle = self.mockKeyHandler()
        let jwk = keyHandle.jwk()

        #expect("{\"crv\":\"P-256\",\"kid\":\"618d228e-4767-4aa2-8683-c35c86d7025c\",\"kty\":\"EC\",\"x\":\"huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs\",\"y\":\"4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg\"}" == jwk)
    }

    @Test func sign() async throws {
        let payload = "testPayload".data(using: .utf8)!
        
        let keyHandle = self.mockKeyHandler()
        let result = try await keyHandle.sign(payload: payload)

        #expect(result == payload)
    }

	@Test func verify() async throws {
        let keyHandle = self.mockKeyHandler()
        try await keyHandle.verify(data: "testData".data(using: .utf8)!, signature: "testSignature".data(using: .utf8)!)
	}
    
    private func mockKeyHandler() -> EqusSdk.KeyHandle {
        return wrapKeyHandleForTests(keyHandle: MockKeyHandle())
    }

}


final class MockKeyHandle : EqusSdk.KeyHandle {
    func pubKey() throws -> Data {
        return "testKey".data(using: .utf8)!
    }

    func jwk() -> String? {
        return "{\"crv\":\"P-256\",\"kid\":\"618d228e-4767-4aa2-8683-c35c86d7025c\",\"kty\":\"EC\",\"x\":\"huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs\",\"y\":\"4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg\"}"
    }

    func alg() -> EqusSdk.Alg {
        return EqusSdk.Alg.es256
    }

    func sign(payload: Data) async throws -> Data {
        return payload
    }

    func verify(data: Data, signature: Data) async throws {
        #expect(data == "testData".data(using: .utf8)!)
        #expect(signature == "testSignature".data(using: .utf8)!)
    }
}
