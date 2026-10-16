import Testing
import Foundation
import Swifter
@testable import EqusSdk

@Suite(.serialized) class KmsTests {


    @Test func create() async throws {
        let kms = self.mockKms()
        let kid = try await kms.create(kt: .ed25519)

        #expect("TestString" == kid) 
    }

    @Test func getByKeyId() async throws {
        let kms = self.mockKms()
        let keyHandle = try await kms.get(kid: "TestString")

        #expect(try keyHandle.inner.pubKey() == "testKey".data(using: .utf8)!)
    }

    @Test func getByPublicKey() async throws {
        let publicKey = "testKey".data(using: .utf8)!
        let kms = self.mockKms()
        let keyHandle = try await kms.getByPublicKey(publicKey: publicKey)

        #expect(try keyHandle.inner.pubKey() == "testKey".data(using: .utf8)!)
    }
    
    private func mockKms() -> EqusSdk.Kms {
        return wrapKmsForTests(kms: MockKms())
    }

}


final class MockKms : EqusSdk.Kms {
    func create(kt: EqusSdk.KeyType) async throws -> String {
        return "TestString"
    }
    
    func get(kid: String) async throws -> EqusSdk.WrappedKeyHandle {
        return EqusSdk.WrappedKeyHandle(inner: MockKeyHandle())
    }
    
    func getByPublicKey(publicKey: Data) async throws -> EqusSdk.WrappedKeyHandle {
        return EqusSdk.WrappedKeyHandle(inner: MockKeyHandle())
    }
    
}
