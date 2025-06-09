import Testing
import Foundation
import Swifter
@testable import Asdk

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
    
    private func mockKms() -> Asdk.Kms {
        return wrapKmsForTests(kms: MockKms())
    }

}


final class MockKms : Asdk.Kms {
    func create(kt: Asdk.KeyType) async throws -> String {
        return "TestString"
    }
    
    func get(kid: String) async throws -> Asdk.WrappedKeyHandle {
        return Asdk.WrappedKeyHandle(inner: MockKeyHandle())
    }
    
    func getByPublicKey(publicKey: Data) async throws -> Asdk.WrappedKeyHandle {
        return Asdk.WrappedKeyHandle(inner: MockKeyHandle())
    }
    
}
