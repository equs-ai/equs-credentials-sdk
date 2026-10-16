import Testing
import Foundation
import Swifter
@testable import EqusSdk

@Suite(.serialized) class DIDKeyTests {

	@Test func generateDID() async throws {
		let kms = InMemKms()
		let kid = try await kms.create(kt: KeyType.p256)
		let keyHandle = try await kms.get(kid: kid)

		let didKey = DidKey()

		let did = try didKey.generate(key: keyHandle)

		#expect(did.contains("did:key:"))
	}
}