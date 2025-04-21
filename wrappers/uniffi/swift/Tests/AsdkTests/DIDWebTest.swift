import Testing
import Foundation
import Swifter
@testable import Asdk

@Suite(.serialized) class DIDWebTests {

	@Test func generateDIDDocument() async throws {
		let did = "did:web:test.example.com"
		let kms = InMemKms()
		let kid = try await kms.create(kt: KeyType.p256)
		let keyHandle = try await kms.get(kid: kid)

		let verificationMethodKey = VerificationMethodKey(
			kh: keyHandle,
			verifications: [
				VerificationRelationshipType.keyAgreement,
				VerificationRelationshipType.authentication,
			])

		let didWeb = DidWeb()

		let didDocument = try didWeb.generateDidDocument(did: did, keys: [verificationMethodKey])

		let document =
			try! JSONSerialization.jsonObject(with: didDocument.data(using: .utf8)!)
			as! Dictionary<String, Any>
		let vmm = (document["verificationMethod"] as! [Dictionary<String, Any>])[0]

		#expect("did:web:test.example.com" == document["id"] as! String)
		#expect(
			[
				"https://www.w3.org/ns/did/v1",
				"https://w3id.org/security#EcdsaSecp256r1VerificationKey2019",
			] == document["@context"] as! [String]
		)
		#expect(["did:web:test.example.com#key-0"] == document["keyAgreement"] as! [String])

		#expect("did:web:test.example.com" == vmm["controller"] as! String)
		#expect("did:web:test.example.com#key-0" == vmm["id"] as! String)
		#expect("EcdsaSecp256r1VerificationKey2019" == vmm["type"] as! String)
	}
}