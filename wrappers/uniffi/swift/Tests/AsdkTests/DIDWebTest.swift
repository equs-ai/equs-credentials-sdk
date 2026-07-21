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

		let didWeb = try DidWeb(httpClient: ReqwestHttpClient.insecure())

		let didDocument = try didWeb.generateDidDocument(did: did, keys: [verificationMethodKey])

		let document =
			try! JSONSerialization.jsonObject(with: didDocument.data(using: .utf8)!)
			as! Dictionary<String, Any>
		let vmm = (document["verificationMethod"] as! [Dictionary<String, Any>])[0]

		#expect("did:web:test.example.com" == document["id"] as! String)
		// The key is used for keyAgreement, so it is published as JsonWebKey2020 /
		// publicKeyJwk (rather than multibase) with the JWK `kid` pinned to the
		// verification method id, so a JWE encryptor can address the exact key.
		#expect(
			[
				"https://www.w3.org/ns/did/v1",
				"https://w3id.org/security#JsonWebKey2020",
			] == document["@context"] as! [String]
		)
		#expect(["did:web:test.example.com#key-0"] == document["keyAgreement"] as! [String])

		#expect("did:web:test.example.com" == vmm["controller"] as! String)
		#expect("did:web:test.example.com#key-0" == vmm["id"] as! String)
		#expect("JsonWebKey2020" == vmm["type"] as! String)

		let jwk = vmm["publicKeyJwk"] as! Dictionary<String, Any>
		#expect("EC" == jwk["kty"] as! String)
		#expect("P-256" == jwk["crv"] as! String)
		#expect("did:web:test.example.com#key-0" == jwk["kid"] as! String)
		#expect(jwk["x"] is String)
		#expect(jwk["y"] is String)
	}
}