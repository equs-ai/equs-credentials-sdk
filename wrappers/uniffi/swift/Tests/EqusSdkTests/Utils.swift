import Testing
import Foundation
import Swifter
@testable import EqusSdk

@Suite(.serialized) class UtilsTests {
	private var sdJwt = Fixtures.identitySdJwt

	@Test func parseClaims() async throws {
		let credential = CredentialData(
			format: VcFormat.sdJwtVc,
			payload: self.sdJwt
		)
		let result = try! await EqusSdk.parseClaims(credential: credential);

		#expect("John" == result["name"]?.unquote())
		#expect("1728882611" == result["iat"])
		#expect("https://credentials.example.com/identity_credential" == result["vct"]?.unquote())
		#expect(Fixtures.didKey(.holder) == result["sub"]?.unquote())
		#expect(Fixtures.didKey(.issuer) == result["iss"]?.unquote())
		#expect("1760418611" == result["exp"])
		#expect("1728882611" == result["nbf"])

	}
}
