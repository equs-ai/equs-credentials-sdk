import Testing
import Foundation
import Swifter
@testable import EqusSdk

@Suite(.serialized) class UtilsTests {
	private var sdJwt = Fixtures.token("vc")

	@Test func parseClaims() async throws {
		let credential = CredentialData(
			format: VcFormat.sdJwtVc,
			payload: self.sdJwt
		)
		let result = try! await EqusSdk.parseClaims(credential: credential);

		// Independent expectation: a naive, unverified decode of the payload segment
		// (registered claims only -- "name" sits behind a disclosure `parseClaims` must merge
		// itself, so it isn't visible here). `name: "John"` is a fixed default the fixture
		// crate's SD-JWT VC builder always discloses; everything else (`sub`/`iss`/timestamps)
		// is a fresh value on every bundle regeneration.
		#expect("John" == result["name"]?.unquote())
		#expect(Fixtures.claim(self.sdJwt, "iat") == result["iat"])
		#expect(Fixtures.claim(self.sdJwt, "vct") == result["vct"]?.unquote())
		#expect(Fixtures.claim(self.sdJwt, "sub") == result["sub"]?.unquote())
		#expect(Fixtures.claim(self.sdJwt, "iss") == result["iss"]?.unquote())
		#expect(Fixtures.claim(self.sdJwt, "exp") == result["exp"])
		#expect(Fixtures.claim(self.sdJwt, "nbf") == result["nbf"])

	}
}
