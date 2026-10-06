import Foundation
@testable import EqusSdk

enum Fixtures {
	static func didKey(_ role: FixtureKey) -> String { fixtureDidKey(role: role) }
	static func didKeyUrl(_ role: FixtureKey) -> String { fixtureDidKeyUrl(role: role) }
	static func publicJwk(_ role: FixtureKey) -> String { try! fixturePublicJwk(role: role) }

	static func kid(_ role: FixtureKey) -> String {
		let jwk = try! JSONSerialization.jsonObject(with: Data(publicJwk(role).utf8)) as! [String: Any]
		return jwk["kid"] as! String
	}

	static func base64Url(_ text: String) -> String {
		Data(text.utf8).base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}

	static let identitySdJwt: String = try! fixtureSdJwt(
		headerJson: #"{"typ":"vc+sd-jwt","alg":"ES256","kid":"\#(didKeyUrl(.issuer))"}"#,
		claimsJson: #"{"vct":"https://credentials.example.com/identity_credential","sub":"\#(didKey(.holder))","nbf":1728882611,"_sd_alg":"sha-256","iss":"\#(didKey(.issuer))","iat":1728882611,"exp":1760418611,"cnf":{"jwk":\#(publicJwk(.holder))}}"#,
		disclosures: [#"["8zQfBB-KqYHuJqnpTDvsUQ", "name", "John"]"#],
		role: .issuer
	)
}
