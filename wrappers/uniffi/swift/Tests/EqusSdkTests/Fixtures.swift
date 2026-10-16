import CryptoKit
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

	static func base64UrlDecode(_ text: String) -> Data {
		var base64 = text
			.replacingOccurrences(of: "-", with: "+")
			.replacingOccurrences(of: "_", with: "/")
		base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
		return Data(base64Encoded: base64)!
	}

	static func jsonObject(_ text: String) -> [String: Any] {
		try! JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any]
	}

	/// base64url SHA-256 of `text`, the SD-JWT digest.
	static func sha256(_ text: String) -> String {
		Data(SHA256.hash(data: Data(text.utf8))).base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}

	/// The `cnf.jwk` of an issuer-signed JWT: the key its holder signs with.
	static func cnfJwk(_ jwt: String) -> [String: Any] {
		(jwtParts(jwt).payload["cnf"] as? [String: Any])?["jwk"] as? [String: Any] ?? [:]
	}

	/// Whether `jws` carries a valid ES256 signature by the P-256 `jwk`.
	static func verifiesEs256(_ jws: String, jwk: [String: Any]) -> Bool {
		let parts = jws.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
		guard parts.count == 3, let x = jwk["x"] as? String, let y = jwk["y"] as? String,
			let key = try? P256.Signing.PublicKey(rawRepresentation: base64UrlDecode(x) + base64UrlDecode(y)),
			let signature = try? P256.Signing.ECDSASignature(rawRepresentation: base64UrlDecode(parts[2]))
		else { return false }
		return key.isValidSignature(signature, for: Data("\(parts[0]).\(parts[1])".utf8))
	}

	/// Header and payload of a compact JWT; a part that is not a JSON object comes back empty.
	static func jwtParts(_ jwt: String) -> (header: [String: Any], payload: [String: Any]) {
		let parts = jwt.split(separator: ".", omittingEmptySubsequences: false).prefix(2).map { part in
			(try? JSONSerialization.jsonObject(with: base64UrlDecode(String(part)))) as? [String: Any] ?? [:]
		}
		return (parts.first ?? [:], parts.count > 1 ? parts[1] : [:])
	}

	static let identitySdJwt: String = try! fixtureSdJwt(
		headerJson: #"{"typ":"vc+sd-jwt","alg":"ES256","kid":"\#(didKeyUrl(.issuer))"}"#,
		claimsJson: #"{"vct":"https://credentials.example.com/identity_credential","sub":"\#(didKey(.holder))","nbf":1728882611,"_sd_alg":"sha-256","iss":"\#(didKey(.issuer))","iat":1728882611,"exp":1760418611,"cnf":{"jwk":\#(publicJwk(.holder))}}"#,
		disclosures: [#"["8zQfBB-KqYHuJqnpTDvsUQ", "name", "John"]"#],
		role: .issuer
	)
}
