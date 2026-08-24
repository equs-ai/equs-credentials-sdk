import Foundation
import Testing
@testable import EqusSdk

@Suite(.serialized) class VCCoreCredentialSignerTests {

    @Test func signsSdJwtUnsignedViaExternallyTaggedWireFormat() async throws {
        let kms = InMemKms()

        let issuer = await createDidAndKeyMetadata(kms: kms)
        let holder = await createDidAndKeyMetadata(kms: kms)

        let holderKeyHandle = try await kms.get(kid: holder.keyMetadata.kid)
        guard let holderJwk = holderKeyHandle.inner.jwk() else {
            Issue.record("holder key handle should expose a JWK")
            return
        }

        let now = Int(Date().timeIntervalSince1970)
        let exp = now + 60 * 60 * 24 * 365

        let unsignedJson = """
        {
          "SdJwt": {
            "claims": {
              "iss": "\(issuer.did)",
              "sub": "\(holder.did)",
              "vct": "https://example.com/credentials/test",
              "iat": \(now),
              "nbf": \(now),
              "exp": \(exp),
              "name": "Alice"
            },
            "disclosure_strategy": "AllLevels",
            "holder_key": \(holderJwk),
            "extra_headers": {
              "typ": "vc+sd-jwt",
              "kid": "\(issuer.keyMetadata.didUrl)"
            },
            "issuer_key_id": "\(issuer.keyMetadata.kid)"
          }
        }
        """

        let resolver = try UniversalDidResolver(resolvers: nil)
        let signer = VcCoreCredentialSigner(kms: kms, didResolver: resolver)

        let credential = try await signer.signCredential(unsignedCredential: unsignedJson)

        #expect(credential.format == VcFormat.sdJwtVc)
        // Compact SD-JWT: 3 base64url segments separated by '.', then disclosures with '~'.
        let pattern = #"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~"#
        #expect(credential.payload.range(of: pattern, options: .regularExpression) != nil,
                "unexpected SD-JWT payload shape: \(credential.payload)")
    }
}
