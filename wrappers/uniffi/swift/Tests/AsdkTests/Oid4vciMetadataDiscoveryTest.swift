import Testing
import Foundation
import Swifter
@testable import Asdk

@Suite(.serialized) class Oid4vciMetadataDiscoveryTest {
    let server: HttpServer

    init() async throws {
        self.server = HttpServer()

        self.server["/.well-known/openid-credential-issuer"] = {
            request in
            return Swifter.HttpResponse.ok(
                .json(
                    try! JSONSerialization.jsonObject(
                        with: Oid4vciMetadataDiscoveryTestConstants.IssuerMetadata.data(using: .utf8)!)))
        }
        self.server["/auth/.well-known/openid-configuration"] = {
            request in
            return Swifter.HttpResponse.ok(
                .json(
                    try! JSONSerialization.jsonObject(
                        with: Oid4vciMetadataDiscoveryTestConstants.AuthServerMetadata)
                ))
        }
        try server.start(9010)
    }

    deinit {
        self.server.stop()
    }

    @Test func discoverIssuerMetadata() async throws {
        let metadata = try await MetadataDiscovery(httpClient: ReqwestHttpClient.insecure()).discoverIssuerMetadata(issuerUrl: "http://localhost:9010")

        compareJsonValues(
            actual: String(data: metadata.data(using: .utf8)!, encoding: .utf8)!,
            expected: Oid4vciMetadataDiscoveryTestConstants.IssuerMetadata)
    }

    @Test func discoverAuthServerMetadata() async throws {
        let metadata = try await MetadataDiscovery(httpClient: ReqwestHttpClient.insecure()).discoverAuthServerMetadata(serverUrl: "http://localhost:9010/auth")

        let actual =
            try! JSONSerialization.jsonObject(with: metadata.data(using: .utf8)!)
            as! Dictionary<String, Any>

        let expected =
            try! JSONSerialization.jsonObject(with: Oid4vciMetadataDiscoveryTestConstants.AuthServerMetadata)
            as! Dictionary<String, Any>


        #expect(actual["issuer"] as! String == expected["issuer"] as! String)
        #expect(actual["authorization_endpoint"] as! String == expected["authorization_endpoint"] as! String)
        #expect(actual["token_endpoint"] as! String == expected["token_endpoint"] as! String)
        #expect(actual["introspection_endpoint"] as! String == expected["introspection_endpoint"] as! String)
        #expect(actual["jwks_uri"] as! String == expected["jwks_uri"] as! String)
        #expect(actual["grant_types_supported"] as! [String] == expected["grant_types_supported"] as! [String])
        #expect(actual["response_types_supported"] as! [String] == expected["response_types_supported"] as! [String])
        #expect(actual["subject_types_supported"] as! [String] == expected["subject_types_supported"] as! [String])
        #expect(actual["id_token_signing_alg_values_supported"] as! [String] == expected["id_token_signing_alg_values_supported"] as! [String])
        #expect(actual["pushed_authorization_request_endpoint"] as! String == expected["pushed_authorization_request_endpoint"] as! String)
    }
}


enum Oid4vciMetadataDiscoveryTestConstants {
    static let CredDefId = "IDENTITY_SD_JWT"

    static let IssuerMetadata = """
		{"credential_issuer":"http://localhost:9010","authorization_servers":["http://localhost:9010/auth"],"credential_endpoint":"http://localhost:9010/credential","nonce_endpoint":"http://localhost:9010/nonce","batch_credential_issuance":{"batch_size":2},"credential_configurations_supported":{"\(CredDefId)":{"scope":"SD_JWT_cred","cryptographic_binding_methods_supported":["jwk"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"format":"dc+sd-jwt","credential_signing_alg_values_supported":["ES256"],"credential_metadata":{"claims":[{"path":["dob"],"mandatory":true,"display":[{"name":"Date of birth"}]},{"path":["given_name"],"mandatory":true,"display":[{"name":"Name"}]},{"path":["family_name"],"mandatory":true,"display":[{"name":"Surname"}]}]},"vct":"SD_JWT_cred"}}}
		"""

    static let AuthServerMetadata = """
		{"issuer":"http://localhost:9010/auth","authorization_endpoint":"http://localhost:9010/auth","token_endpoint":"http://localhost:9010/auth/token","introspection_endpoint":"http://localhost:9010/auth/introspection","jwks_uri":"http://localhost:9010/auth/jwks","grant_types_supported":["authorization_code"],"response_types_supported":["code","token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"],"pushed_authorization_request_endpoint":"http://localhost:9010/auth/par/request"}
		""".data(using: .utf8)!

}
