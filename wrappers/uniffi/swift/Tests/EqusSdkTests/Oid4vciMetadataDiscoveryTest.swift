import Testing
import Foundation
@testable import EqusSdk

@Suite(.serialized) class Oid4vciMetadataDiscoveryTest {
    let http: MockHttpRouter
    let port: in_port_t

    init() async throws {
        self.http = MockHttpRouter()
        // No socket is bound; the router matches on path, so the port only has to
        // make the fixture URLs well-formed.
        self.port = 9000

        let issuerMetadata = Oid4vciMetadataDiscoveryTestConstants.issuerMetadata(port: port)
        let authServerMetadata = Oid4vciMetadataDiscoveryTestConstants.authServerMetadata(port: port)

        self.http["/.well-known/openid-credential-issuer"] = { _ in
            MockHttpRouter.ok(issuerMetadata)
        }
        self.http["/.well-known/oauth-authorization-server/auth"] = { _ in
            MockHttpRouter.ok(String(data: authServerMetadata, encoding: .utf8)!)
        }
    }


    @Test func discoverIssuerMetadata() async throws {
        let metadata = try await MetadataDiscovery(httpClient: http).discoverIssuerMetadata(issuerUrl: "http://localhost:\(port)")

        compareJsonValues(
            actual: String(data: metadata.data(using: .utf8)!, encoding: .utf8)!,
            expected: Oid4vciMetadataDiscoveryTestConstants.issuerMetadata(port: port))
    }

    @Test func discoverAuthServerMetadata() async throws {
        let metadata = try await MetadataDiscovery(httpClient: http).discoverAuthServerMetadata(serverUrl: "http://localhost:\(port)/auth")

        let actual =
            try! JSONSerialization.jsonObject(with: metadata.data(using: .utf8)!)
            as! Dictionary<String, Any>

        let expected =
            try! JSONSerialization.jsonObject(with: Oid4vciMetadataDiscoveryTestConstants.authServerMetadata(port: port))
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

    static func issuerMetadata(port: in_port_t) -> String {
        """
        {"credential_issuer":"http://localhost:\(port)","authorization_servers":["http://localhost:\(port)/auth"],"credential_endpoint":"http://localhost:\(port)/credential","nonce_endpoint":"http://localhost:\(port)/nonce","batch_credential_issuance":{"batch_size":2},"credential_configurations_supported":{"\(CredDefId)":{"scope":"SD_JWT_cred","cryptographic_binding_methods_supported":["jwk"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"format":"dc+sd-jwt","credential_signing_alg_values_supported":["ES256"],"credential_metadata":{"claims":[{"path":["dob"],"mandatory":true,"display":[{"name":"Date of birth"}]},{"path":["given_name"],"mandatory":true,"display":[{"name":"Name"}]},{"path":["family_name"],"mandatory":true,"display":[{"name":"Surname"}]}]},"vct":"SD_JWT_cred"}}}
        """
    }

    static func authServerMetadata(port: in_port_t) -> Data {
        """
        {"issuer":"http://localhost:\(port)/auth","authorization_endpoint":"http://localhost:\(port)/auth","token_endpoint":"http://localhost:\(port)/auth/token","introspection_endpoint":"http://localhost:\(port)/auth/introspection","jwks_uri":"http://localhost:\(port)/auth/jwks","grant_types_supported":["authorization_code"],"response_types_supported":["code","token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"],"pushed_authorization_request_endpoint":"http://localhost:\(port)/auth/par/request"}
        """.data(using: .utf8)!
    }
}
