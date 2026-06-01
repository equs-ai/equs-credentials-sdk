import Testing
import Foundation
import Swifter
@testable import Asdk

@Suite(.serialized) class CredentialOfferResolverTests {
	let server: HttpServer
	let port: in_port_t

	init() async throws {
		self.server = HttpServer()
		// Bind to port 0 so the OS picks a guaranteed-free port; avoids collisions
		// with whatever else (CI runner, prior job, etc.) might hold a fixed port.
		// forceIPv4 keeps reqwest's 127.0.0.1 connect path reachable under the iOS Simulator.
		try server.start(0, forceIPv4: true)
		self.port = in_port_t(try server.port())

		let authServerMetadata = CredentialOfferResolverTestConstants.authServerMetadata(port: port)
		let credOffer = CredentialOfferResolverTestConstants.credOfferWithPreAuthGrant(port: port)

		self.server["/.well-known/oauth-authorization-server/auth"] = { request in
			return HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: authServerMetadata.data(using: .utf8)!)))
		}
		self.server["/credential_offer"] = { request in
			return HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: credOffer.data(using: .utf8)!)
				))
		}
	}

	// No deinit { server.stop() }: Swifter 1.5.0's HttpServer.stop() can race with its
	// background accept loop and crash xctest. With rotating ports, the previous test's
	// server stays alive on its unused port until process exit; harmless.

	@Test func resolveOfferByReferenceWithPreAuthorizedCodeGrant() async throws {
		let resolver = try? CredentialOfferResolver(httpClient: ReqwestHttpClient.insecure())

		let resolvedOffer = try? await resolver?.resolve(
			offerUri:
				"openid-credential-offer://?credential_offer_uri=http://localhost:\(port)/credential_offer"
		)

		compareJsonValues(
			actual: resolvedOffer!,
			expected: CredentialOfferResolverTestConstants.credOfferWithPreAuthGrant(port: port))
	}

	@Test func resolveOfferByValueWithPreAuthorizedCodeGrant() async throws {
		let resolver = try? CredentialOfferResolver(httpClient: ReqwestHttpClient.insecure())

		let resolvedOffer = try? await resolver?.resolve(
			offerUri:
				"openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:\(port)%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22authorization_server%22:%22http://localhost:\(port)/auth%22}},%22extra_field%22:%22extra_value%22}"
		)

		compareJsonValues(
			actual: resolvedOffer!,
			expected: CredentialOfferResolverTestConstants.credOfferWithPreAuthGrant(port: port))
	}
}

enum CredentialOfferResolverTestConstants {
	static func authServerMetadata(port: in_port_t) -> String {
		"{\"issuer\":\"http://localhost:\(port)/auth\",\"authorization_endpoint\":\"http://localhost:\(port)/auth\",\"token_endpoint\":\"http://localhost:\(port)/auth/token\",\"introspection_endpoint\":\"http://localhost:\(port)/auth/introspection\",\"jwks_uri\":\"http://localhost:\(port)/auth/jwks\",\"grant_types_supported\":[\"authorization_code\"],\"response_types_supported\":[\"code\",\"token\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"ES256\"],\"pushed_authorization_request_endpoint\":\"http://localhost:\(port)/auth/par/request\"}"
	}

	static func credOfferWithPreAuthGrant(port: in_port_t) -> String {
		"{\"credential_issuer\":\"http://localhost:\(port)\",\"credential_configuration_ids\":[\"IDENTITY_SD_JWT\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"code\",\"authorization_server\":\"http://localhost:\(port)/auth\"}},\"extra_field\":\"extra_value\"}"
	}
}
