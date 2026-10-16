import Testing
import Foundation
@testable import EqusSdk

@Suite(.serialized) class CredentialOfferResolverTests {
	let http: MockHttpRouter
	let port: in_port_t

	init() async throws {
		self.http = MockHttpRouter()
		// No socket is bound; the router matches on path, so the port only has to
		// make the fixture URLs well-formed.
		self.port = 9000

		let authServerMetadata = CredentialOfferResolverTestConstants.authServerMetadata(port: port)
		let credOffer = CredentialOfferResolverTestConstants.credOfferWithPreAuthGrant(port: port)

		self.http["/.well-known/oauth-authorization-server/auth"] = { _ in
			MockHttpRouter.ok(authServerMetadata)
		}
		self.http["/credential_offer"] = { _ in
			MockHttpRouter.ok(credOffer)
		}
	}


	@Test func resolveOfferByReferenceWithPreAuthorizedCodeGrant() async throws {
		let resolver = try? CredentialOfferResolver(httpClient: http)

		let resolvedOffer = try? await resolver?.resolve(
			offerUri:
				"openid-credential-offer://?credential_offer_uri=http://localhost:\(port)/credential_offer"
		)

		compareJsonValues(
			actual: resolvedOffer!,
			expected: CredentialOfferResolverTestConstants.credOfferWithPreAuthGrant(port: port))
	}

	@Test func resolveOfferByValueWithPreAuthorizedCodeGrant() async throws {
		let resolver = try? CredentialOfferResolver(httpClient: http)

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
