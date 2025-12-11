import Testing
import Foundation
import Swifter
@testable import Asdk

@Suite(.serialized) class CredentialOfferResolverTests {
	let server: HttpServer

	init() async throws {
		self.server = HttpServer()

		self.server["/.well-known/oauth-authorization-server/auth"] = { request in
			return HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: CredentialOfferResolverTestConstants.AuthServerMetadata.data(
							using: .utf8)!)))
		}
		self.server["/credential_offer"] = { request in
			return HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: CredentialOfferResolverTestConstants.CredOfferWithPreAuthGrant.data(
							using: .utf8)!)
				))
		}
		try server.start(9002)
	}

	deinit {
		self.server.stop()
	}

	@Test func resolveOfferByReferenceWithPreAuthorizedCodeGrant() async throws {
		let resolver = try? CredentialOfferResolver(httpClient: ReqwestHttpClient.insecure())

		let resolvedOffer = try? await resolver?.resolve(
			offerUri:
				"openid-credential-offer://?credential_offer_uri=http://localhost:9002/credential_offer"
		)

		compareJsonValues(
			actual: resolvedOffer!,
			expected: CredentialOfferResolverTestConstants.CredOfferWithPreAuthGrant)
	}

	@Test func resolveOfferByValueWithPreAuthorizedCodeGrant() async throws {
		let resolver = try? CredentialOfferResolver(httpClient: ReqwestHttpClient.insecure())

		let resolvedOffer = try? await resolver?.resolve(
			offerUri:
				"openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9002%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22authorization_server%22:%22http://localhost:9002/auth%22}},%22extra_field%22:%22extra_value%22}"
		)

		compareJsonValues(
			actual: resolvedOffer!,
			expected: CredentialOfferResolverTestConstants.CredOfferWithPreAuthGrant)
	}
}

enum CredentialOfferResolverTestConstants {
	static let AuthServerMetadata =
		"{\"issuer\":\"http://localhost:9002/auth\",\"authorization_endpoint\":\"http://localhost:9002/auth\",\"token_endpoint\":\"http://localhost:9002/auth/token\",\"introspection_endpoint\":\"http://localhost:9002/auth/introspection\",\"jwks_uri\":\"http://localhost:9002/auth/jwks\",\"grant_types_supported\":[\"authorization_code\"],\"response_types_supported\":[\"code\",\"token\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"ES256\"],\"pushed_authorization_request_endpoint\":\"http://localhost:9002/auth/par/request\"}"

	static let CredOfferWithPreAuthGrant =
		"{\"credential_issuer\":\"http://localhost:9002\",\"credential_configuration_ids\":[\"IDENTITY_SD_JWT\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"code\",\"authorization_server\":\"http://localhost:9002/auth\"}},\"extra_field\":\"extra_value\"}"
}
