import Testing
import Foundation
import Swifter
@testable import Asdk

@Suite(.serialized) class Oid4vciHolderTests {
	let server: HttpServer

	init() async throws {
		self.server = HttpServer()

		self.server["/.well-known/openid-credential-issuer"] = { request in
            return Swifter.HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: Oid4vciHolderTestConstants.IssuerMetadata.data(using: .utf8)!)))
		}
		self.server["/auth/.well-known/openid-configuration"] = { request in
            return Swifter.HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: Oid4vciHolderTestConstants.AuthServerMetadata)
				))
		}
		self.server["/auth/par/request"] = { request in
            return Swifter.HttpResponse.raw(
				201,
				"Created",
				["Content-Type": "application/json"],
				{ writer in
					try writer.write([UInt8](Oid4vciHolderTestConstants.CodeResponse))
				}
			)
		}
		self.server["/auth/token"] = { request in
            return Swifter.HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: Oid4vciHolderTestConstants.AccessTokenResponse)
				))
		}
		self.server["/credential"] = { request in
            let body = String(decoding: request.body, as: UTF8.self)
            if body.contains("proofs") {
                return Swifter.HttpResponse.ok(
                    .json(
                        try! JSONSerialization.jsonObject(
                            with: Oid4vciHolderTestConstants.BatchCredentialResponse)
                ))
            }

            return Swifter.HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: Oid4vciHolderTestConstants.CredentialResponse)
				))
		}
		self.server["/nonce"] = { request in
            return Swifter.HttpResponse.ok(
				.json(
					try! JSONSerialization.jsonObject(
						with: Oid4vciHolderTestConstants.NonceResponse)
				))
		}
		try server.start(9000)
	}

	deinit {
		self.server.stop()
	}

	@Test func retrieveIssuerMetadata() async throws {
		let holder = await self.buildHolder()
		let metadata = try holder.getIssuerMetadata().data(using: .utf8)!

		compareJsonValues(
			actual: String(data: metadata, encoding: .utf8)!,
			expected: Oid4vciHolderTestConstants.IssuerMetadata)
	}

	@Test func authorizeUsingAuthCode() async throws {
		let holder = await self.buildHolder()

		let tokenResponse = try await holder.authzCodeFlowWithScope(
			scope: "SD_JWT_cred", authorizationCodeCallback: AuthorizationCodeCallback())

		#expect(tokenResponse.accessToken == Oid4vciHolderTestConstants.AccessToken)
	}

	@Test func getAccessTokenByUsingResolvedCredentialOfferWithPreAuthorizedCodeGrant() async throws
	{
		let holder = await self.buildHolder()

		let result = try await holder.getAccessToken(
			offerParams: Oid4vciHolderTestConstants.CredentialOfferWithPreAuthGrant,
			authorizationCallback: PreAuthorizationCallback()
		)
		#expect(result.accessToken == Oid4vciHolderTestConstants.AccessToken)

	}

	@Test func getAccessTokenByUsingResolvedCredentialOfferWithAuthorizationCodeGrant() async throws
	{
		let holder = await self.buildHolder()

		let result = try await holder.getAccessToken(
			offerParams: Oid4vciHolderTestConstants.CredentialOfferWithAuthGrant,
			authorizationCallback: AuthorizationCallback()
		)

		#expect(result.accessToken == Oid4vciHolderTestConstants.AccessToken)
	}

	@Test func requestCredential() async throws {
		let kms = InMemKms()
		let vault = InMemVault()
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.CredentialOffer),
            httpClient: ReqwestHttpClient.insecure(),
            pop: ProofOfPossessionMetadataBuilder().withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300)).withLifetime(lifetime: 10)
                            .build()
		).build()

		let didAndKeyMetadata = await createDidAndKeyMetadata(kms: kms)

		let credResponse = try await holder.requestCredential(
			token: Oid4vciHolderTestConstants.AccessToken,
			credDefId: Oid4vciHolderTestConstants.CredDefId,
			keyMetadata: [didAndKeyMetadata.keyMetadata])

		#expect(
			credResponse.data
				== .immediate(
					credentials: [
					    Credential(
					        format: VcFormat.sdJwtVc,
					        payload: Oid4vciHolderTestConstants.CredentialResponseImmediatePayload
					    )
					],
					notificationId: "1111"))

	}

	@Test func requestMultipleCredentials() async throws {
		let kms = InMemKms()
		let vault = InMemVault()
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.CredentialOffer),
            httpClient: ReqwestHttpClient.insecure(),
            pop: ProofOfPossessionMetadataBuilder().withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300)).withLifetime(lifetime: 10)
                            .build()
		).build()

		let didAndKeyMetadata1 = await createDidAndKeyMetadata(kms: kms)
		let didAndKeyMetadata2 = await createDidAndKeyMetadata(kms: kms)

		let credResponse = try await holder.requestCredential(
			token: Oid4vciHolderTestConstants.AccessToken,
			credDefId: Oid4vciHolderTestConstants.CredDefId,
			keyMetadata: [didAndKeyMetadata1.keyMetadata, didAndKeyMetadata2.keyMetadata])

		#expect(
			credResponse.data
				== .immediate(
					credentials: [
					    Credential(
					        format: VcFormat.sdJwtVc,
					        payload: Oid4vciHolderTestConstants.CredentialResponseImmediatePayload
					    ),
					     Credential(
					        format: VcFormat.sdJwtVc,
					        payload: Oid4vciHolderTestConstants.CredentialResponseImmediatePayload
					    )
					],
					notificationId: "1111"))

	}

	@Test func storeCredential() async throws {
		let vault = InMemVault();
		let kms = InMemKms();
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.CredentialOffer),
            httpClient: ReqwestHttpClient.insecure(),
            pop: ProofOfPossessionMetadataBuilder().withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300)).withLifetime(lifetime: 10)
                                 .build()
		).build()

		let credential = Credential(
			format: VcFormat.sdJwtVc,
			payload: Oid4vciHolderTestConstants.CredentialResponseImmediatePayload)

		var didAndKeyMetadata = await createDidAndKeyMetadata(kms: kms)
        didAndKeyMetadata.keyMetadata.didUrl = "did:key:zDnaenpntCkXnDCnaDk62LxNqPc4CMd32fbhiVsZV5KpPTG2c#zDnaenpntCkXnDCnaDk62LxNqPc4CMd32fbhiVsZV5KpPTG2c"

		let metadata = try await resolveMetadata(
			credential: credential, metadata: didAndKeyMetadata.keyMetadata);

		let id = try await holder.storeCredential(
			credential: credential, credentialMetadata: metadata);

		let credentialEntry = try await vault.getCredential(id: id)!

		#expect(credentialEntry.credential == credential)
		#expect(credentialEntry.kid == didAndKeyMetadata.keyMetadata.kid)
		#expect(credentialEntry.id == id)
	}

	private func buildHolder() async -> Oid4vciHolder {
		return try! await Oid4vciHolderBuilder(
			kms: InMemKms(), vault: InMemVault(), clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.CredentialOffer),
            httpClient: ReqwestHttpClient.insecure(),
            pop: ProofOfPossessionMetadataBuilder().withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300)).withLifetime(lifetime: 10)
                                 .build()
		).build()
	}
}

final class AuthorizationCodeCallback: AuthCodeCallback {
	func authenticate(url: String) async throws -> String {
		#expect(
			url
				== "http://localhost:9000/auth?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Acode&client_id=client_id"
		)
		return "code";

	}
}

final class PreAuthorizationCallback: AuthCallback {
	func authenticate(authzFlow: AuthzFlow) async throws -> String {
		guard case .preauthorized = authzFlow else {
			throw NSError(domain: "Preauthorized AuthzFlow", code: 1)
		}
		return "code";

	}
}

final class AuthorizationCallback: AuthCallback {
	func authenticate(authzFlow: AuthzFlow) async throws -> String {
		guard case .authorize(_) = authzFlow else {
			throw NSError(domain: "Authorized AuthzFlow", code: 1)
		}

		return "code";

	}
}

enum Oid4vciHolderTestConstants {

	static let CredDefId = "IDENTITY_SD_JWT"

	static let AccessToken =
		"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA"

	static let CredentialOffer = """
		{"credential_issuer": "http://localhost:9000","credential_configuration_ids": ["\(CredDefId)"],"grants": {"authorization_code": {"issuer_state": null,"authorization_server": null}}}
		"""

	static let CredentialOfferWithPreAuthGrant = """
			{"credential_issuer":"http://localhost:9000","credential_configuration_ids":["\(CredDefId)"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code","tx_code":null,"interval":null,"authorization_server":"http://localhost:9000/auth"}}}
		"""

	static let CredentialOfferWithAuthGrant = """
			{"credential_issuer":"http://localhost:9000","credential_configuration_ids":["\(CredDefId)"],"grants":{"authorization_code":{"issuer_state":"state"}}}
		"""

	static let IssuerMetadata = """
		{"credential_issuer":"http://localhost:9000","authorization_servers":["http://localhost:9000/auth"],"credential_endpoint":"http://localhost:9000/credential","nonce_endpoint":"http://localhost:9000/nonce","batch_credential_issuance":{"batch_size":2},"credential_configurations_supported":{"\(CredDefId)":{"scope":"SD_JWT_cred","cryptographic_binding_methods_supported":["jwk"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"format":"dc+sd-jwt","credential_signing_alg_values_supported":["ES256"],"claims":[{"path":["dob"],"mandatory":true,"display":[{"name":"Date of birth"}]},{"path":["given_name"],"mandatory":true,"display":[{"name":"Name"}]},{"path":["family_name"],"mandatory":true,"display":[{"name":"Surname"}]}],"vct":"SD_JWT_cred"}}}
		"""

	static let AuthServerMetadata = """
		{"issuer":"http://localhost:9000/auth","authorization_endpoint":"http://localhost:9000/auth","token_endpoint":"http://localhost:9000/auth/token","introspection_endpoint":"http://localhost:9000/auth/introspection","jwks_uri":"http://localhost:9000/auth/jwks","grant_types_supported":["authorization_code"],"response_types_supported":["code","token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"],"pushed_authorization_request_endpoint":"http://localhost:9000/auth/par/request"}
		""".data(using: .utf8)!

	static let CodeResponse = """
		{"request_uri": "urn:ietf:params:oauth:request_uri:code","expires_in": 86400}
		""".data(using: .utf8)!

	static let AccessTokenResponse = """
		{"access_token": "\(AccessToken)","token_type": "bearer","expires_in": 86400}
		""".data(using: .utf8)!

	static let CredentialResponseImmediatePayload =
		"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~"

	static let CredentialResponse = """
		{"credentials":[{"credential": "\(CredentialResponseImmediatePayload)"}], "notification_id":"1111"}
		""".data(using: .utf8)!

	static let BatchCredentialResponse = """
		{"credentials":[{"credential": "\(CredentialResponseImmediatePayload)"}, {"credential": "\(CredentialResponseImmediatePayload)"}], "notification_id":"1111"}
		""".data(using: .utf8)!

	static let NonceResponse = """
		{"c_nonce":"0GtZieAoAL_3Zafyn6TgCA"}
		""".data(using: .utf8)!
}
