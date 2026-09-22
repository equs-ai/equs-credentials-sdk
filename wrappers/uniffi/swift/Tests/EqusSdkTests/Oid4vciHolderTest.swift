import Testing
import Foundation
@testable import EqusSdk

@Suite(.serialized) class Oid4vciHolderTests {
	let http: MockHttpRouter
	let port: in_port_t

	init() async throws {
		self.http = MockHttpRouter()
		// No socket is bound; the router matches on path, so the port only has to
		// make the fixture URLs well-formed.
		self.port = 9000

		let issuerMetadata = Oid4vciHolderTestConstants.issuerMetadata(port: port)
		let authServerMetadata = Oid4vciHolderTestConstants.authServerMetadata(port: port)

		self.http["/.well-known/openid-credential-issuer"] = { _ in
			MockHttpRouter.ok(issuerMetadata)
		}
		self.http["/.well-known/oauth-authorization-server/auth"] = { _ in
			MockHttpRouter.ok(String(data: authServerMetadata, encoding: .utf8)!)
		}
		self.http["/auth/par/request"] = { _ in
			EqusSdk.HttpResponse(
				statusCode: 201,
				headers: ["content-type": "application/json"],
				body: String(data: Oid4vciHolderTestConstants.CodeResponse, encoding: .utf8)!)
		}
		self.http["/auth/token"] = { _ in
			MockHttpRouter.ok(String(data: Oid4vciHolderTestConstants.AccessTokenResponse, encoding: .utf8)!)
		}
		self.http["/credential"] = { _ in
			MockHttpRouter.ok(String(data: Oid4vciHolderTestConstants.BatchCredentialResponse, encoding: .utf8)!)
		}
		self.http["/deferred_credential"] = { _ in
			MockHttpRouter.ok(String(data: Oid4vciHolderTestConstants.DeferredCredentialResponse, encoding: .utf8)!)
		}
		self.http["/notification"] = { _ in
			MockHttpRouter.ok("", contentType: "text/plain")
		}
		self.http["/nonce"] = { _ in
			MockHttpRouter.ok(String(data: Oid4vciHolderTestConstants.NonceResponse, encoding: .utf8)!)
		}
	}


	@Test func retrieveIssuerMetadata() async throws {
		let holder = try await self.buildHolder()
		let metadata = try holder.getIssuerMetadata().data(using: .utf8)!

		compareJsonValues(
			actual: String(data: metadata, encoding: .utf8)!,
			expected: Oid4vciHolderTestConstants.issuerMetadata(port: port))
	}

	@Test func authorizeUsingAuthCode() async throws {
		let holder = try await self.buildHolder()

		let tokenResponse = try await holder.authzCodeFlowWithScope(
			scope: "SD_JWT_cred", authorizationCodeCallback: AuthorizationCodeCallback(port: port))

		#expect(tokenResponse.accessToken == Oid4vciHolderTestConstants.AccessToken)
	}

	@Test func getAccessTokenByUsingResolvedCredentialOfferWithPreAuthorizedCodeGrant() async throws
	{
		let holder = try await self.buildHolder()

		let result = try await holder.getAccessToken(
			offerParams: Oid4vciHolderTestConstants.credentialOfferWithPreAuthGrant(port: port),
			authorizationCallback: PreAuthorizationCallback()
		)
		#expect(result.accessToken == Oid4vciHolderTestConstants.AccessToken)

	}

	@Test func getAccessTokenByUsingResolvedCredentialOfferWithAuthorizationCodeGrant() async throws
	{
		let holder = try await self.buildHolder()

		let result = try await holder.getAccessToken(
			offerParams: Oid4vciHolderTestConstants.credentialOfferWithAuthGrant(port: port),
			authorizationCallback: AuthorizationCallback()
		)

		#expect(result.accessToken == Oid4vciHolderTestConstants.AccessToken)
	}

	@Test func requestMultipleCredentials() async throws {
		let kms = InMemKms()
		let vault = InMemVault()
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.credentialOffer(port: port)),
      httpClient: http,
      pop: ProofOfPossessionMetadataBuilder()
        .withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300))
        .withLifetime(lifetime: 10)
        .build(),
      credentialExtraVerification: nil
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

	@Test func requestDeferredCredentials() async throws {
		let kms = InMemKms()
		let vault = InMemVault()
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.credentialOffer(port: port)),
            httpClient: http,
            pop: ProofOfPossessionMetadataBuilder()
              .withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300))
              .withLifetime(lifetime: 10)
              .build(),
            credentialExtraVerification: nil
        ).build()

		let credResponse = try await holder.requestDeferredCredential(
			token: Oid4vciHolderTestConstants.AccessToken,
			transactionId: "transaction_id",
	    )

		#expect(
			credResponse.data == CredentialResult.deferred(
				transactionId: "8xLOxBtZp8",
				interval: 300
			)
		)
	}

	@Test func sendNotification() async throws {
		let kms = InMemKms()
		let vault = InMemVault()
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.credentialOffer(port: port)),
            httpClient: http,
            pop: ProofOfPossessionMetadataBuilder()
              .withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300))
              .withLifetime(lifetime: 10)
              .build(),
            credentialExtraVerification: nil
        ).build()

        try await holder.sendNotification(
			token: Oid4vciHolderTestConstants.AccessToken,
            notification: Notification(
			    notificationId: "3fwe98js",
			    event: NotificationEvent.credentialAccepted,
			    eventDescription: "Issued credential has been accepted"
			)
	    )
	}

	@Test func verifyCredentialExtra() async throws {
		// SdJwtCredentialDidWebIss is a pre-signed JWT with iss=did:web:localhost%3A9000,
		// so this test must present metadata for port 9000 for the
		// credentialIssuerIdentifier check to match.
		let fixedPort: in_port_t = 9000
		let extraHttp = MockHttpRouter()
		let extraIssuerMetadata = Oid4vciHolderTestConstants.issuerMetadata(port: fixedPort)
		let extraAuthServerMetadata = Oid4vciHolderTestConstants.authServerMetadata(port: fixedPort)
		extraHttp["/.well-known/openid-credential-issuer"] = { _ in
			MockHttpRouter.ok(extraIssuerMetadata)
		}
		extraHttp["/.well-known/oauth-authorization-server/auth"] = { _ in
			MockHttpRouter.ok(String(data: extraAuthServerMetadata, encoding: .utf8)!)
		}

		let vault = InMemVault();
		let kms = InMemKms();
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.credentialOffer(port: fixedPort)),
      httpClient: extraHttp,
      pop: ProofOfPossessionMetadataBuilder()
        .withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300))
        .withLifetime(lifetime: 10)
        .build(),
      credentialExtraVerification: [CredentialExtraVerification.credentialIssuerIdentifier]
		).build()

    let credential = Credential(
      format: VcFormat.sdJwtVc,
      payload: Oid4vciHolderTestConstants.SdJwtCredentialDidWebIss);

    try await holder.verifyCredentialExtra(
      credential: credential
    )
	}

	@Test func storeCredential() async throws {
		let vault = InMemVault();
		let kms = InMemKms();
		let holder = try await Oid4vciHolderBuilder(
			kms: kms,
			vault: vault,
			clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.credentialOffer(port: port)),
            httpClient: http,
      pop: ProofOfPossessionMetadataBuilder()
        .withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300))
        .withLifetime(lifetime: 10)
        .build(),
      credentialExtraVerification: nil
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

	private func buildHolder() async throws -> Oid4vciHolder {
		try await Oid4vciHolderBuilder(
			kms: InMemKms(), vault: InMemVault(), clientId: "client_id",
			issuerDiscovery: IssuerDiscovery.offer(Oid4vciHolderTestConstants.credentialOffer(port: port)),
			httpClient: http,
			pop: ProofOfPossessionMetadataBuilder()
				.withNotBefore(notBefore: ProofOfPossessionNotBefore.leeway(300))
				.withLifetime(lifetime: 10)
				.build(),
			credentialExtraVerification: nil
		).build()
	}
}

final class AuthorizationCodeCallback: AuthCodeCallback {
	let port: in_port_t

	init(port: in_port_t) {
		self.port = port
	}

	func authenticate(url: String) async throws -> String {
		#expect(
			url
				== "http://localhost:\(port)/auth?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Acode&client_id=client_id"
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

	static func credentialOffer(port: in_port_t) -> String {
		"""
		{"credential_issuer": "http://localhost:\(port)","credential_configuration_ids": ["\(CredDefId)"],"grants": {"authorization_code": {"issuer_state": null,"authorization_server": null}}}
		"""
	}

	static func credentialOfferWithPreAuthGrant(port: in_port_t) -> String {
		"""
		{"credential_issuer":"http://localhost:\(port)","credential_configuration_ids":["\(CredDefId)"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code","tx_code":null,"interval":null,"authorization_server":"http://localhost:\(port)/auth"}}}
		"""
	}

	static func credentialOfferWithAuthGrant(port: in_port_t) -> String {
		"""
		{"credential_issuer":"http://localhost:\(port)","credential_configuration_ids":["\(CredDefId)"],"grants":{"authorization_code":{"issuer_state":"state"}}}
		"""
	}

	static func issuerMetadata(port: in_port_t) -> String {
		"""
		{"credential_issuer":"http://localhost:\(port)","authorization_servers":["http://localhost:\(port)/auth"],"credential_endpoint":"http://localhost:\(port)/credential","deferred_credential_endpoint":"http://localhost:\(port)/deferred_credential","notification_endpoint":"http://localhost:\(port)/notification","nonce_endpoint":"http://localhost:\(port)/nonce","batch_credential_issuance":{"batch_size":2},"credential_configurations_supported":{"\(CredDefId)":{"scope":"SD_JWT_cred","cryptographic_binding_methods_supported":["jwk"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"format":"dc+sd-jwt","credential_signing_alg_values_supported":["ES256"],"credential_metadata":{"claims":[{"path":["dob"],"mandatory":true,"display":[{"name":"Date of birth"}]},{"path":["given_name"],"mandatory":true,"display":[{"name":"Name"}]},{"path":["family_name"],"mandatory":true,"display":[{"name":"Surname"}]}]},"vct":"SD_JWT_cred"}}}
		"""
	}

	static func authServerMetadata(port: in_port_t) -> Data {
		"""
		{"issuer":"http://localhost:\(port)/auth","authorization_endpoint":"http://localhost:\(port)/auth","token_endpoint":"http://localhost:\(port)/auth/token","introspection_endpoint":"http://localhost:\(port)/auth/introspection","jwks_uri":"http://localhost:\(port)/auth/jwks","grant_types_supported":["authorization_code"],"response_types_supported":["code","token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"],"pushed_authorization_request_endpoint":"http://localhost:\(port)/auth/par/request"}
		""".data(using: .utf8)!
	}

	static let CodeResponse = """
		{"request_uri": "urn:ietf:params:oauth:request_uri:code","expires_in": 86400}
		""".data(using: .utf8)!

	static let AccessTokenResponse = """
		{"access_token": "\(AccessToken)","token_type": "bearer","expires_in": 86400}
		""".data(using: .utf8)!

	static let CredentialResponseImmediatePayload =
		"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~"

	static let BatchCredentialResponse = """
		{"credentials":[{"credential": "\(CredentialResponseImmediatePayload)"}, {"credential": "\(CredentialResponseImmediatePayload)"}], "notification_id":"1111"}
		""".data(using: .utf8)!

	static let DeferredCredentialResponse = """
	    {"transaction_id": "8xLOxBtZp8", "interval": 300}
	    """.data(using: .utf8)!

	static let NonceResponse = """
		{"c_nonce":"0GtZieAoAL_3Zafyn6TgCA"}
		""".data(using: .utf8)!

	static let SdJwtCredentialDidWebIss =
		"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6d2ViOmxvY2FsaG9zdCUzQTkwMDAiLCJpYXQiOjE3NTk3NTk4NDYsImV4cCI6MjA3NTI3ODIyNCwidmN0IjoiU0RfSldUX2NyZWQiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19LCJfc2QiOlsiWDJFRFRQekhDaFVZaVM4THBvb1g3VXltM0hlZm5hLVh5SlU5bDg3UFZZYyIsImh1RlhRSlNlMDl4bGIzNXZtSEJBa3BfQW9sUlZQLXB5ek9hdTFZQWlsRTgiLCJyVWlMbzZ6OXliZ05rTTRIRHlKX2Z6ajRaRnNsYWo2YXdUeUpkTWZTbURnIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.z_t8Xi_fyXgikwZPegwKkw6E7xVqSM7LwsjCGw2WoEnktmFsjwBUOHgx1PYwTue71Ryb0LJZtEjpSIqu79pjNw~WyJlYzM4MmY5MGY4ZDBmMjNjIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJkMzJhMDhhZTE5MjAwYjUyIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJjNWFmNjdiZGY4OWQxNGVhIiwiZG9iIiwiMDkvMDkvMTk4OSJd~"
}
