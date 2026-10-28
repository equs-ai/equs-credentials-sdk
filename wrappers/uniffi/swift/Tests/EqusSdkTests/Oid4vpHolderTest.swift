import CryptoKit
import Foundation
import Testing
@testable import EqusSdk

@Suite(.serialized) class Oid4vpHolderTests {
	let http: MockHttpRouter
	let holder: Oid4vpHolder

	init() async throws {
		self.http = MockHttpRouter()
		self.holder = try await Oid4vpHolderTests.setupHolder(http: http)
	}

	@Test func getAuthorizationRequest() async throws {
		self.http["/auth_request"] = { request in
			return MockHttpRouter.ok(Oid4vpHolderTestConstants.authRequestJwt, contentType: "application/oauth-authz-req+jwt")
		}

		let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
			requestUri: Oid4vpHolderTestConstants.requestUri)

		compareJsonValues(
			actual: actual.clientMetadata,
			expected: Oid4vpHolderTestConstants.authRequest.clientMetadata)
		compareJsonValues(
			actual: actual.presentationDefinition,
			expected: Oid4vpHolderTestConstants.authRequest.presentationDefinition)

		#expect(actual.clientId == Oid4vpHolderTestConstants.authRequest.clientId)
		#expect(actual.nonce == Oid4vpHolderTestConstants.authRequest.nonce)
		#expect(actual.responseType == Oid4vpHolderTestConstants.authRequest.responseType)
		#expect(actual.responseMode == Oid4vpHolderTestConstants.authRequest.responseMode)
		#expect(actual.responseUri == Oid4vpHolderTestConstants.authRequest.responseUri)
		#expect(actual.state == Oid4vpHolderTestConstants.authRequest.state)
	}

		@Test func getAuthorizationRequestWithTransactionData() async throws {
    		self.http["/auth_request"] = { request in
    			return MockHttpRouter.ok(Oid4vpHolderTestConstants.authRequestJwt, contentType: "application/oauth-authz-req+jwt")
    		}

    		let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
    			requestUri: Oid4vpHolderTestConstants.requestUriForTransactionData)

            #expect(
                actual.transactionData == [
                    TransactionDataItem(
                        credentialIds: ["Identity-1"], transactionDataHashesAlg: [.sha256],
                        content: .unknown(type: "type1", data: "{}"))
                ])
    	}

	@Test func delegateTransactionDataYieldsDelegationGrant() async throws {
		let (holder, credentials) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt])
		self.http["/auth_request_delegate"] = { _ in
			MockHttpRouter.ok(Oid4vpHolderTestConstants.delegationAuthRequestJwt, contentType: "application/oauth-authz-req+jwt")
		}

		var request = try await holder.getAuthorizationRequest(
			requestUri: Oid4vpHolderTestConstants.requestUriForDelegation)

		let items = try #require(request.transactionData)
		#expect(items.count == 2)
		#expect(items[0].credentialIds == ["Identity-1"])
		#expect(items[0].content == Oid4vpHolderTestConstants.delegateContent)
		guard case let .unknown(paymentType, paymentData) = items[1].content else {
			Issue.record("expected the payment item as an unknown type, got \(items[1].content)")
			return
		}
		#expect(paymentType == "payment")
		compareJsonValues(actual: paymentData, expected: #"{"payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}}"#)

		let origin = "https://agent.example.org"
		request.responseMode = "dc_api"
		request.responseUri = nil
		let result = try await holder.presentCredentialsAuto(
			authRequest: request,
			authResponseMetadata: AuthorizationResponseMetadata(
				claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: origin)
		)
		guard case let .authResponse(.plain(response)) = result else {
			Issue.record("expected a plain authorization response, got \(result)")
			return
		}

		try Oid4vpHolderTests.expectDelegationGrant(
			Oid4vpHolderTests.presentation(for: "Identity-1", in: response.vpToken),
			credential: try #require(credentials.first),
			typ: "kb+sd-jwt+kb",
			delegatePayload: #"{"purchase_id":"p-42","cnf":{"jwk":\#(Oid4vpHolderTestConstants.delegateJwk)},"aud":"origin:\#(origin)","nonce":"\#(request.nonce)"}"#)
		#expect(
			response.transactionDataHashes
				== [Oid4vpHolderTestConstants.delegateTransactionData, Oid4vpHolderTestConstants.paymentTransactionData]
				.map(Oid4vpHolderTestConstants.transactionDataHash))
	}

	@Test func delegateGrantIsPostedToTheVerifier() async throws {
		let (holder, credentials) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt])
		self.http["/auth_request_delegate"] = { _ in
			MockHttpRouter.ok(Oid4vpHolderTestConstants.delegationAuthRequestJwt, contentType: "application/oauth-authz-req+jwt")
		}
		self.http["/response"] = { _ in MockHttpRouter.ok("", contentType: "text/plain") }
		let request = try await holder.getAuthorizationRequest(
			requestUri: Oid4vpHolderTestConstants.requestUriForDelegation)

		let result = try await holder.presentCredentialsAuto(
			authRequest: request,
			authResponseMetadata: AuthorizationResponseMetadata(
				claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: nil))
		guard case .presented = result else {
			Issue.record("expected the response to be posted, got \(result)")
			return
		}

		let body = try #require(self.http.requests.last { MockHttpRouter.path(of: $0.url) == "/response" }?.body)
		let form = Oid4vpHolderTests.formFields(body)
		try Oid4vpHolderTests.expectDelegationGrant(
			Oid4vpHolderTests.presentation(for: "Identity-1", in: try #require(form["vp_token"])),
			credential: try #require(credentials.first),
			typ: "kb+sd-jwt+kb",
			delegatePayload: #"{"purchase_id":"p-42","cnf":{"jwk":\#(Oid4vpHolderTestConstants.delegateJwk)},"aud":"\#(Oid4vpHolderTestConstants.verifierClientId)","nonce":"\#(request.nonce)"}"#)
		let hashes = try #require(form["transaction_data_hashes"])
		#expect(
			try JSONSerialization.jsonObject(with: Data(hashes.utf8)) as? [String]
				== [Oid4vpHolderTestConstants.delegateTransactionData, Oid4vpHolderTestConstants.paymentTransactionData]
				.map(Oid4vpHolderTestConstants.transactionDataHash))
	}

	@Test func openDelegationYieldsAGrantWithoutCnf() async throws {
		let (holder, credentials) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt])
		let origin = "https://agent.example.org"
		let request = Oid4vpHolderTests.dcApiRequest([
			Oid4vpHolderTests.identityDelegateItem(
				.delegateSdJwt(
					DelegateSdJwtTransactionData(
						format: .open,
						delegatePayloadDisclosure: Fixtures.base64Url(#"["test-salt",{"purchase_id":"p-7"}]"#),
						delegateDisclosures: nil)))
		])

		let result = try await holder.presentCredentialsAuto(
			authRequest: request,
			authResponseMetadata: AuthorizationResponseMetadata(
				claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: origin))
		guard case let .authResponse(.plain(response)) = result else {
			Issue.record("expected a plain authorization response, got \(result)")
			return
		}

		try Oid4vpHolderTests.expectDelegationGrant(
			Oid4vpHolderTests.presentation(for: "Identity-1", in: response.vpToken),
			credential: try #require(credentials.first),
			typ: "kb+sd-jwt",
			delegatePayload: #"{"purchase_id":"p-7","aud":"origin:\#(origin)","nonce":"\#(request.nonce)"}"#)
	}

	@Test func presentCredentialsAnswersADelegateItem() async throws {
		let (holder, credentials) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt])
		let origin = "https://agent.example.org"
		let request = Oid4vpHolderTests.dcApiRequest([
			Oid4vpHolderTests.identityDelegateItem(Oid4vpHolderTestConstants.delegateContent)
		])

		let result = try await holder.presentCredentials(
			authRequest: request,
			credentialMapping: try await Oid4vpHolderTests.foundCredentials(holder, request),
			authResponseMetadata: AuthorizationResponseMetadata(
				claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: origin))
		guard case let .authResponse(.plain(response)) = result else {
			Issue.record("expected a plain authorization response, got \(result)")
			return
		}

		try Oid4vpHolderTests.expectDelegationGrant(
			Oid4vpHolderTests.presentation(for: "Identity-1", in: response.vpToken),
			credential: try #require(credentials.first),
			typ: "kb+sd-jwt+kb",
			delegatePayload: #"{"purchase_id":"p-42","cnf":{"jwk":\#(Oid4vpHolderTestConstants.delegateJwk)},"aud":"origin:\#(origin)","nonce":"\#(request.nonce)"}"#)
	}

	@Test func delegateItemOnlyTurnsItsOwnCredentialIntoAGrant() async throws {
		let (holder, credentials) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt, Oid4vpHolderTestConstants.membershipSdJwt])
		let origin = "https://agent.example.org"
		let request = Oid4vpHolderTests.dcApiRequest(
			[Oid4vpHolderTests.identityDelegateItem(Oid4vpHolderTestConstants.delegateContent)],
			dcqlQuery: Oid4vpHolderTestConstants.identityAndMembershipDcqlQuery)

		let result = try await holder.presentCredentialsAuto(
			authRequest: request,
			authResponseMetadata: AuthorizationResponseMetadata(
				claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: origin))
		guard case let .authResponse(.plain(response)) = result else {
			Issue.record("expected a plain authorization response, got \(result)")
			return
		}

		try Oid4vpHolderTests.expectDelegationGrant(
			Oid4vpHolderTests.presentation(for: "Identity-1", in: response.vpToken),
			credential: credentials[0],
			typ: "kb+sd-jwt+kb",
			delegatePayload: #"{"purchase_id":"p-42","cnf":{"jwk":\#(Oid4vpHolderTestConstants.delegateJwk)},"aud":"origin:\#(origin)","nonce":"\#(request.nonce)"}"#)
		// The credential the item does not target is presented as usual: its disclosure and a KB-JWT.
		let presentation = try Oid4vpHolderTests.presentation(for: "Membership-1", in: response.vpToken)
		let components = presentation.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
		let issuedComponents = credentials[1].split(separator: "~", omittingEmptySubsequences: false).map(String.init)
		let kbJwt = try #require(components.last)
		#expect(components == [issuedComponents[0], issuedComponents[1], kbJwt])
		let kbParts = Fixtures.jwtParts(kbJwt)
		#expect(kbParts.header["typ"] as? String == "kb+jwt")
		#expect(kbParts.payload["aud"] as? String == "origin:\(origin)")
		#expect(kbParts.payload["nonce"] as? String == request.nonce)
		#expect(kbParts.payload["sd_hash"] as? String == Fixtures.sha256(String(presentation.dropLast(kbJwt.count))))
		#expect(Fixtures.verifiesEs256(kbJwt, jwk: Fixtures.cnfJwk(issuedComponents[0])))
	}

	@Test func nestedDelegateDisclosuresAreRejected() async throws {
		let (holder, _) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt])
		let nested = TransactionDataItemTypeContent.delegateSdJwt(
			DelegateSdJwtTransactionData(
				format: .holderBinding,
				delegatePayloadDisclosure: Oid4vpHolderTestConstants.delegatePayloadDisclosure,
				delegateDisclosures: [Fixtures.base64Url(#"["test-salt","role","buyer"]"#)]))

		do {
			_ = try await holder.presentCredentialsAuto(
				authRequest: Oid4vpHolderTests.dcApiRequest([Oid4vpHolderTests.identityDelegateItem(nested)]),
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: "https://agent.example.org"))
			Issue.record("expected nested delegate disclosures to be rejected")
		} catch EqusSdk.Error.Oid4vpHolder(let message) {
			#expect(message.contains("delegate_disclosures"), "\(message)")
		}
	}

	/// The credentials `holder` finds for `request`; a query it finds none for fails the test.
	private static func foundCredentials(
		_ holder: Oid4vpHolder, _ request: AuthorizationRequest
	) async throws -> [String: [CredentialEntry]] {
		var mapping: [String: [CredentialEntry]] = [:]
		for (key, result) in try await holder.findVcsForPresentation(authRequest: request) {
			guard case let .credentials(credentials) = result.data else {
				throw NSError(
					domain: "Oid4vpHolderTests", code: 3,
					userInfo: [NSLocalizedDescriptionKey: "expected credentials for \(key), got \(result.data)"])
			}
			mapping[key] = credentials
		}
		return mapping
	}

	private static func dcApiRequest(
		_ transactionData: [TransactionDataItem], dcqlQuery: String = Oid4vpHolderTestConstants.identityDcqlQuery
	) -> AuthorizationRequest {
		var request = Oid4vpHolderTestConstants.authRequest
		request.presentationDefinition = #"{"dcql_query":\#(dcqlQuery)}"#
		request.responseMode = "dc_api"
		request.responseUri = nil
		request.transactionData = transactionData
		return request
	}

	private static func identityDelegateItem(_ content: TransactionDataItemTypeContent) -> TransactionDataItem {
		TransactionDataItem(credentialIds: ["Identity-1"], transactionDataHashesAlg: nil, content: content)
	}

	private static func presentation(for credentialId: String, in vpToken: String) throws -> String {
		try #require((Fixtures.jsonObject(vpToken)[credentialId] as? [String])?.first)
	}

	private static func formFields(_ body: String) -> [String: String] {
		var components = URLComponents()
		components.percentEncodedQuery = body.replacingOccurrences(of: "+", with: "%20")
		return Dictionary(
			(components.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { first, _ in first })
	}

	/// A one-hop grant over the identity `credential` whose single delegate payload is `delegatePayload`.
	private static func expectDelegationGrant(
		_ grant: String, credential: String, typ: String, delegatePayload: String
	) throws {
		let components = grant.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
		let issuedComponents = credential.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
		let link = components.count > 3 ? components[3] : ""
		// The issuer JWT, only the requested disclosure (`name`, not `surname`), the empty
		// component that precedes a chain link, the link and the trailing empty component.
		#expect(components == [issuedComponents[0], issuedComponents[1], "", link, ""])
		let linkParts = Fixtures.jwtParts(link)
		#expect(linkParts.header["typ"] as? String == typ)
		let actual = try #require(linkParts.payload["delegate_payload"] as? [Any])
		let expected = try #require(try JSONSerialization.jsonObject(with: Data("[\(delegatePayload)]".utf8)) as? [Any])
		#expect(NSArray(array: actual).isEqual(to: expected), "\(actual)")
		// What a verifier checks: the link binds to the issuer JWT and is signed by the key in its `cnf`.
		#expect(linkParts.payload["issuer_jwt_hash"] as? String == Fixtures.sha256(issuedComponents[0]))
		#expect(Fixtures.verifiesEs256(link, jwk: Fixtures.cnfJwk(issuedComponents[0])))
		#expect(!Fixtures.verifiesEs256(link, jwk: Fixtures.jsonObject(Oid4vpHolderTestConstants.delegateJwk)))
	}

	@Test func transactionDataHashCoversTheItemPayload() async throws {
		func hash(_ data: String) async throws -> String {
			var request = Oid4vpHolderTestConstants.authRequest
			request.responseMode = "dc_api"
			request.responseUri = nil
			request.transactionData = [Oid4vpHolderTestConstants.unknownItem("payment", data)]
			let result = try await self.holder.presentCredentialsAuto(
				authRequest: request,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: "https://example.verifier.org"))
			guard case let .authResponse(.plain(response)) = result else {
				throw NSError(
					domain: "Oid4vpHolderTests", code: 1,
					userInfo: [NSLocalizedDescriptionKey: "expected a plain authorization response"])
			}
			return try #require(response.transactionDataHashes?.first)
		}
		// The item as the SDK serializes it for hashing: its own fields first, then `type` and `data`.
		func expectedHash(_ payload: String) -> String {
			Oid4vpHolderTestConstants.transactionDataHash(Fixtures.base64Url(
				#"{"credential_ids":["Identity-1"],"transaction_data_hashes_alg":null,"type":"payment"\#(payload)}"#))
		}

		#expect(try await hash("{}") == expectedHash(""))
		#expect(
			try await hash(#"{"payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}}"#)
				== expectedHash(#","payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}"#))
		#expect(
			try await hash(#"{"amount":100000000000000000000}"#)
				== expectedHash(#","amount":100000000000000000000"#))
	}

	private func declineAndReadResponse(_ item: TransactionDataItem, holder: Oid4vpHolder? = nil) async throws -> String? {
		self.http["/response"] = { _ in MockHttpRouter.ok("", contentType: "text/plain") }
		var request = Oid4vpHolderTestConstants.authRequest
		request.transactionData = [item]
		_ = try await (holder ?? self.holder).declineAuthorizationRequest(authRequest: request)
		return self.http.requests.last { MockHttpRouter.path(of: $0.url) == "/response" }?.body
	}

	@Test func delegationIsOffByDefault() async throws {
		// A stored credential that matches the request, so each refusal below can only come from the gate.
		let (holder, _) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt], allowDelegation: nil)
		let item = Oid4vpHolderTests.identityDelegateItem(Oid4vpHolderTestConstants.delegateContent)
		let request = Oid4vpHolderTests.dcApiRequest([item])
		var plainRequest = request
		plainRequest.transactionData = nil
		let metadata = AuthorizationResponseMetadata(
			claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: "https://agent.example.org")

		// Without the delegate item the same request finds the credential.
		let credentialMapping = try await Oid4vpHolderTests.foundCredentials(holder, plainRequest)
		#expect(Array(credentialMapping.keys) == ["Identity-1"])

		await Self.expectDelegationRefused("presentCredentialsAuto") {
			_ = try await holder.presentCredentialsAuto(authRequest: request, authResponseMetadata: metadata)
		}
		await Self.expectDelegationRefused("findVcsForPresentation") {
			_ = try await holder.findVcsForPresentation(authRequest: request)
		}
		await Self.expectDelegationRefused("presentCredentials") {
			_ = try await holder.presentCredentials(
				authRequest: request, credentialMapping: credentialMapping, authResponseMetadata: metadata)
		}

		let body = try await declineAndReadResponse(item, holder: holder)
		#expect(body?.hasPrefix("error=access_denied") == true)
	}

	private static func expectDelegationRefused(_ name: String, _ call: () async throws -> Void) async {
		do {
			try await call()
			Issue.record("expected \(name) to refuse the delegation")
		} catch EqusSdk.Error.Oid4vpHolder(let message) {
			#expect(message.contains("delegation is not enabled"), "\(name): \(message)")
		} catch {
			Issue.record("expected \(name) to refuse the delegation, got \(error)")
		}
	}

	@Test func declineWorksWithUnrecognizedDelegateItem() async throws {
		let body = try await declineAndReadResponse(
			Oid4vpHolderTestConstants.unknownItem(
				"delegate", #"{"format":"dSD-JWT+XYZ","delegate_payload_disclosure":"x"}"#))
		#expect(body?.hasPrefix("error=access_denied") == true)
	}

	@Test func declineWorksWithLargeIntegerPayload() async throws {
		let body = try await declineAndReadResponse(
			Oid4vpHolderTestConstants.unknownItem("payment", #"{"amount":100000000000000000000}"#))
		#expect(body?.hasPrefix("error=access_denied") == true)
	}

	@Test func unrecognizedDelegateItemsAreRejected() async throws {
		// Upstream parses a `delegate` item without its fields, or with an unknown `format`, as `unknown`.
		let reasons = [
			(#"{"delegate_payload_disclosure":"x"}"#, "has no `format`"),
			(#"{"format":"dSD-JWT+XYZ","delegate_payload_disclosure":"x"}"#, "has an unsupported `format`"),
			(#"{"format":"dSD-JWT+KB"}"#, "has no `delegate_payload_disclosure`"),
		]
		let (holder, _) = try await Oid4vpHolderTests.delegatingWallet(
			http: http, issue: [Oid4vpHolderTestConstants.delegationSdJwt])
		for (data, reason) in reasons {
			var request = Oid4vpHolderTestConstants.authRequest
			request.transactionData = [Oid4vpHolderTestConstants.unknownItem("delegate", data)]
			do {
				_ = try await holder.findVcsForPresentation(authRequest: request)
				Issue.record("expected \(data) to be rejected")
			} catch EqusSdk.Error.Oid4vpHolder(let message) {
				#expect(message.contains(reason), "\(message)")
			}
		}
	}

	@Test func malformedJsonArgumentsRaiseParseErrors() async throws {
		var notAnObject = Oid4vpHolderTestConstants.authRequest
		notAnObject.transactionData = [Oid4vpHolderTestConstants.unknownItem("payment", #""secret-value""#)]
		do {
			_ = try await self.holder.findVcsForPresentation(authRequest: notAnObject)
			Issue.record("expected a non-object `data` to be rejected")
		} catch EqusSdk.Error.Parse(let message) {
			#expect(message.contains("must be a JSON object"), "\(message)")
			#expect(!message.contains("secret-value"))
		}
		var notJson = Oid4vpHolderTestConstants.authRequest
		notJson.clientMetadata = "{secret-value"
		do {
			_ = try await self.holder.findVcsForPresentation(authRequest: notJson)
			Issue.record("expected malformed client metadata to be rejected")
		} catch EqusSdk.Error.Parse(let message) {
			#expect(!message.contains("secret-value"))
		}
	}

	@Test func checkCustomNonceHandler() async throws {
		self.http["/request"] = { request in
			let body = request.body ?? "<invalid body>"
			#expect(body.contains("some_nonce"))
			return MockHttpRouter.ok(Oid4vpHolderTestConstants.authRequestJwt, contentType: "application/oauth-authz-req+jwt")
		}

		let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
			requestUri: Oid4vpHolderTestConstants.requestUriWithMethod)
	}

	@Test func presentCredentialsAuto() async throws {
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.http["/response"] = { request in
				let body = request.body!.removingPercentEncoding!

				#expect(body.contains(Oid4vpHolderTestConstants.sdJwtPayload))

				confirmResponse()
				return MockHttpRouter.ok("", contentType: "text/plain")
			}

			let holder = try await Oid4vpHolderTests.setupHolder(http: http)

			let _ = try await holder.presentCredentialsAuto(
				authRequest: Oid4vpHolderTestConstants.authRequest,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: nil)
			)
		}
	}

	@Test func presentCredentialsAutoWithDirectPostJwt() async throws {
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.http["/response"] = { request in
				let body = request.body!.removingPercentEncoding!

				#expect(body.contains(Oid4vpHolderTestConstants.responseString))

				confirmResponse()
				return MockHttpRouter.ok("", contentType: "text/plain")
			}

			let holder = try await Oid4vpHolderTests.setupHolder(http: http)

			let _ = try await holder.presentCredentialsAuto(
				authRequest: Oid4vpHolderTestConstants.authRequestWithDirectPostJwt,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: nil)
			)
		}
	}


	@Test func presentCredentials() async throws {
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.http["/response"] = { request in
				let body = request.body!.removingPercentEncoding!

				#expect(body.contains(Oid4vpHolderTestConstants.sdJwtPayload))

				confirmResponse()
				return MockHttpRouter.ok("", contentType: "text/plain")
			}

			let holder = try await Oid4vpHolderTests.setupHolder(http: http)

			let credentials = try await holder.findVcsForPresentation(
				authRequest: Oid4vpHolderTestConstants.authRequest)

			var credentialMapping: [String: Array<CredentialEntry>] = [:]

			for (key, result) in credentials {
				switch result.data {
				case .credentials(let credentials):
					credentialMapping[key] = credentials

				case .reason(let reason):
					throw NSError(
						domain: "ExtractError", code: 2,
						userInfo: [
							NSLocalizedDescriptionKey:
								"Failed to find credentials for key: \(key); reason: \(reason)"
						])
				}
			}

			let _ = try await holder.presentCredentials(
				authRequest: Oid4vpHolderTestConstants.authRequest,
				credentialMapping: credentialMapping,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: nil)
			)
		}
	}

	@Test
	func findVcsForPresentationReturnsCredentials() async throws {

		let credentialsMapping = try await self.holder.findVcsForPresentation(
			authRequest: Oid4vpHolderTestConstants.authRequest)

		for (key, result) in credentialsMapping {
			switch result.data {
			case .credentials(let creds):
				guard let credential = creds.first else {
					throw NSError(
						domain: "ExtractError", code: 2,
						userInfo: [
							NSLocalizedDescriptionKey:
								#"No credentials found for key: \#(key)"#
						])
				}
				#expect(credential.credential.format == VcFormat.sdJwtVc)

			case .reason(let reasons):
				throw NSError(
					domain: "ExtractError", code: 2,
					userInfo: [
						NSLocalizedDescriptionKey:
							#"Expected credentials, found reasons of failure \#(key): \#(reasons)"#
					])
			}
		}
	}

    @Test
    func findVcsForPresentationReturnsReasonWithPaths() async throws {

        let credentialsMapping = try await self.holder.findVcsForPresentation(
            authRequest: Oid4vpHolderTestConstants.authRequestWithFakeConstraints)

        for (key, result) in credentialsMapping {
            switch result.data {
            case .credentials(let creds):
                throw NSError(
                    domain: "ExtractError", code: 2,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            #"Expected reasons of failure, found credentials \#(key): \#(creds)"#
                    ])

            case .reason(let reason):
                switch reason {
                case .paths(let claimsPaths):
                    #expect(claimsPaths == [["$.first_name"],["$.last_name", "$.surname"]])
                default:
                    throw NSError(
                        domain: "ExtractError", code: 2,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                #"Expected typesNotMatched, found another reason: \#(reason)"#
                        ])
                }

            }
        }
    }

    @Test
    func findVcsForPresentationReturnsReasonTypesNotMatched() async throws {

        let credentialsMapping = try await self.holder.findVcsForPresentation(
            authRequest: Oid4vpHolderTestConstants.authRequestWithFakeVct)

        for (key, result) in credentialsMapping {
            switch result.data {
            case .credentials(let creds):
                throw NSError(
                    domain: "ExtractError", code: 2,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            #"Expected reasons of failure, found credentials \#(key): \#(creds)"#
                    ])

            case .reason(let reason):
                switch reason {
                case .typesNotMatched:
                    print("Reason typesNotMatched is expected")
                default:
                    throw NSError(
                        domain: "ExtractError", code: 2,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                #"Expected typesNotMatched, found another reason: \#(reason)"#
                        ])
                }

            }
        }
    }

	@Test
	func findVcsForPresentationReturnsReasonCredentialsNotFound() async throws {
        let holder = try await Oid4vpHolderTests.setupHolderWithEmptyVault(http: http)

		let credentialsMapping = try await holder.findVcsForPresentation(
			authRequest: Oid4vpHolderTestConstants.authRequestWithFakeVct)

		for (key, result) in credentialsMapping {
			switch result.data {
			case .credentials(let creds):
				throw NSError(
					domain: "ExtractError", code: 2,
					userInfo: [
						NSLocalizedDescriptionKey:
							#"Expected reasons of failure, found credentials \#(key): \#(creds)"#
					])

			case .reason(let reason):
                switch reason {
                case .credentialsNotFound:
                    print("Reason credentialsNotFound is expected")
                default:
                    throw NSError(
                        domain: "ExtractError", code: 2,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                #"Expected credentialsNotFound, found another reason: \#(reason)"#
                        ])
                }

			}
		}
	}

	@Test func declineAuthorizationRequest() async throws {
		let expectedResponse =
			"error=access_denied&error_description=consent+to+share+the+presentation+is+not+given&state=1d8b0d93-86e8-4135-87d4-524bb0500bf3"

		try await confirmation("Decline Response is not received") { confirmResponse in
			self.http["/response"] = { request in
				let body = request.body!

				#expect(body == expectedResponse)

				confirmResponse()

				return MockHttpRouter.ok("", contentType: "text/plain")
			}

			let holder = try await Oid4vpHolderTests.setupHolder(http: http)

			let _ = try await holder.declineAuthorizationRequest(
				authRequest: Oid4vpHolderTestConstants.authRequest)
		}
	}

	@Test func declineAuthorizationRequestWithReason() async throws {
		let expectedResponse =
			"error=invalid_transaction_data&error_description=unsupported+currency&state=1d8b0d93-86e8-4135-87d4-524bb0500bf3"

		try await confirmation("Decline Response is not received") { confirmResponse in
			self.http["/response"] = { request in
				#expect(request.body! == expectedResponse)

				confirmResponse()

				return MockHttpRouter.ok("", contentType: "text/plain")
			}

			let holder = try await Oid4vpHolderTests.setupHolder(http: http)

			let _ = try await holder.declineAuthorizationRequest(
				authRequest: Oid4vpHolderTestConstants.authRequest,
				reason: DeclineReason(error: .invalidTransactionData, description: "unsupported currency"))
		}
	}

	@Test func declineAuthorizationRequestRejectsNonAsciiDescription() async throws {
		do {
			let _ = try await self.holder.declineAuthorizationRequest(
				authRequest: Oid4vpHolderTestConstants.authRequest,
				reason: DeclineReason(error: .accessDenied, description: "отказано"))
			Issue.record("expected the non-ASCII description to be rejected")
		} catch EqusSdk.Error.Oid4vpHolder(let message) {
			#expect(message.contains("decline description must be non-empty"), "\(message)")
		} catch {
			Issue.record("expected the non-ASCII description to be rejected, got \(error)")
		}
	}

	@Test func getCredentialStatus() async throws {
        self.http["/status_list"] = { request in
            return MockHttpRouter.ok(Oid4vpHolderTestConstants.statusList, contentType: "application/statuslist+jwt")
        }

        let credential = Credential(format: VcFormat.sdJwtVc, payload: Oid4vpHolderTestConstants.sdJwtWithStatusPayload)
        let status = try await self.holder.getCredentialStatus(credential: credential)

        #expect(status == .statusListToken(TslVcStatus.valid))
	}

    private static func setupHolder(http: MockHttpRouter) async throws -> Oid4vpHolder {
        let inMemKms = InMemKms()
        let inMemVault = InMemVault()
        let nonceHandler = MockNonceHandler(nonce: "some_nonce")

        var didAndKeyMetadata = await createDidAndKeyMetadata(kms: inMemKms)
        didAndKeyMetadata.keyMetadata.didUrl = Fixtures.didKeyUrl(.holder)

        let credential = Credential(
            format: VcFormat.sdJwtVc, payload: Oid4vpHolderTestConstants.sdJwtPayload)
        let metadata = try await resolveMetadata(
            credential: credential, metadata: didAndKeyMetadata.keyMetadata)
        try await inMemVault.storeCredential(credential: credential, metadata: metadata)

        let holder = try await Oid4vpHolderBuilder(
            kms: inMemKms, vault: inMemVault, clientId: Oid4vpHolderTestConstants.clientId,
            httpClient: http,
            nonceHandler: nonceHandler
        ).build()

        return holder
    }

	/// A wallet, opted in unless `allowDelegation` says otherwise (`nil` leaves the builder's default), and
	/// the credentials it holds, each issued to the wallet's own key, so the links and KB-JWTs it signs
	/// verify against their `cnf`.
	private static func delegatingWallet(
		http: MockHttpRouter, issue: [(_ did: String, _ jwk: String) -> String], allowDelegation: Bool? = true
	) async throws -> (Oid4vpHolder, [String]) {
		let kms = InMemKms()
		let vault = InMemVault()
		let didAndKeyMetadata = await createDidAndKeyMetadata(kms: kms)
		let jwk = try #require(try await kms.get(kid: didAndKeyMetadata.keyMetadata.kid).inner.jwk())
		let credentials = issue.map { $0(didAndKeyMetadata.did, jwk) }
		for payload in credentials {
			let credential = Credential(format: .sdJwtVc, payload: payload)
			let metadata = try await resolveMetadata(credential: credential, metadata: didAndKeyMetadata.keyMetadata)
			try await vault.storeCredential(credential: credential, metadata: metadata)
		}
		let holder = try await Oid4vpHolderBuilder(
			kms: kms, vault: vault, clientId: Oid4vpHolderTestConstants.clientId,
			httpClient: http, nonceHandler: MockNonceHandler(nonce: "some_nonce"), allowDelegation: allowDelegation
		).build()
		return (holder, credentials)
	}

	private static func setupHolderWithEmptyVault(http: MockHttpRouter) async throws -> Oid4vpHolder {
		let inMemKms = InMemKms()
		let inMemVault = InMemVault()
		let nonceHandler = MockNonceHandler(nonce: "some_nonce")

		let holder = try await Oid4vpHolderBuilder(
			kms: inMemKms, vault: inMemVault, clientId: Oid4vpHolderTestConstants.clientId,
			httpClient: http,
			nonceHandler: nonceHandler
		).build()

		return holder
	}
}

enum Oid4vpHolderTestConstants {
	static let presentationDefinition = """
		{
		   "presentation_definition":
		    {
				   "id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
				   "input_descriptors":[
				      {
				         "id":"Identity-1",
				         "constraints":{
				            "fields":[
				               {
				                  "path":[
				                     "$.vct"
				                  ],
				                  "filter":{
				                     "type":"string",
				                     "const":"https://credentials.example.com/identity_credential"
				                  },
				                  "predicate":null,
				                  "intent_to_retain":false
				               },
				               {
				                  "path":[
				                     "$.name"
				                  ],
				                  "optional":true,
				                  "predicate":null,
				                  "intent_to_retain":false
				               }
				            ]
				         },
				         "name":"Identity VC",
				         "purpose":"We want an identity",
				         "format":{
				            "dc+sd-jwt":{
				               "sd-jwt_alg_values":[
				                  "ES256",
				                  "EdDSA"
				               ],
				               "kb-jwt_alg_values":[
				                  "ES256",
				                  "EdDSA"
				               ]
				            }
				         }
				      }
				   ]
		}
		}
		"""
	static let presentationDefinitionWithFakeVct = """
        {
           "presentation_definition":
            {
                   "id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
                   "input_descriptors":[
                      {
                         "id":"Identity-1",
                         "constraints":{
                            "fields":[
                               {
                                  "path":[
                                     "$.vct"
                                  ],
                                  "filter":{
                                     "type":"string",
                                     "const":"https://credentials.example.com/identity_credential_1"
                                  },
                                  "predicate":null,
                                  "intent_to_retain":false
                               },
                               {
                                  "path":[
                                     "$.name"
                                  ],
                                  "optional":true,
                                  "predicate":null,
                                  "intent_to_retain":false
                               }
                            ]
                         },
                         "name":"Identity VC",
                         "purpose":"We want an identity",
                         "format":{
                            "dc+sd-jwt":{
                               "sd-jwt_alg_values":[
                                  "ES256",
                                  "EdDSA"
                               ],
                               "kb-jwt_alg_values":[
                                  "ES256",
                                  "EdDSA"
                               ]
                            }
                         }
                      }
                   ]
        }
        }
        """

static let presentationDefinitionWithFakeConstraints = """
        {
          "presentation_definition": {
            "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
            "input_descriptors": [
              {
                "id": "Identity-1",
                "constraints": {
                  "fields": [
                    {
                      "path": [
                        "$.vct"
                      ],
                      "filter": {
                        "type": "string",
                        "const": "https://credentials.example.com/identity_credential"
                      },
                      "predicate": null,
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "$.first_name"
                      ],
                      "optional": false,
                      "predicate": null,
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "$.last_name",
                        "$.surname"
                      ],
                      "optional": false,
                      "predicate": null,
                      "intent_to_retain": false
                    }
                  ]
                },
                "name": "Identity VC",
                "purpose": "We want an identity",
                "format": {
                  "dc+sd-jwt": {
                    "sd-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                    ],
                    "kb-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                    ]
                  }
                }
              }
            ]
          }
        }
    """

	static let clientMetadataForDirectPostJwt = """
		{
		  "vp_formats_supported": {
		    "dc+sd-jwt": {
				"sd-jwt_alg_values": ["EdDSA", "ES256"],
				"kb-jwt_alg_values": ["EdDSA", "ES256"]
			}
		  },
		  "jwks": {
		    "keys": [
		      {
		        "kid": "ecdsa-kid",
		        "kty": "EC",
		        "crv": "P-256",
		        "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
		        "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
		        "alg": "ES256"
		      }
		    ]
		  }
		}
		"""
	static let clientMetadata = """
        {"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["EdDSA","ES256"],"kb-jwt_alg_values":["EdDSA","ES256"]}},"jwks":{"keys":[{"use":"enc","alg":"ES256","kid":"5QsdgXUGuH:P256:","kty":"EC","crv":"P-256","x":"Cb_uJhiPN7H9KXdQN4PQN0uWC6LmEwIz4j03wX1rBAw","y":"yEZ8-uX5hGhCuN9NrIz4ShNH0T1y4fQts5siiCH0Q7w"}]},"encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"],"subject_syntax_types_supported":["did:key"]}
        """

	static let clientId = Fixtures.didKey(.verifier)
	static let verifierClientId = "decentralized_identifier:\(clientId)"
	static let encodedVerifierClientId = verifierClientId.replacingOccurrences(of: ":", with: "%3A")
	static let requestUri =
		"openid4vp://?client_id=\(encodedVerifierClientId)&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
	static let requestUriForTransactionData =
	    "openid4vp://?client_id=\(encodedVerifierClientId)&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
	static let requestUriWithMethod =
		"openid4vp://?client_id=\(verifierClientId)&request_uri_method=post&request_uri=http://localhost:9001/request"
	static let authRequest = AuthorizationRequest(
		clientId: verifierClientId,
		clientMetadata: clientMetadata,
		presentationDefinition: presentationDefinition,
		nonce: "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M",
		responseType: "vp_token",
		responseMode: "direct_post",
		responseUri: "http://localhost:9001/response",
		state: "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
		transactionData: nil,
		expectedOrigins: nil
	)
	static let authRequestWithDirectPostJwt = AuthorizationRequest(
		clientId: verifierClientId,
		clientMetadata: clientMetadataForDirectPostJwt,
		presentationDefinition: presentationDefinition,
		nonce: "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M",
		responseType: "vp_token",
		responseMode: "direct_post.jwt",
		responseUri: "http://localhost:9001/response",
		state: "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
		transactionData: nil,
		expectedOrigins: nil
	)

    static let authRequestWithFakeVct = AuthorizationRequest(
        clientId: verifierClientId,
        clientMetadata: clientMetadata,
        presentationDefinition: presentationDefinitionWithFakeVct,
        nonce: "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M",
        responseType: "vp_token",
        responseMode: "direct_post",
        responseUri: "http://localhost:9001/response",
        state: "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
        transactionData: nil,
        expectedOrigins: nil
    )

	static let authRequestWithFakeConstraints = AuthorizationRequest(
		clientId: verifierClientId,
		clientMetadata: clientMetadata,
		presentationDefinition: presentationDefinitionWithFakeConstraints,
		nonce: "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M",
		responseType: "vp_token",
		responseMode: "direct_post",
		responseUri: "http://localhost:9001/response",
		state: "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
		transactionData: nil,
		expectedOrigins: nil
	)

	static let transactionData = Fixtures.base64Url(
		#"{"type":"type1","credential_ids":["Identity-1"],"transaction_data_hashes_alg":["sha-256"]}"#)
	static let delegateJwk = Fixtures.publicJwk(.verifier)
	static func unknownItem(_ type: String, _ data: String) -> TransactionDataItem {
		TransactionDataItem(
			credentialIds: ["Identity-1"], transactionDataHashesAlg: nil, content: .unknown(type: type, data: data))
	}
	/// An identity credential (`name`, `surname`) issued to the holder `did` and bound to its key `jwk`.
	static func delegationSdJwt(did: String, jwk: String) -> String {
		issuedSdJwt(
			did: did, jwk: jwk, vct: "https://credentials.example.com/identity_credential",
			disclosures: [
				#"["SknIWuK1_VVXSB2EoYuRRw", "name", "John"]"#,
				#"["2CBudCWI5EImahgzdcU1Vw", "surname", "Doe"]"#,
			])
	}
	/// A membership card (`member_id`) issued to the holder `did` and bound to its key `jwk`.
	static func membershipSdJwt(did: String, jwk: String) -> String {
		issuedSdJwt(
			did: did, jwk: jwk, vct: "https://credentials.example.com/membership_card",
			disclosures: [#"["Tq0b3hBr8Ue5eYyM2xkZ1w", "member_id", "M-1"]"#])
	}
	private static func issuedSdJwt(did: String, jwk: String, vct: String, disclosures: [String]) -> String {
		try! fixtureSdJwt(
			headerJson: #"{"typ":"dc+sd-jwt","alg":"ES256","kid":"\#(Fixtures.didKeyUrl(.issuer))"}"#,
			claimsJson: #"{"sub":"\#(did)","vct":"\#(vct)","iat":1760606075,"_sd_alg":"sha-256","iss":"\#(Fixtures.didKey(.issuer))","exp":2075966075,"nbf":1760606075,"cnf":{"jwk":\#(jwk)}}"#,
			disclosures: disclosures,
			role: .issuer
		)
	}
	static let delegatePayloadDisclosure = Fixtures.base64Url(
		#"["test-salt-for-delegation",{"purchase_id":"p-42","cnf":{"jwk":\#(delegateJwk)}}]"#)
	static let delegateContent = TransactionDataItemTypeContent.delegateSdJwt(
		DelegateSdJwtTransactionData(
			format: .holderBinding, delegatePayloadDisclosure: delegatePayloadDisclosure, delegateDisclosures: nil))
	static let identityDcqlQuery =
		#"{"credentials":[{"id":"Identity-1","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]},"claims":[{"path":["name"]}]}]}"#
	static let identityAndMembershipDcqlQuery =
		#"{"credentials":[{"id":"Identity-1","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]},"claims":[{"path":["name"]}]},{"id":"Membership-1","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/membership_card"]},"claims":[{"path":["member_id"]}]}]}"#
	// Both items are written in the SDK's serialization order, so the hash of the received string
	// is also the hash an SDK verifier computes for them.
	static let delegateTransactionData = Fixtures.base64Url(
		#"{"credential_ids":["Identity-1"],"transaction_data_hashes_alg":null,"type":"delegate","format":"dSD-JWT+KB","delegate_payload_disclosure":"\#(delegatePayloadDisclosure)"}"#)
	static let paymentTransactionData = Fixtures.base64Url(
		#"{"credential_ids":["Identity-1"],"transaction_data_hashes_alg":null,"type":"payment","payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}}"#)

	static func transactionDataHash(_ encodedItem: String) -> String {
		Data(SHA256.hash(data: Data(encodedItem.utf8))).base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}
	static let requestUriForDelegation =
		"openid4vp://?client_id=\(encodedVerifierClientId)&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request_delegate"
	static let delegationAuthRequestJwt: String = try! fixtureJws(
		headerJson: #"{"alg":"ES256","kid":"\#(Fixtures.didKeyUrl(.verifier))","typ":"application/oauth-authz-req+jwt"}"#,
		payloadJson: #"{"response_type":"vp_token","state":"1d8b0d93-86e8-4135-87d4-524bb0500bf3","transaction_data":["\#(delegateTransactionData)","\#(paymentTransactionData)"],"response_mode":"direct_post","nonce":"F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M","client_metadata":\#(clientMetadata),"client_id":"\#(verifierClientId)","dcql_query":\#(identityDcqlQuery),"response_uri":"http://localhost:9001/response"}"#,
		role: .verifier
	)
	static let authRequestJwt: String = try! fixtureJws(
		headerJson: #"{"alg":"ES256","kid":"\#(Fixtures.didKeyUrl(.verifier))","typ":"application/oauth-authz-req+jwt"}"#,
		payloadJson: #"{"response_type":"vp_token","state":"1d8b0d93-86e8-4135-87d4-524bb0500bf3","transaction_data":["\#(transactionData)"],"response_mode":"direct_post","nonce":"F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M","client_metadata":{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["EdDSA","ES256"],"kb-jwt_alg_values":["EdDSA","ES256"]}},"jwks":{"keys":[{"use":"enc","alg":"ES256","kid":"5QsdgXUGuH:P256:","kty":"EC","crv":"P-256","x":"Cb_uJhiPN7H9KXdQN4PQN0uWC6LmEwIz4j03wX1rBAw","y":"yEZ8-uX5hGhCuN9NrIz4ShNH0T1y4fQts5siiCH0Q7w"}]},"encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"],"subject_syntax_types_supported":["did:key"]},"client_id":"\#(verifierClientId)","presentation_definition":{"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]},"response_uri":"http://localhost:9001/response"}"#,
		role: .verifier
	)
	static let sdJwtPayload: String = try! fixtureSdJwt(
		headerJson: #"{"typ":"dc+sd-jwt","alg":"ES256","kid":"\#(Fixtures.didKeyUrl(.issuer))"}"#,
		claimsJson: #"{"sub":"\#(Fixtures.didKey(.holder))","vct":"https://credentials.example.com/identity_credential","iat":1760606075,"_sd_alg":"sha-256","iss":"\#(Fixtures.didKey(.issuer))","exp":2075966075,"nbf":1760606075,"cnf":{"jwk":\#(Fixtures.publicJwk(.holder))}}"#,
		disclosures: [#"["SknIWuK1_VVXSB2EoYuRRw", "name", "John"]"#],
		role: .issuer
	)

    static let statusList: String = try! fixtureJws(
		headerJson: #"{"typ":"statuslist+jwt","alg":"ES256","kid":"\#(Fixtures.didKeyUrl(.issuer))"}"#,
		payloadJson: #"{"status_list":{"lst":"eNqbwMwABgAEnQCU","bits":2},"sub":"http://localhost:9001/status_list","iat":1763025623,"_sd_alg":"sha-256"}"#,
		role: .issuer
	) + "~"
    static let sdJwtWithStatusPayload: String = try! fixtureSdJwt(
		headerJson: #"{"typ":"dc+sd-jwt","alg":"ES256","kid":"\#(Fixtures.didKeyUrl(.issuer))"}"#,
		claimsJson: #"{"address":"221B Baker Street","iat":1753054448,"date":"09/09/1989","sub":"\#(Fixtures.didKey(.holder))","vct":"https://credentials.example.com/identity_credential","status":{"status_list":{"uri":"http://localhost:9001/status_list","idx":1}},"_sd_alg":"sha-256","iss":"\#(Fixtures.didKey(.issuer))","exp":1753055048,"nbf":1753054448,"cnf":{"jwk":\#(Fixtures.publicJwk(.holder))}}"#,
		disclosures: [
			#"["uxLNTemWQkc1VO6LgsArlQ", "name", "John"]"#,
			#"["2CBudCWI5EImahgzdcU1Vw", "surname", "Doe"]"#,
		],
		role: .issuer
	)

	static let responseString = "response=ey"
}
