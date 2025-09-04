import Foundation
import Swifter
import Testing
@testable import Asdk

@Suite(.serialized) class Oid4vpHolderTests {
	let server: HttpServer
	let holder: Oid4vpHolder

	init() async throws {
		self.server = HttpServer()
		try server.start(9001)

		self.holder = try await Oid4vpHolderTests.setupHolder()
	}

	deinit {
		server.stop()
	}

	@Test func getAuthorizationRequest() async throws {
		self.server["/auth_request"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
			return .ok(
				.data(
					Oid4vpHolderTestConstants.authRequestJwt.data(using: .utf8)!,
					contentType: "application/oauth-authz-req+jwt"))
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
    		self.server["/auth_request"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
    			return .ok(
    				.data(
    					Oid4vpHolderTestConstants.authRequestJwtWithTransactionData.data(using: .utf8)!,
    					contentType: "application/oauth-authz-req+jwt"))
    		}

    		let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
    			requestUri: Oid4vpHolderTestConstants.requestUriForTransactionData)

            let transactionData = TransactionDataItem(type: "type1", credentialIds: ["Identity-1"], transactionDataHashesAlg: ["sha-256"])

            #expect(actual.transactionData?.first?.type == transactionData.type)
            #expect(actual.transactionData?.first?.credentialIds.first == transactionData.credentialIds.first)
            #expect(actual.transactionData?.first?.transactionDataHashesAlg?.first == transactionData.transactionDataHashesAlg?.first)
    	}

	@Test func checkCustomNonceHandler() async throws {
		self.server["/request"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
			let body = String(data: Data(request.body), encoding: .utf8) ?? "<invalid body>"
			#expect(body.contains("some_nonce"))
			return .ok(
				.data(
					Oid4vpHolderTestConstants.authRequestJwt.data(using: .utf8)!,
					contentType: "application/oauth-authz-req+jwt"))
		}

		let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
			requestUri: Oid4vpHolderTestConstants.requestUriWithMethod)
	}

	@Test func presentCredentialsAuto() async throws {
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.server["/response"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
				let body = String(bytes: request.body, encoding: String.Encoding.utf8)!
					.removingPercentEncoding!

				#expect(body.contains(Oid4vpHolderTestConstants.sdJwtPayload))

				confirmResponse()
				return .ok(.text(""))
			}

			let holder = try await Oid4vpHolderTests.setupHolder()

			let _ = try await holder.presentCredentialsAuto(
				authRequest: Oid4vpHolderTestConstants.authRequest,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil)
			)
		}
	}

	@Test func presentCredentialsAutoWithDirectPostJwt() async throws {
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.server["/response"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
				let body = String(bytes: request.body, encoding: String.Encoding.utf8)!
					.removingPercentEncoding!

				#expect(body.contains(Oid4vpHolderTestConstants.responseString))

				confirmResponse()
				return .ok(.text(""))
			}

			let holder = try await Oid4vpHolderTests.setupHolder()

			let _ = try await holder.presentCredentialsAuto(
				authRequest: Oid4vpHolderTestConstants.authRequestWithDirectPostJwt,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil)
			)
		}
	}


	@Test func presentCredentials() async throws {
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.server["/response"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
				let body = String(bytes: request.body, encoding: String.Encoding.utf8)!
					.removingPercentEncoding!

				#expect(body.contains(Oid4vpHolderTestConstants.sdJwtPayload))

				confirmResponse()
				return .ok(.text(""))
			}

			let holder = try await Oid4vpHolderTests.setupHolder()

			let credentials = try await holder.findVcsForPresentation(
				authRequest: Oid4vpHolderTestConstants.authRequest)

			var credentialMapping: [String: CredentialEntry] = [:]

			for (key, result) in credentials {
				switch result.data {
				case .credentials(let credentials):
					guard let first = credentials.first else {
						throw NSError(
							domain: "ExtractError", code: 1,
							userInfo: [
								NSLocalizedDescriptionKey: "No credentials found for key: \(key)"
							])
					}
					credentialMapping[key] = first

				case .reasons(let reasons):
					let reasonDescriptions = reasons.map { "\($0)" }.joined(separator: "; ")
					throw NSError(
						domain: "ExtractError", code: 2,
						userInfo: [
							NSLocalizedDescriptionKey:
								"Failed to find credentials for key: \(key); reasons: \(reasonDescriptions)"
						])
				}
			}

			let _ = try await holder.presentCredentials(
				authRequest: Oid4vpHolderTestConstants.authRequest,
				credentialMapping: credentialMapping,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil)
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

			case .reasons(let reasons):
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
	func findVcsForPresentationReturnsReasonsOfFailure() async throws {

		let credentialsMapping = try await self.holder.findVcsForPresentation(
			authRequest: Oid4vpHolderTestConstants.authRequestFake)

		for (key, result) in credentialsMapping {
			switch result.data {
			case .credentials(let creds):
				throw NSError(
					domain: "ExtractError", code: 2,
					userInfo: [
						NSLocalizedDescriptionKey:
							#"Expected reasons of failure, found credentials \#(key): \#(creds)"#
					])

			case .reasons(let groupedReasons):
				#expect(groupedReasons.count == 1, "Expected exactly one group of reasons")
				let reasons = groupedReasons[0]

				#expect(reasons.count == 1, "Expected exactly one reason in the group")
				let reason = reasons[0]

				#expect(reason.paths == ["$.vct"], "Expected paths to be [\"$.vct\"]")
				#expect(reason.type == "const", "Expected type to be \"const\"")
				#expect(
					reason.value == "https://credentials.example.com/identity_credential_1",
					"Unexpected value")

			}
		}
	}

	@Test func declineAuthorizationRequest() async throws {
		let expectedResponse =
			"error=access_denied&error_description=consent+to+share+the+presentation+is+not+given&state=eea7b48e-1866-41b4-beae-03b95d41670c"

		try await confirmation("Decline Response is not received") { confirmResponse in
			self.server["/response"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
				let body = String(bytes: request.body, encoding: String.Encoding.utf8)!

				#expect(body == expectedResponse)

				confirmResponse()

				return .ok(.text(""))
			}

			let holder = try await Oid4vpHolderTests.setupHolder()

			let _ = try await holder.declineAuthorizationRequest(
				authRequest: Oid4vpHolderTestConstants.authRequest)
		}
	}

	private static func setupHolder() async throws -> Oid4vpHolder {
		let inMemKms = InMemKms()
		let inMemVault = InMemVault()
		let nonceHandler = MockNonceHandler(nonce: "some_nonce")

		var didAndKeyMetadata = await createDidAndKeyMetadata(kms: inMemKms)
		didAndKeyMetadata.keyMetadata.didUrl =
			"did:key:zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM#zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM"

		let credential = Credential(
			format: VcFormat.sdJwtVc, payload: Oid4vpHolderTestConstants.sdJwtPayload)
		let metadata = try await resolveMetadata(
			credential: credential, metadata: didAndKeyMetadata.keyMetadata)
		try await inMemVault.storeCredential(credential: credential, metadata: metadata)

		let holder = try await Oid4vpHolderBuilder(
			kms: inMemKms, vault: inMemVault, clientId: Oid4vpHolderTestConstants.clientId,
			httpClient: ReqwestHttpClient.insecure(),
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
	static let presentationDefinitionFake = """
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

	static let clientMetadataForDirectPostJwt = """
		{
		  "vp_formats": {
		    "dc+sd-jwt": {
		      "alg": [
		        "EdDSA",
		        "ES256"
		      ]
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
        {"vp_formats":{"dc+sd-jwt":{"alg":["EdDSA","ES256"]}}}
        """

	static let clientId = "wallet-dev"
	static let requestUri =
		"openid4vp://?client_id=did%3Akey%3AzDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
	static let requestUriForTransactionData =
	    "openid4vp://?client_id=did%3Akey%3AzDnaeXHgwoWiRJM6LVVSgu7kNJKsS3L4rsVhTBPRSSj9eg5VZ&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
	static let requestUriWithMethod =
		"openid4vp://?client_id=did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri_method=post&request_uri=http://localhost:9001/request"
	static let authRequest = AuthorizationRequest(
		clientId: "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
		clientMetadata: clientMetadata,
		presentationDefinition: presentationDefinition,
		nonce: "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
		responseType: "vp_token",
		responseMode: "direct_post",
		responseUri: "http://localhost:9001/response",
		state: "eea7b48e-1866-41b4-beae-03b95d41670c",
		transactionData: nil
	)
	static let authRequestWithDirectPostJwt = AuthorizationRequest(
		clientId: "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
		clientMetadata: clientMetadataForDirectPostJwt,
		presentationDefinition: presentationDefinition,
		nonce: "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
		responseType: "vp_token",
		responseMode: "direct_post.jwt",
		responseUri: "http://localhost:9001/response",
		state: "eea7b48e-1866-41b4-beae-03b95d41670c",
		transactionData: nil
	)

	static let authRequestFake = AuthorizationRequest(
		clientId: "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
		clientMetadata: clientMetadata,
		presentationDefinition: presentationDefinitionFake,
		nonce: "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
		responseType: "vp_token",
		responseMode: "direct_post",
		responseUri: "http://localhost:9001/response",
		state: "eea7b48e-1866-41b4-beae-03b95d41670c",
		transactionData: nil
	)

	static let authRequestJwt =
		"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVlVEc4OHdwUGhNenVEUnZMUlRUeU5NeUppcDVlNlRMbXNqeXZQaVNZVUZrNyN6RG5hZWVURzg4d3BQaE16dURSdkxSVFR5Tk15SmlwNWU2VExtc2p5dlBpU1lVRms3IiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6ImVlYTdiNDhlLTE4NjYtNDFiNC1iZWFlLTAzYjk1ZDQxNjcwYyIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiWXp0QU5nbFJkbVA0Q2h4c3JjUzhVY0dZb1BXd2tnaVVJbWtCclFtZ1drVSIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzIjp7ImRjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiJdfX19LCJjbGllbnRfaWQiOiJkaWQ6a2V5OnpEbmFlZVRHODh3cFBoTXp1RFJ2TFJUVHlOTXlKaXA1ZTZUTG1zanl2UGlTWVVGazciLCJjbGllbnRfaWRfc2NoZW1lIjoiZGlkIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIxYjlkNmJjZC1iYmZkLTRiMmQtOWI1ZC1hYjhkZmJiZDRiZWQiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJJZGVudGl0eS0xIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmN0Il0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYW4gaWRlbnRpdHkiLCJmb3JtYXQiOnsiZGMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdfX19XX0sInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9yZXNwb25zZSJ9.dV0RXxaAJTjnAqGNuPUzMor93gsEkXpoqVRj9-J638lV7mkka4ixXZJ3VIQ0Iqhb7GvCIr0D-7_bWp_xnIYAVA"
    static let authRequestJwtWithTransactionData =
        "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVYSGd3b1dpUkpNNkxWVlNndTdrTkpLc1MzTDRyc1ZoVEJQUlNTajllZzVWWiN6RG5hZVhIZ3dvV2lSSk02TFZWU2d1N2tOSktzUzNMNHJzVmhUQlBSU1NqOWVnNVZaIiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4gaWRfdG9rZW4iLCJzY29wZSI6Im9wZW5pZCIsImlkX3Rva2VuX3R5cGUiOiJzdWJqZWN0X3NpZ25lZF9pZF90b2tlbiIsInRyYW5zYWN0aW9uX2RhdGEiOlsiZXlKMGVYQmxJam9pZEhsd1pURWlMQ0pqY21Wa1pXNTBhV0ZzWDJsa2N5STZXeUpKWkdWdWRHbDBlUzB4SWwwc0luUnlZVzV6WVdOMGFXOXVYMlJoZEdGZmFHRnphR1Z6WDJGc1p5STZXeUp6YUdFdE1qVTJJbDE5Il0sInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6IkNOZXhCWnFQcGxmRF9QV2pnWTZFT2ZpWGpJLWF1TWNCODA5SVZBUVpSUjQiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJkYytzZC1qd3QiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiXX0sImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5Il19fSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDprZXkiXSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJlbmMiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtEQlhjOU5Ubnk6UDI1NjoiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImVvWDdheXliZkZtSldpcjNoNzJYVi1LVy1BRk9oY3gyUjlfUVA2UjBCZEkiLCJ5IjoiSUtDSUo3MGoyQjEzNGU4aEZYM0ZhMGQxeWllQTNXMmZHck9JNmlpbHpFbyJ9XX0sImVuY3J5cHRlZF9yZXNwb25zZV9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMjU2R0NNIl0sImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIn0sImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVYSGd3b1dpUkpNNkxWVlNndTdrTkpLc1MzTDRyc1ZoVEJQUlNTajllZzVWWiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiZjY0ZWRjOTktMmI3OS00NWNlLWFkMzYtNWUzNDZlYmZjNmVjIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsXzEifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuZW1haWwud29yayJdLCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC51c2VybmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuY291bnRyeSJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiVVMifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuYWdlX292ZXJfMTgiXSwiZmlsdGVyIjp7InR5cGUiOiJib29sZWFuIiwiY29uc3QiOnRydWV9LCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfV19LCJuYW1lIjoiSWRlbnRpdHkgVkMiLCJwdXJwb3NlIjoiV2Ugd2FudCBhbiBpZGVudGl0eSIsImZvcm1hdCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl19fX0seyJpZCI6InJlc2lkZW50LWNhcmQiLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC50eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoiYXJyYXkiLCJjb250YWlucyI6eyJjb25zdCI6IlBlcm1hbmVudFJlc2lkZW50Q2FyZCJ9fSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYSByZXNpZGVudCBjYXJkIiwiZm9ybWF0Ijp7ImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5Il19fX0seyJpZCI6ImFsdW1uaS1jYXJkIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJBbHVtbmlDcmVkZW50aWFsIn19LCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfV19LCJuYW1lIjoiVW5pdmVyc2l0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGEgZGlwbG9tYSIsImZvcm1hdCI6eyJsZHBfdmMiOnsicHJvb2ZfdHlwZSI6WyJFY2RzYVJkZmMyMDE5IiwiRWREc2FSZGZjMjAyMiJdfX19XSwibmFtZSI6IkV4YW1wbGUgd2l0aCBzZWxlY3RpdmUgZGlzY2xvc3VyZSJ9LCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwOTgvcHJlc2VudCJ9.Zce8XVbP9Zf1tYIXupYDHiL50a7udE0U734Nwu4iTCjZL-Wz5ZMWIj6jIJS4plfDC2VlsoiIpa1hMHzWWKNU9A"
	static let sdJwtPayload =
		"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~"

	static let responseString = "response=ey"
}
