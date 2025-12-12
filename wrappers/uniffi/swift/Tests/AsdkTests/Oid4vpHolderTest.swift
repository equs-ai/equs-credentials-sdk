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
    					Oid4vpHolderTestConstants.authRequestJwt.data(using: .utf8)!,
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
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: nil)
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
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: nil)
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
        let holder = try await Oid4vpHolderTests.setupHolderWithEmptyVault()

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
            "did:key:zDnaeZ1MuKdxYsz4UM69cJz6cEJJVo9aS4GKTkGvz1a4f9Fiu#zDnaeZ1MuKdxYsz4UM69cJz6cEJJVo9aS4GKTkGvz1a4f9Fiu"

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

	private static func setupHolderWithEmptyVault() async throws -> Oid4vpHolder {
		let inMemKms = InMemKms()
		let inMemVault = InMemVault()
		let nonceHandler = MockNonceHandler(nonce: "some_nonce")

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

	static let clientId = "did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN"
	static let requestUri =
		"openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
	static let requestUriForTransactionData =
	    "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
	static let requestUriWithMethod =
		"openid4vp://?client_id=decentralized_identifier:did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN&request_uri_method=post&request_uri=http://localhost:9001/request"
	static let authRequest = AuthorizationRequest(
		clientId: "decentralized_identifier:did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN",
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
		clientId: "decentralized_identifier:did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN",
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
        clientId: "decentralized_identifier:did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN",
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
		clientId: "decentralized_identifier:did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN",
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

	static let authRequestJwt =
		"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVRcE5ZUUQ2aDE4Vm5hZ3lBMVhiZXk5aEZLQTFqNWN5aHFQSEdmYXE5dHhtTiN6RG5hZVFwTllRRDZoMThWbmFneUExWGJleTloRktBMWo1Y3locVBIR2ZhcTl0eG1OIiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6IjFkOGIwZDkzLTg2ZTgtNDEzNS04N2Q0LTUyNGJiMDUwMGJmMyIsInRyYW5zYWN0aW9uX2RhdGEiOlsiZXlKMGVYQmxJam9pZEhsd1pURWlMQ0pqY21Wa1pXNTBhV0ZzWDJsa2N5STZXeUpKWkdWdWRHbDBlUzB4SWwwc0luUnlZVzV6WVdOMGFXOXVYMlJoZEdGZmFHRnphR1Z6WDJGc1p5STZXeUp6YUdFdE1qVTJJbDE5Il0sInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiRjN2YkN5WFY0QmtqLVJDb25laUcxaUtkQTVYdWFFSEhheWNPSUNJTnUyTSIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2Il19fSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJlbmMiLCJhbGciOiJFUzI1NiIsImtpZCI6IjVRc2RnWFVHdUg6UDI1NjoiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkNiX3VKaGlQTjdIOUtYZFFONFBRTjB1V0M2TG1Fd0l6NGowM3dYMXJCQXciLCJ5IjoieUVaOC11WDVoR2hDdU45TnJJejRTaE5IMFQxeTRmUXRzNXNpaUNIMFE3dyJ9XX0sImVuY3J5cHRlZF9yZXNwb25zZV9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4R0NNIiwiQTEyOENCQy1IUzI1NiJdLCJzdWJqZWN0X3N5bnRheF90eXBlc19zdXBwb3J0ZWQiOlsiZGlkOmtleSJdfSwiY2xpZW50X2lkIjoiZGVjZW50cmFsaXplZF9pZGVudGlmaWVyOmRpZDprZXk6ekRuYWVRcE5ZUUQ2aDE4Vm5hZ3lBMVhiZXk5aEZLQTFqNWN5aHFQSEdmYXE5dHhtTiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMWI5ZDZiY2QtYmJmZC00YjJkLTliNWQtYWI4ZGZiYmQ0YmVkIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn0sInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm5hbWUiXSwib3B0aW9uYWwiOnRydWUsInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX0sIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7ImRjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl0sImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXX19fV19LCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvcmVzcG9uc2UifQ.27WD-THq-vBdZZNb20WY3VYDRbbws0PTcp6LZM_GFh8Bhpp7tVPZnhu2m362D9E_fWtIwbLQiHzdigP27D9VyA"
	static let sdJwtPayload =
		"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVkNnN6c044VDhBWEhxQ044ZXFVOW9mWFpLQ1FDZUhzN2hqdmhVOHdiTmd4OSN6RG5hZWQ2c3pzTjhUOEFYSHFDTjhlcVU5b2ZYWktDUUNlSHM3aGp2aFU4d2JOZ3g5In0.eyJfc2QiOlsiZkZnbndmQ2k4TjZ0dUlYZWtCUU5BWC05eFA0RURkcVhTaXlpMV9NSWdJayJdLCJzdWIiOiJkaWQ6a2V5OnpEbmFlWjFNdUtkeFlzejRVTTY5Y0p6NmNFSkpWbzlhUzRHS1RrR3Z6MWE0ZjlGaXUiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJpYXQiOjE3NjA2MDYwNzUsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZWQ2c3pzTjhUOEFYSHFDTjhlcVU5b2ZYWktDUUNlSHM3aGp2aFU4d2JOZ3g5IiwiZXhwIjoyMDc1OTY2MDc1LCJuYmYiOjE3NjA2MDYwNzUsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJmMnVCbkhIZ1BIZmRHQmtUV3h5SnZETnVJWWhWUkw1eGVzLTBoTXBkWVRZIiwieSI6Ilp2eE1aNDJ0dzVMcDlDV0FUbllWT3Q4bkxhNzJRdEtjUFRENWphay1ZNncifX19.mwwICXVTPrH38BesqXZs3U-Zvc2SvAEo1YLFrukGkK1dRiyavku-ppBOeUPU_E4KKQQhMT2nDVUd_-GR5eN9OA~WyJTa25JV3VLMV9WVlhTQjJFb1l1UlJ3IiwgIm5hbWUiLCAiSm9obiJd~"

	static let responseString = "response=ey"
}
