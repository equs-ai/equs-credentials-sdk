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

            let transactionData = TransactionDataItem(type: "type1", credentialIds: ["Identity-1"], transactionDataHashesAlg: ["sha-256"])

            #expect(actual.transactionData?.first?.type == transactionData.type)
            #expect(actual.transactionData?.first?.credentialIds.first == transactionData.credentialIds.first)
            #expect(actual.transactionData?.first?.transactionDataHashesAlg?.first == transactionData.transactionDataHashesAlg?.first)
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
