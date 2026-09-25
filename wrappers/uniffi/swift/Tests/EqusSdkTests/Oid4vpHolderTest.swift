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
		let minted = try await MintedOid4vp.authRequest.value
		self.http["/auth_request"] = { request in
			return MockHttpRouter.ok(minted.jwt, contentType: "application/oauth-authz-req+jwt")
		}

		let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
			requestUri: minted.requestUri)

		compareJsonValues(
			actual: actual.clientMetadata,
			expected: minted.authRequest.clientMetadata)
		compareJsonValues(
			actual: actual.presentationDefinition,
			expected: minted.authRequest.presentationDefinition)

		#expect(actual.clientId == minted.authRequest.clientId)
		#expect(actual.nonce == minted.authRequest.nonce)
		#expect(actual.responseType == minted.authRequest.responseType)
		#expect(actual.responseMode == minted.authRequest.responseMode)
		#expect(actual.responseUri == minted.authRequest.responseUri)
		#expect(actual.state == minted.authRequest.state)
	}

		@Test func getAuthorizationRequestWithTransactionData() async throws {
			let minted = try await MintedOid4vp.authRequest.value
    			self.http["/auth_request"] = { request in
    				return MockHttpRouter.ok(minted.jwt, contentType: "application/oauth-authz-req+jwt")
    			}

    			let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
    				requestUri: minted.requestUriForTransactionData)

            let transactionData = TransactionDataItem(type: "type1", credentialIds: ["Identity-1"], transactionDataHashesAlg: ["sha-256"])

            #expect(actual.transactionData?.first?.type == transactionData.type)
            #expect(actual.transactionData?.first?.credentialIds.first == transactionData.credentialIds.first)
            #expect(actual.transactionData?.first?.transactionDataHashesAlg?.first == transactionData.transactionDataHashesAlg?.first)
    	}

	@Test func checkCustomNonceHandler() async throws {
		let minted = try await MintedOid4vp.authRequest.value
		self.http["/request"] = { request in
			let body = request.body ?? "<invalid body>"
			#expect(body.contains("some_nonce"))
			return MockHttpRouter.ok(minted.jwt, contentType: "application/oauth-authz-req+jwt")
		}

		let actual: AuthorizationRequest = try await self.holder.getAuthorizationRequest(
			requestUri: minted.requestUriWithMethod)
	}

	@Test func presentCredentialsAuto() async throws {
		let minted = try await MintedOid4vp.authRequest.value
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.http["/response"] = { request in
				let body = request.body!.removingPercentEncoding!

				// The credential discloses both `name` and `surname` (the fixture crate's SD-JWT
				// VC builder always sets both), but the presentation definition only requests
				// `$.name`, so presenting it drops the unneeded `surname` disclosure -- the full
				// compact credential string is therefore no longer a literal substring of the
				// presented body. Its JWS part (everything before the disclosures) is unchanged,
				// and the specifically requested `name` disclosure is still present; check those
				// instead of the whole string.
				#expect(body.contains(Fixtures.jwsPrefix(Oid4vpHolderTestConstants.sdJwtPayload)))
				#expect(body.contains(Fixtures.disclosure(Oid4vpHolderTestConstants.sdJwtPayload, forClaim: "name")!))

				confirmResponse()
				return MockHttpRouter.ok("", contentType: "text/plain")
			}

			let holder = try await Oid4vpHolderTests.setupHolder(http: http)

			let _ = try await holder.presentCredentialsAuto(
				authRequest: minted.authRequest,
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
		let minted = try await MintedOid4vp.authRequest.value
		try await confirmation("Auth Response is not received") { confirmResponse in
			self.http["/response"] = { request in
				let body = request.body!.removingPercentEncoding!

				// The credential discloses both `name` and `surname` (the fixture crate's SD-JWT
				// VC builder always sets both), but the presentation definition only requests
				// `$.name`, so presenting it drops the unneeded `surname` disclosure -- the full
				// compact credential string is therefore no longer a literal substring of the
				// presented body. Its JWS part (everything before the disclosures) is unchanged,
				// and the specifically requested `name` disclosure is still present; check those
				// instead of the whole string.
				#expect(body.contains(Fixtures.jwsPrefix(Oid4vpHolderTestConstants.sdJwtPayload)))
				#expect(body.contains(Fixtures.disclosure(Oid4vpHolderTestConstants.sdJwtPayload, forClaim: "name")!))

				confirmResponse()
				return MockHttpRouter.ok("", contentType: "text/plain")
			}

			let holder = try await Oid4vpHolderTests.setupHolder(http: http)

			let credentials = try await holder.findVcsForPresentation(
				authRequest: minted.authRequest)

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
				authRequest: minted.authRequest,
				credentialMapping: credentialMapping,
				authResponseMetadata: AuthorizationResponseMetadata(
					claimsToExclude: nil, idTokenMetadata: nil, dcApiOrigin: nil)
			)
		}
	}

	@Test
	func findVcsForPresentationReturnsCredentials() async throws {
		let minted = try await MintedOid4vp.authRequest.value

		let credentialsMapping = try await self.holder.findVcsForPresentation(
			authRequest: minted.authRequest)

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
                    // The bundle's `vc` fixture discloses both `name` and `surname` (the fixture
                    // crate's SD-JWT VC builder always sets both -- unlike the old committed
                    // token, which only ever disclosed `name`), so the `surname`/`last_name`
                    // alternative is now genuinely satisfied; only `$.first_name` (which nothing
                    // discloses) is still missing.
                    #expect(claimsPaths == [["$.first_name"]])
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
		let minted = try await MintedOid4vp.authRequest.value
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
				authRequest: minted.authRequest)
		}
	}

	@Test func getCredentialStatus() async throws {
        self.http["/status-list"] = { request in
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
        let subject = Fixtures.claim(Oid4vpHolderTestConstants.sdJwtPayload, "sub")!
        didAndKeyMetadata.keyMetadata.didUrl = "\(subject)#\(subject.replacingOccurrences(of: "did:key:", with: ""))"

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

// The generated fixture bundle's `authRequestJwt` is a DCQL/`dc_api.jwt` request (see
// `test-fixtures/src/request_object.rs`); this suite exercises the PEX/`presentation_definition`
// code path instead, and no OID4VP verifier is exposed to the Swift UniFFI bindings (only
// `Oid4vpHolder` exists), unlike the nodejs wrapper the TypeScript suite uses
// (`OID4VPVerifierBuilder`). So `MintedOid4vp` mints its own PEX-format request object
// in-process instead, the same way `equs-test-fixtures`' `jws::sign_compact` does -- see
// `JwsFixtures.swift`.
//
// The bundle's `vcWithStatus`/`statusListJwt` pair *is* usable here, unlike in the TypeScript
// suite: `MockHttpRouter` (see `MockHttpRouter.swift`) matches routes on URL *path* only, never
// touching real DNS/sockets, so the bundle's fixed `https://issuer.example/status-list` is
// reachable simply by registering that path -- no local minting needed for it.
enum MintedOid4vp {
    struct AuthRequestFixture: Sendable {
        let jwt: String
        let authRequest: AuthorizationRequest
        let requestUri: String
        let requestUriForTransactionData: String
        let requestUriWithMethod: String
    }

    static let authRequest: Task<AuthRequestFixture, any Swift.Error> = Task {
        try await mintAuthRequestFixture()
    }
}

private func mintAuthRequestFixture() async throws -> MintedOid4vp.AuthRequestFixture {
    let nonce = "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M"
    let state = "1d8b0d93-86e8-4135-87d4-524bb0500bf3"
    let responseUri = "http://localhost:9001/response"

    let key = try await JwsFixtures.newSigningKey()
    let clientId = "decentralized_identifier:\(key.did)"

    let transactionDataItem: [String: Any] = [
        "type": "type1",
        "credential_ids": ["Identity-1"],
        "transaction_data_hashes_alg": ["sha-256"],
    ]
    let transactionDataEncoded = JwsFixtures.b64url(JwsFixtures.jsonBytes(transactionDataItem))

    let pdObject =
        try JSONSerialization.jsonObject(
            with: Oid4vpHolderTestConstants.presentationDefinition.data(using: .utf8)!) as! [String: Any]
    let presentationDefinitionInner = pdObject["presentation_definition"]!

    let clientMetadataObject =
        try JSONSerialization.jsonObject(
            with: Oid4vpHolderTestConstants.clientMetadata.data(using: .utf8)!) as! [String: Any]

    let header: [String: Any] = [
        "alg": "ES256",
        "kid": key.didUrl,
        "typ": "application/oauth-authz-req+jwt",
    ]
    let payload: [String: Any] = [
        "response_type": "vp_token",
        "state": state,
        "transaction_data": [transactionDataEncoded],
        "response_mode": "direct_post",
        "nonce": nonce,
        "client_metadata": clientMetadataObject,
        "client_id": clientId,
        "presentation_definition": presentationDefinitionInner,
        "response_uri": responseUri,
    ]

    let jwt = try await JwsFixtures.sign(header: header, payload: payload, key: key)

    let transactionData = TransactionDataItem(
        type: "type1", credentialIds: ["Identity-1"], transactionDataHashesAlg: ["sha-256"])

    let authRequest = AuthorizationRequest(
        clientId: clientId,
        clientMetadata: Oid4vpHolderTestConstants.clientMetadata,
        presentationDefinition: Oid4vpHolderTestConstants.presentationDefinition,
        nonce: nonce,
        responseType: "vp_token",
        responseMode: "direct_post",
        responseUri: responseUri,
        state: state,
        transactionData: [transactionData],
        expectedOrigins: nil
    )

    let encodedDid = key.did.replacingOccurrences(of: ":", with: "%3A")
    let requestUri =
        "openid4vp://?client_id=decentralized_identifier%3A\(encodedDid)&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
    let requestUriForTransactionData =
        "openid4vp://?client_id=decentralized_identifier%3A\(encodedDid)&request_uri=http%3A%2F%2Flocalhost%3A9001%2Fauth_request"
    let requestUriWithMethod =
        "openid4vp://?client_id=decentralized_identifier:\(key.did)&request_uri_method=post&request_uri=http://localhost:9002/request"

    return MintedOid4vp.AuthRequestFixture(
        jwt: jwt, authRequest: authRequest, requestUri: requestUri,
        requestUriForTransactionData: requestUriForTransactionData,
        requestUriWithMethod: requestUriWithMethod)
}

enum Oid4vpHolderTestConstants {
	static let VC_TYPE = "https://issuer.example/credential-schema"

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
				                     "const":"\(VC_TYPE)"
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
                        "const": "\(VC_TYPE)"
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

	static let sdJwtPayload = Fixtures.token("vc")

    static let statusList = Fixtures.token("statusListJwt")
    static let sdJwtWithStatusPayload = Fixtures.token("vcWithStatus")

	static let responseString = "response=ey"
}
