import com.equs.Fixtures
import com.equs.MockNonceHandler
import com.equs.credentials.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlinx.serialization.json.Json
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

val presentationDefinitionJson = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()
val presentationDefinitionJsonWithFakeVct = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential_1"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()
val presentationDefinitionJsonWithFakeConstraints = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential"},"predicate":null,"intent_to_retain":false},{"path":["$.first_name"],"optional":false,"predicate":null,"intent_to_retain":false},{"path":["$.last_name", "$.surname"],"optional":false,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()

val clientMetadata =
    Json.parseToJsonElement("""{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["EdDSA","ES256"],"kb-jwt_alg_values":["EdDSA","ES256"]}},"jwks":{"keys":[{"use":"enc","alg":"ES256","kid":"5QsdgXUGuH:P256:","kty":"EC","crv":"P-256","x":"Cb_uJhiPN7H9KXdQN4PQN0uWC6LmEwIz4j03wX1rBAw","y":"yEZ8-uX5hGhCuN9NrIz4ShNH0T1y4fQts5siiCH0Q7w"}]},"encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"],"subject_syntax_types_supported":["did:key"]}""")
        .toString()
val clientMetadataWithDirectPostJwt =
    Json.parseToJsonElement("""{"vp_formats_supported":{"dc+sd-jwt":{"alg":["EdDSA","ES256"]}},"jwks":{"keys":[{"kid":"FxPNoKrsrw:P256:","kty":"EC","crv":"P-256","x":"M0zxcPWnayCVSiSlxLE-p9IP6bJbkCPbghap2Q-GKFY","y":"bYjdxpD5aJnMd1hnrBV8FxbJbXpcEUgogy2c265owHA","alg":"ES256"}]}}""")
        .toString()
val VERIFIER_CLIENT_ID: String by lazy { "decentralized_identifier:${fixtureDidKey(FixtureKey.VERIFIER)}" }
val ENCODED_VERIFIER_CLIENT_ID: String by lazy { VERIFIER_CLIENT_ID.replace(":", "%3A") }
const val CLIENT_ID = "did:key:zDnaekPT1E2PbmXnD7ZHu4My3jCykZUyCVv9FSN5dR6jQrGDo"
val REQUEST_URI: String by lazy {
    "openid4vp://?client_id=$ENCODED_VERIFIER_CLIENT_ID&request_uri=http%3A%2F%2Flocalhost%3A9001"
}
val REQUEST_URI_FOR_TRANSACTION_DATA: String by lazy {
    "openid4vp://?client_id=$ENCODED_VERIFIER_CLIENT_ID&request_uri=http%3A%2F%2Flocalhost%3A9005"
}
val authRequest: AuthorizationRequest by lazy {
    AuthorizationRequest(
        clientId = VERIFIER_CLIENT_ID,
        clientMetadata = clientMetadata,
        presentationDefinition = presentationDefinitionJson,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = "http://localhost:9001/response",
        nonce = "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M",
        state = "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
        transactionData = listOf(
            TransactionDataItem(
                type = "type1",
                credentialIds = listOf("Identity-1"),
                transactionDataHashesAlg = listOf("sha-256")
            )
        ),
        expectedOrigins = null,
    )
}

val authRequestWithDirectPostJwt = AuthorizationRequest(
    clientId = "decentralized_identifier:did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadataWithDirectPostJwt,
    presentationDefinition = presentationDefinitionJson,
    responseType = "vp_token",
    responseMode = "direct_post.jwt",
    responseUri = "http://localhost:9003/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c",
    transactionData = null,
    expectedOrigins = null,
)
val authRequestWithFakeVct = AuthorizationRequest(
    clientId = "decentralized_identifier:did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadata,
    presentationDefinition = presentationDefinitionJsonWithFakeVct,
    responseType = "vp_token",
    responseMode = "direct_post",
    responseUri = "http://localhost:9001/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c",
    transactionData = null,
    expectedOrigins = null,
)
val authRequestWithFakeConstraints = AuthorizationRequest(
    clientId = "decentralized_identifier:did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadata,
    presentationDefinition = presentationDefinitionJsonWithFakeConstraints,
    responseType = "vp_token",
    responseMode = "direct_post",
    responseUri = "http://localhost:9001/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c",
    transactionData = null,
    expectedOrigins = null,
)
val TRANSACTION_DATA: String =
    Fixtures.base64Url("""{"type":"type1","credential_ids":["Identity-1"],"transaction_data_hashes_alg":["sha-256"]}""")
val AUTH_REQUEST_JWT: String by lazy {
    fixtureJws(
        """{"alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.VERIFIER)}","typ":"application/oauth-authz-req+jwt"}""",
        """{"response_type":"vp_token","state":"1d8b0d93-86e8-4135-87d4-524bb0500bf3","transaction_data":["$TRANSACTION_DATA"],"response_mode":"direct_post","nonce":"F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M","client_metadata":{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["EdDSA","ES256"],"kb-jwt_alg_values":["EdDSA","ES256"]}},"jwks":{"keys":[{"use":"enc","alg":"ES256","kid":"5QsdgXUGuH:P256:","kty":"EC","crv":"P-256","x":"Cb_uJhiPN7H9KXdQN4PQN0uWC6LmEwIz4j03wX1rBAw","y":"yEZ8-uX5hGhCuN9NrIz4ShNH0T1y4fQts5siiCH0Q7w"}]},"encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"],"subject_syntax_types_supported":["did:key"]},"client_id":"$VERIFIER_CLIENT_ID","presentation_definition":{"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]},"response_uri":"http://localhost:9001/response"}""",
        FixtureKey.VERIFIER,
    )
}
val VC: String by lazy {
    fixtureSdJwt(
        """{"typ":"dc+sd-jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
        """{"sub":"${fixtureDidKey(FixtureKey.HOLDER)}","vct":"https://credentials.example.com/identity_credential","iat":1760606075,"_sd_alg":"sha-256","iss":"${fixtureDidKey(FixtureKey.ISSUER)}","exp":2075966075,"nbf":1760606075,"cnf":{"jwk":${fixturePublicJwk(FixtureKey.HOLDER)}}}""",
        listOf("""["SknIWuK1_VVXSB2EoYuRRw", "name", "John"]"""),
        FixtureKey.ISSUER,
    )
}
val STATUS_LIST: String by lazy {
    fixtureJws(
        """{"typ":"statuslist+jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
        """{"status_list":{"lst":"eNqbwMwABgAEnQCU","bits":2},"sub":"http://localhost:9001/status_list","iat":1763025623,"_sd_alg":"sha-256"}""",
        FixtureKey.ISSUER,
    ) + "~"
}
val VC_WITH_STATUS: String by lazy {
    fixtureSdJwt(
        """{"typ":"dc+sd-jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
        """{"address":"221B Baker Street","iat":1753054448,"date":"09/09/1989","sub":"${fixtureDidKey(FixtureKey.HOLDER)}","vct":"https://credentials.example.com/identity_credential","status":{"status_list":{"uri":"http://localhost:9001/status_list","idx":1}},"_sd_alg":"sha-256","iss":"${fixtureDidKey(FixtureKey.ISSUER)}","exp":1753055048,"nbf":1753054448,"cnf":{"jwk":${fixturePublicJwk(FixtureKey.HOLDER)}}}""",
        listOf(
            """["uxLNTemWQkc1VO6LgsArlQ", "name", "John"]""",
            """["2CBudCWI5EImahgzdcU1Vw", "surname", "Doe"]""",
        ),
        FixtureKey.ISSUER,
    )
}

//Note: The webserver sends the auth requests as queue object and whichever test thread is first gets the top of the queue.
// This works when all the tests need the same request but for other tests that need different request, we created another server in a different port.

class HolderVPTest {
    companion object {
        lateinit var mockServer: MockWebServer
        lateinit var holder: Oid4vpHolder

        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
            mockServer = MockWebServer()
            mockServer.start(9001)
            runBlocking {
                val inMemKms = InMemKms()
                val inMemVault = InMemVault()

                val didAndKeyMetadata = createDidAndKeyMetadata(inMemKms)
                didAndKeyMetadata.keyMetadata.didUrl = fixtureDidKeyUrl(FixtureKey.HOLDER)
                val credential = Credential(format = VcFormat.SD_JWT_VC, payload = VC)
                val metadata = resolveMetadata(credential, didAndKeyMetadata.keyMetadata)

                holder = Oid4vpHolderBuilder(
                    inMemKms, inMemVault, CLIENT_ID, ReqwestHttpClient.insecure(),
                    MockNonceHandler("some_nonce")
                ).build()

                inMemVault.storeCredential(credential, metadata)
            }
        }

        @JvmStatic
        @AfterAll
        fun after_all() {
            mockServer.shutdown()
        }
    }


    @Test
    fun testGetAuthorizationRequestWithTransactionData() = runTest {
        val mockServer = MockWebServer()
        mockServer.start(9005)
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(AUTH_REQUEST_JWT)
                .setHeader("content-type", "application/oauth-authz-req+jwt")
        )

        val authorizationRequest = holder.getAuthorizationRequest(REQUEST_URI_FOR_TRANSACTION_DATA)

        val transactionData = listOf(
            TransactionDataItem(
                type = "type1",
                credentialIds = listOf("Identity-1"),
                transactionDataHashesAlg = listOf("sha-256")
            )
        )
        assert(transactionData == authorizationRequest.transactionData)
        mockServer.shutdown()

    }

    @Test
    fun testGetAuthorizationRequest() = runTest {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(AUTH_REQUEST_JWT)
                .setHeader("content-type", "application/oauth-authz-req+jwt")
        )

        val authorizationRequest = holder.getAuthorizationRequest(REQUEST_URI)
        assertEquals(authRequest, authorizationRequest)
    }

    @Test
    fun testCustomNonceHandler() = runTest {
        val mockServer = MockWebServer()
        mockServer.start(9002)

        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(AUTH_REQUEST_JWT)
                .setHeader("content-type", "application/oauth-authz-req+jwt")
        )
        holder.getAuthorizationRequest("openid4vp://?client_id=$VERIFIER_CLIENT_ID&request_uri_method=post&request_uri=http://localhost:9002/request")
        val request = mockServer.takeRequest()
        val body = request.body.readUtf8()
        assert(request.method.equals("POST"))
        assert(body.contains("some_nonce"))
        mockServer.shutdown()
    }

    @Test
    fun testPresentCredentialsAuto() = runTest {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("")
                .setHeader("content-type", "text/plain")
        )

        val presented = holder.presentCredentialsAuto(
            authRequest,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = null)
        ) as PresentationResult.Presented
    }

    @Test
    fun testPresentCredentialsAutoWithDirectPostJwt() = runTest {

        // We need to check the request for this test. So we need a new mock server
        val customMockServer = MockWebServer()
        customMockServer.start(9003)
        customMockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("")
                .setHeader("content-type", "text/plain")
        )
        val presented = holder.presentCredentialsAuto(
            authRequestWithDirectPostJwt,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = null)
        ) as PresentationResult.Presented
        val request = customMockServer.takeRequest()
        assert(request.body.readUtf8().startsWith("response=ey"))

        customMockServer.shutdown()
    }

    @Test
    fun testPresentCredentials() = runTest {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("")
                .setHeader("content-type", "text/plain")
        )

        val credentialsMapping = holder.findVcsForPresentation(authRequest)
        val credentials = credResultsToCredMapping(credentialsMapping)

        holder.presentCredentials(
            authRequest,
            credentials,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = null)
        )
    }


    @Test
    fun testPresentCredentialsWhenDcApiResponseIsUsed() = runTest {
        val authorizationRequest = authRequest.copy(responseMode = "dc_api", responseUri = null)

        val credentialsMapping = holder.findVcsForPresentation(authRequest)
        val credentials = credResultsToCredMapping(credentialsMapping)

        val result = holder.presentCredentials(
            authorizationRequest,
            credentials,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = "https://example.verifier.org")
        ) as PresentationResult.AuthResponse

        val authResponse = result.v1 as AuthorizationResponse.Plain

        assertNotNull(authResponse.v1.vpToken)
    }


    @Test
    fun testPresentCredentialsWhenDcApiJwtResponseIsUsed() = runTest {
        val origin = "https://example.verifier.org";
        val authorizationRequest = authRequest.copy(responseMode = "dc_api.jwt", responseUri = null, expectedOrigins = listOf(origin))

        val credentialsMapping = holder.findVcsForPresentation(authRequest)
        val credentials = credResultsToCredMapping(credentialsMapping)

        val result = holder.presentCredentials(
            authorizationRequest,
            credentials,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = origin)
        ) as PresentationResult.AuthResponse

        val authResponse = result.v1 as AuthorizationResponse.Jwe

        assert(authResponse.v1.startsWith("ey"))
    }

    @Test
    fun testPresentCredentialsForDcApiResponseModeFailsWhenOriginIsNotProvided() = runTest {
        val authorizationRequest = authRequest.copy(responseMode = "dc_api", responseUri = null)

        val credentialsMapping = holder.findVcsForPresentation(authRequest)
        val credentials = credResultsToCredMapping(credentialsMapping)

        try {
            holder.presentCredentials(
                authorizationRequest,
                credentials,
                AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = null)
            )
            throw Exception("Unexpected result. Should throw Exception.Oid4vpHolder exception")
        } catch (e: Exception.Oid4vpHolder) {
            assert(e.message.contains("origin value of authorization response metadata is missed. Its required for dc_api/dc_api.jwt response mode"))
        }
    }

    private fun credResultsToCredMapping(credentialsMapping: Map<String, CredentialsFindResult>): Map<String, List<CredentialEntry>> =
        credentialsMapping.map { (key, findVCsResult) ->
            when (val data = findVCsResult.data) {
                is CredentialsSearchResult.Credentials -> {
                    key to data.v1
                }

                is CredentialsSearchResult.Reason -> {
                    throw IllegalStateException("Find vcs for presentation returned reasons of failure: $data")
                }
            }
        }.toMap()

    @Test
    fun findVcsForPresentationReturnsCredentials() = runTest {
        val credentialsMapping = holder.findVcsForPresentation(authRequest)
        credentialsMapping.map { (key, findVCsResult) ->
            when (val data = findVCsResult.data) {
                is CredentialsSearchResult.Credentials -> {
                    val credential = data.v1.firstOrNull()
                        ?: throw IllegalStateException("No credentials found for key: $key")
                    key to credential
                }

                is CredentialsSearchResult.Reason -> {
                    throw IllegalStateException("Find vcs for presentation returned reasons of failure: $data")
                }
            }
        }

    }

    @Test
    fun findVcsForPresentationReturnsReasonsOfFailure() = runTest {

        val credentialsMapping = holder.findVcsForPresentation(authRequestWithFakeConstraints)

        credentialsMapping.map { (key, findVCsResult) ->
            when (val data = findVCsResult.data) {
                is CredentialsSearchResult.Credentials -> {
                    throw IllegalStateException("Find vcs for presentation returned credentials instead of reasons of failure: $key -> $data")
                }

                is CredentialsSearchResult.Reason -> {
                    when (data.v1) {
                        is FindVCsFailReason.Paths -> {
                            assert(data.v1.v1 == listOf(listOf("$.first_name"), listOf("$.last_name", "$.surname")))
                        }

                        else -> {
                            throw IllegalStateException("Find vcs for presentation returned wrong reason: $data")

                        }
                    }
                }

            }
        }
    }

    @Test
    fun findVcsForPresentationReturnsReasonTypesNotMatched() = runTest {
        val credentialsMapping = holder.findVcsForPresentation(authRequestWithFakeVct)

        credentialsMapping.map { (key, findVCsResult) ->
            when (val data = findVCsResult.data) {
                is CredentialsSearchResult.Credentials -> {
                    throw IllegalStateException("Find vcs for presentation returned credentials instead of reasons of failure: $key -> $data")
                }

                is CredentialsSearchResult.Reason -> {
                    when (data.v1) {
                        is FindVCsFailReason.TypesNotMatched -> {
                        }

                        else -> {
                            throw IllegalStateException("Find vcs for presentation should return TypesNotMatched but returned wrong reason: $data")

                        }
                    }
                }

            }
        }
    }

    @Test
    fun findVcsForPresentationReturnsReasonCredentialsNotFoundDueToExpiredStatus() = runTest {
        val inMemKms = InMemKms()
        val inMemVault = InMemVault()

        val holder = Oid4vpHolderBuilder(
            inMemKms, inMemVault, CLIENT_ID, ReqwestHttpClient.insecure(),
            MockNonceHandler("some_nonce")
        ).build()

        val credentialsMapping = holder.findVcsForPresentation(authRequestWithFakeVct)

        credentialsMapping.map { (key, findVCsResult) ->
            when (val data = findVCsResult.data) {
                is CredentialsSearchResult.Credentials -> {
                    throw IllegalStateException("Find vcs for presentation returned credentials instead of reasons of failure: $key -> $data")
                }

                is CredentialsSearchResult.Reason -> {
                    when (data.v1) {
                        is FindVCsFailReason.CredentialsNotFound -> {
                        }

                        else -> {
                            throw IllegalStateException("Find vcs for presentation should return CredentialsNotFound but returned wrong reason: $data")

                        }
                    }
                }

            }
        }
    }

    @Test
    fun testDeclineAuthorizationRequest() = runTest {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("")
                .setHeader("content-type", "text/plain")
        )

        holder.declineAuthorizationRequest(authRequest)
        // Ugly hack
        repeat(mockServer.requestCount - 1) {
            mockServer.takeRequest()
        }
        val request = String(mockServer.takeRequest(3, TimeUnit.SECONDS)!!.body.readByteArray())
        assertEquals(
            "error=access_denied&error_description=consent+to+share+the+presentation+is+not+given&state=1d8b0d93-86e8-4135-87d4-524bb0500bf3",
            request
        )
    }

    @Test
    fun testGettingCredentialStatus() = runTest {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(STATUS_LIST)
                .setHeader("content-type", "application/statuslist+jwt")
        )

        val credential = Credential(format = VcFormat.SD_JWT_VC, payload = VC_WITH_STATUS)
        val status = holder.getCredentialStatus(credential)!! as VcStatus.StatusListToken

        assertEquals(status.v1, TslVcStatus.Valid)
    }
}