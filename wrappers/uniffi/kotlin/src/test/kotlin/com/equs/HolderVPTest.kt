import com.equs.Fixtures
import com.equs.MockNonceHandler
import com.equs.VcCoreFixtures
import com.equs.credentials.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

// The generated fixture bundle has no request object; this suite exercises the
// PEX/`presentation_definition` code path, and no OID4VP verifier is exposed to the
// Kotlin/Swift UniFFI bindings (only
// `wrappers/uniffi/src/vc/oid4vp/holder.rs` exists -- there is no `verifier.rs`), unlike the
// nodejs wrapper the TypeScript suite uses (`OID4VPVerifierBuilder`). So this file mints its own
// PEX-format request object in-process, the same way `equs-test-fixtures`' `jws::sign_compact`
// does: base64url(header).base64url(payload), signed with `KeyHandle.sign()` -- a real ES256
// signature over a real, freshly generated `did:key`, using primitives already exposed to Kotlin
// (`InMemKms`, `DidKey`, `KeyHandle`).
const val VC_TYPE = "https://issuer.example/credential-schema"

val presentationDefinitionJson = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"$VC_TYPE"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()
val presentationDefinitionJsonWithFakeVct = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential_1"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()
val presentationDefinitionJsonWithFakeConstraints = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"$VC_TYPE"},"predicate":null,"intent_to_retain":false},{"path":["$.first_name"],"optional":false,"predicate":null,"intent_to_retain":false},{"path":["$.last_name", "$.surname"],"optional":false,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()

val clientMetadata =
    Json.parseToJsonElement("""{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["EdDSA","ES256"],"kb-jwt_alg_values":["EdDSA","ES256"]}},"jwks":{"keys":[{"use":"enc","alg":"ES256","kid":"5QsdgXUGuH:P256:","kty":"EC","crv":"P-256","x":"Cb_uJhiPN7H9KXdQN4PQN0uWC6LmEwIz4j03wX1rBAw","y":"yEZ8-uX5hGhCuN9NrIz4ShNH0T1y4fQts5siiCH0Q7w"}]},"encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"],"subject_syntax_types_supported":["did:key"]}""")
        .toString()
val clientMetadataWithDirectPostJwt =
    Json.parseToJsonElement("""{"vp_formats_supported":{"dc+sd-jwt":{"alg":["EdDSA","ES256"]}},"jwks":{"keys":[{"kid":"FxPNoKrsrw:P256:","kty":"EC","crv":"P-256","x":"M0zxcPWnayCVSiSlxLE-p9IP6bJbkCPbghap2Q-GKFY","y":"bYjdxpD5aJnMd1hnrBV8FxbJbXpcEUgogy2c265owHA","alg":"ES256"}]}}""")
        .toString()
const val CLIENT_ID = "did:key:zDnaekPT1E2PbmXnD7ZHu4My3jCykZUyCVv9FSN5dR6jQrGDo"

// Populated in `HolderVPTest`'s `@BeforeAll` -- the deep-link `client_id` must name the DID that
// actually signs `AUTH_REQUEST_JWT`, which is minted fresh on every run.
lateinit var VERIFIER_DID: String
lateinit var REQUEST_URI: String
lateinit var REQUEST_URI_FOR_TRANSACTION_DATA: String

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

// Both minted fresh in `HolderVPTest`'s `@BeforeAll`: `AUTH_REQUEST_JWT` is the real, signed
// compact JWS the mock server serves; `authRequest` is the `AuthorizationRequest` a real
// `holder.getAuthorizationRequest()` resolves that JWT to (used both for that comparison and
// directly, in-process, by the present/find/decline tests below).
lateinit var AUTH_REQUEST_JWT: String
lateinit var authRequest: AuthorizationRequest

// The credential under test, and its status-list pair -- minted fresh in `@BeforeAll`.
lateinit var VC: String
lateinit var STATUS_LIST: String
lateinit var VC_WITH_STATUS: String

private fun b64url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

private fun encodeTransactionDataItem(item: TransactionDataItem): String {
    val json = buildJsonObject {
        put("type", item.type)
        put("credential_ids", buildJsonArray { item.credentialIds.forEach { add(it) } })
        item.transactionDataHashesAlg?.let { algs ->
            put("transaction_data_hashes_alg", buildJsonArray { algs.forEach { add(it) } })
        }
    }
    return b64url(json.toString().toByteArray())
}

/**
 * Mints a real signed OID4VP request object carrying a `presentation_definition` query, matching
 * what the old committed `AUTH_REQUEST_JWT` carried. `client_id`/`nonce`/`state`/`response_uri`/
 * `transaction_data`/`client_metadata`/`presentation_definition` are unchanged from the old
 * fixture; only the signing key (and therefore `client_id`'s DID) is new, since that key's private
 * half isn't available to sign with any more.
 */
private suspend fun mintAuthRequestFixture(): Pair<String, AuthorizationRequest> {
    val kms = InMemKms()
    val kid = kms.create(KeyType.P256)
    val keyHandle = kms.get(kid)
    val did = DidKey().generate(keyHandle)
    val didUrl = "$did#${did.removePrefix("did:key:")}"
    val clientId = "decentralized_identifier:$did"

    val nonce = "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M"
    val state = "1d8b0d93-86e8-4135-87d4-524bb0500bf3"
    val responseUri = "http://localhost:9001/response"
    val transactionData = listOf(
        TransactionDataItem(
            type = "type1",
            credentialIds = listOf("Identity-1"),
            transactionDataHashesAlg = listOf("sha-256"),
        )
    )

    val header = buildJsonObject {
        put("alg", "ES256")
        put("kid", didUrl)
        put("typ", "application/oauth-authz-req+jwt")
    }

    val presentationDefinitionInner = Json.parseToJsonElement(presentationDefinitionJson)
        .jsonObject["presentation_definition"]!!

    val payload = buildJsonObject {
        put("response_type", "vp_token")
        put("state", state)
        put("transaction_data", buildJsonArray { transactionData.forEach { add(encodeTransactionDataItem(it)) } })
        put("response_mode", "direct_post")
        put("nonce", nonce)
        put("client_metadata", Json.parseToJsonElement(clientMetadata))
        put("client_id", clientId)
        put("presentation_definition", presentationDefinitionInner)
        put("response_uri", responseUri)
    }

    val signingInput = "${b64url(header.toString().toByteArray())}.${b64url(payload.toString().toByteArray())}"
    val signature = keyHandle.inner.sign(signingInput.toByteArray())
    val jwt = "$signingInput.${b64url(signature)}"

    VERIFIER_DID = did

    val resolvedAuthRequest = AuthorizationRequest(
        clientId = clientId,
        clientMetadata = clientMetadata,
        presentationDefinition = presentationDefinitionJson,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = responseUri,
        nonce = nonce,
        state = state,
        transactionData = transactionData,
        expectedOrigins = null,
    )

    return jwt to resolvedAuthRequest
}

/**
 * Mints a real, SDK-signed SD-JWT VC + status-list pair published at
 * `http://localhost:9001/status_list` -- the mock server `HolderVPTest` already serves on. The
 * generated bundle's own `vcWithStatus`/`statusListJwt` pair can't stand in for this: it's
 * published at the fixed `https://issuer.example/status-list`, which this suite's
 * `ReqwestHttpClient` (a real HTTP client, no interception) can never reach -- `issuer.example` is
 * a reserved, non-resolving domain, so the fetch would fail, not silently succeed. Reuses
 * `VcCoreFixtures` (`VcCoreTest.kt`), which already targets this exact URL and is proven against
 * the SDK's own status verifier.
 */
private suspend fun mintStatusCredentialPair(): Pair<String, String> {
    val issuerKms = InMemKms()
    val issuerKeyMetadata = createDidAndKeyMetadata(issuerKms).keyMetadata

    val statusIssuer = VcCoreStatusIssuer(issuerKms, VcCoreFixtures.statusIssuerMetadata(issuerKeyMetadata))
    val statusListJwt = (statusIssuer.issueStatusList(
        VcCoreFixtures.STATUS_LIST_ID,
        VcStatusesData.StatusListToken(listOf(StatusEntry(1u, 0u))),
    ) as StatusList.StatusListTokenJwt).v1

    val resolver = UniversalDidResolver(null)
    val issuer = VcCoreIssuer(issuerKms, VcCoreFixtures.issuerMetadata(issuerKeyMetadata), resolver)

    val holderKms = InMemKms()
    val holderVault = InMemVault()
    val holderKeyMetadata = createDidAndKeyMetadata(holderKms).keyMetadata
    val holder = VcCoreHolder(holderKms, holderVault, VcCoreFixtures.holderMetadata(), resolver, ReqwestHttpClient.insecure())

    val offer = issuer.offerCredential(VcCoreFixtures.SCOPE, null)
    val credentialRequest = holder.requestCredential(offer, VcCoreFixtures.NONCE, holderKeyMetadata)
    val credential = issuer.issueCredential(
        credentialRequest,
        VcCoreFixtures.claims,
        VcCoreFixtures.NONCE,
        VcCoreFixtures.credStatusInfo,
    )

    return credential.payload to statusListJwt
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

                val (jwt, resolved) = mintAuthRequestFixture()
                AUTH_REQUEST_JWT = jwt
                authRequest = resolved
                val encodedVerifierDid = VERIFIER_DID.replace(":", "%3A")
                REQUEST_URI =
                    "openid4vp://?client_id=decentralized_identifier%3A$encodedVerifierDid&request_uri=http%3A%2F%2Flocalhost%3A9001"
                REQUEST_URI_FOR_TRANSACTION_DATA =
                    "openid4vp://?client_id=decentralized_identifier%3A$encodedVerifierDid&request_uri=http%3A%2F%2Flocalhost%3A9005"

                VC = Fixtures.token("vc")
                val (vcWithStatus, statusListJwt) = mintStatusCredentialPair()
                VC_WITH_STATUS = vcWithStatus
                STATUS_LIST = statusListJwt

                val didAndKeyMetadata = createDidAndKeyMetadata(inMemKms)
                val subject = Fixtures.claim(VC, "sub")!!
                didAndKeyMetadata.keyMetadata.didUrl = "$subject#${subject.removePrefix("did:key:")}"
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
        holder.getAuthorizationRequest("openid4vp://?client_id=decentralized_identifier:$VERIFIER_DID&request_uri_method=post&request_uri=http://localhost:9002/request")
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

        val credentialsMapping = holder.findVcsForPresentation(authorizationRequest)
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
                            // The bundle's `vc` fixture discloses both `name` and `surname` (the
                            // fixture crate's SD-JWT VC builder always sets both -- unlike the old
                            // committed token, which only ever disclosed `name`), so the
                            // `surname`/`last_name` alternative is now genuinely satisfied; only
                            // `$.first_name` (which nothing discloses) is still missing.
                            assert(data.v1.v1 == listOf(listOf("$.first_name")))
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
