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
const val CLIENT_ID = "did:key:zDnaekPT1E2PbmXnD7ZHu4My3jCykZUyCVv9FSN5dR6jQrGDo"
const val REQUEST_URI =
    "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN&request_uri=http%3A%2F%2Flocalhost%3A9001"
const val REQUEST_URI_FOR_TRANSACTION_DATA =
    "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN&request_uri=http%3A%2F%2Flocalhost%3A9005"
val authRequest = AuthorizationRequest(
    clientId = "decentralized_identifier:did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN",
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
const val AUTH_REQUEST_JWT =
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVRcE5ZUUQ2aDE4Vm5hZ3lBMVhiZXk5aEZLQTFqNWN5aHFQSEdmYXE5dHhtTiN6RG5hZVFwTllRRDZoMThWbmFneUExWGJleTloRktBMWo1Y3locVBIR2ZhcTl0eG1OIiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6IjFkOGIwZDkzLTg2ZTgtNDEzNS04N2Q0LTUyNGJiMDUwMGJmMyIsInRyYW5zYWN0aW9uX2RhdGEiOlsiZXlKMGVYQmxJam9pZEhsd1pURWlMQ0pqY21Wa1pXNTBhV0ZzWDJsa2N5STZXeUpKWkdWdWRHbDBlUzB4SWwwc0luUnlZVzV6WVdOMGFXOXVYMlJoZEdGZmFHRnphR1Z6WDJGc1p5STZXeUp6YUdFdE1qVTJJbDE5Il0sInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiRjN2YkN5WFY0QmtqLVJDb25laUcxaUtkQTVYdWFFSEhheWNPSUNJTnUyTSIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2Il19fSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJlbmMiLCJhbGciOiJFUzI1NiIsImtpZCI6IjVRc2RnWFVHdUg6UDI1NjoiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkNiX3VKaGlQTjdIOUtYZFFONFBRTjB1V0M2TG1Fd0l6NGowM3dYMXJCQXciLCJ5IjoieUVaOC11WDVoR2hDdU45TnJJejRTaE5IMFQxeTRmUXRzNXNpaUNIMFE3dyJ9XX0sImVuY3J5cHRlZF9yZXNwb25zZV9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4R0NNIiwiQTEyOENCQy1IUzI1NiJdLCJzdWJqZWN0X3N5bnRheF90eXBlc19zdXBwb3J0ZWQiOlsiZGlkOmtleSJdfSwiY2xpZW50X2lkIjoiZGVjZW50cmFsaXplZF9pZGVudGlmaWVyOmRpZDprZXk6ekRuYWVRcE5ZUUQ2aDE4Vm5hZ3lBMVhiZXk5aEZLQTFqNWN5aHFQSEdmYXE5dHhtTiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMWI5ZDZiY2QtYmJmZC00YjJkLTliNWQtYWI4ZGZiYmQ0YmVkIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn0sInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm5hbWUiXSwib3B0aW9uYWwiOnRydWUsInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX0sIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7ImRjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl0sImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXX19fV19LCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvcmVzcG9uc2UifQ.27WD-THq-vBdZZNb20WY3VYDRbbws0PTcp6LZM_GFh8Bhpp7tVPZnhu2m362D9E_fWtIwbLQiHzdigP27D9VyA"
const val VC =
    "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVkNnN6c044VDhBWEhxQ044ZXFVOW9mWFpLQ1FDZUhzN2hqdmhVOHdiTmd4OSN6RG5hZWQ2c3pzTjhUOEFYSHFDTjhlcVU5b2ZYWktDUUNlSHM3aGp2aFU4d2JOZ3g5In0.eyJfc2QiOlsiZkZnbndmQ2k4TjZ0dUlYZWtCUU5BWC05eFA0RURkcVhTaXlpMV9NSWdJayJdLCJzdWIiOiJkaWQ6a2V5OnpEbmFlWjFNdUtkeFlzejRVTTY5Y0p6NmNFSkpWbzlhUzRHS1RrR3Z6MWE0ZjlGaXUiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJpYXQiOjE3NjA2MDYwNzUsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZWQ2c3pzTjhUOEFYSHFDTjhlcVU5b2ZYWktDUUNlSHM3aGp2aFU4d2JOZ3g5IiwiZXhwIjoyMDc1OTY2MDc1LCJuYmYiOjE3NjA2MDYwNzUsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJmMnVCbkhIZ1BIZmRHQmtUV3h5SnZETnVJWWhWUkw1eGVzLTBoTXBkWVRZIiwieSI6Ilp2eE1aNDJ0dzVMcDlDV0FUbllWT3Q4bkxhNzJRdEtjUFRENWphay1ZNncifX19.mwwICXVTPrH38BesqXZs3U-Zvc2SvAEo1YLFrukGkK1dRiyavku-ppBOeUPU_E4KKQQhMT2nDVUd_-GR5eN9OA~WyJTa25JV3VLMV9WVlhTQjJFb1l1UlJ3IiwgIm5hbWUiLCAiSm9obiJd~"
const val STATUS_LIST =
    "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZVp4QmJlVFdBYlhOcXlHZER4dDJXRTZjbzNteHU0VllEOHlieXlkdjhkQnh4I3pEbmFlWnhCYmVUV0FiWE5xeUdkRHh0MldFNmNvM214dTRWWUQ4eWJ5eWR2OGRCeHgifQ.eyJzdGF0dXNfbGlzdCI6eyJsc3QiOiJlTnFid013QUJnQUVuUUNVIiwiYml0cyI6Mn0sInN1YiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9zdGF0dXNfbGlzdCIsImlhdCI6MTc2MzAyNTYyMywiX3NkX2FsZyI6InNoYS0yNTYifQ.lCOpC_53MXw4mShUwGtLbxh3Ha-qFNiRohPTZWo2XyCkBVSWn2daxEjSXM048p2DN8LAo61fcgAA69BGvcf5WQ~"
const val VC_WITH_STATUS =
    "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVmYUdTd1RmWmsyVXVRV1JqRFQ1Z3J0TEw2RWE1Z3hGcjVBN1hyMzZIUXdtQiN6RG5hZWZhR1N3VGZaazJVdVFXUmpEVDVncnRMTDZFYTVneEZyNUE3WHIzNkhRd21CIn0.eyJfc2QiOlsiTGtNQ3hnT3dKZXVWa2xFUVIxYUl1TDVUSXllRkZiSUhEYXNjZk9EOGlHWSIsInc5WHpEVG5YMFRNOVFFX0NjYUVSaUtpbVV3VkFkWEwxRzZIdU1wZHdkclkiXSwiYWRkcmVzcyI6IjIyMUIgQmFrZXIgU3RyZWV0IiwiaWF0IjoxNzUzMDU0NDQ4LCJkYXRlIjoiMDkvMDkvMTk4OSIsInN1YiI6ImRpZDprZXk6ekRuYWVoVzJXWERnaHBNMTZYRzN5Z2Vja2FSTWJpamJjWG9tZnQ0ZzI2cnlpUlZXUiIsInZjdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCIsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJ1cmkiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvc3RhdHVzX2xpc3QiLCJpZHgiOjF9fSwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6a2V5OnpEbmFlZmFHU3dUZlprMlV1UVdSakRUNWdydExMNkVhNWd4RnI1QTdYcjM2SFF3bUIiLCJleHAiOjE3NTMwNTUwNDgsIm5iZiI6MTc1MzA1NDQ0OCwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Il9hRHExTWE2SFNOUUZrR0F0ZnBpNlR3UnVuMUhlVnpCWWo2R29DcEhmcW8iLCJ5IjoiSTY0VnRmaTNlbzktQTM0TmNNMFJ4cHRsbzhiOGd1RUV3dnd2S2w1YUZlWSJ9fX0.jruSbbpygwgyWcJ2DO0myKlGimKW0n_dsYc5l-hksJqIWZF2Wy5Sf01nZlkUop-_JkN3x9Ct1kCOHes8-Ozdxg~WyJ1eExOVGVtV1FrYzFWTzZMZ3NBcmxRIiwgIm5hbWUiLCAiSm9obiJd~WyIyQ0J1ZENXSTVFSW1haGd6ZGNVMVZ3IiwgInN1cm5hbWUiLCAiRG9lIl0~"

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
                didAndKeyMetadata.keyMetadata.didUrl =
                    "did:key:zDnaeZ1MuKdxYsz4UM69cJz6cEJJVo9aS4GKTkGvz1a4f9Fiu#zDnaeZ1MuKdxYsz4UM69cJz6cEJJVo9aS4GKTkGvz1a4f9Fiu"
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
        holder.getAuthorizationRequest("openid4vp://?client_id=decentralized_identifier:did:key:zDnaeQpNYQD6h18VnagyA1Xbey9hFKA1j5cyhqPHGfaq9txmN&request_uri_method=post&request_uri=http://localhost:9002/request")
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