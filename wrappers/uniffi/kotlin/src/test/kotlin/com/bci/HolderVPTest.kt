import com.bci.MockNonceHandler
import com.bci.asdk.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNull

val presentationDefinitionJson = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()
val presentationDefinitionJsonFake = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential_1"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()

val clientMetadata = Json.parseToJsonElement("""{"vp_formats":{"dc+sd-jwt":{"alg":["EdDSA","ES256"]}}}""").toString()
val clientMetadataWithDirectPostJwt = Json.parseToJsonElement("""{"vp_formats":{"dc+sd-jwt":{"alg":["EdDSA","ES256"]}},"jwks":{"keys":[{"kid":"ecdsa-kid","kty":"EC","crv":"P-256","x":"SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM","y":"rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY","alg":"ES256"}]}}""").toString()
const val CLIENT_ID = "wallet-dev"
const val REQUEST_URI =
    "openid4vp://?client_id=did%3Akey%3AzDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri=http%3A%2F%2Flocalhost%3A9001"
const val REQUEST_URI_FOR_TRANSACTION_DATA =
    "openid4vp://?client_id=did%3Akey%3AzDnaeXHgwoWiRJM6LVVSgu7kNJKsS3L4rsVhTBPRSSj9eg5VZ&request_uri=http%3A%2F%2Flocalhost%3A9005"
val authRequest = AuthorizationRequest(
    clientId = "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadata,
    presentationDefinition = presentationDefinitionJson,
    responseType = "vp_token",
    responseMode = "direct_post",
    responseUri = "http://localhost:9001/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c",
    transactionData = null,
)

val authRequestWithDirectPostJwt = AuthorizationRequest(
    clientId = "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadataWithDirectPostJwt,
    presentationDefinition = presentationDefinitionJson,
    responseType = "vp_token",
    responseMode = "direct_post.jwt",
    responseUri = "http://localhost:9003/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c",
    transactionData = null,
)
val authRequestFake = AuthorizationRequest(
    clientId = "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadata,
    presentationDefinition = presentationDefinitionJsonFake,
    responseType = "vp_token",
    responseMode = "direct_post",
    responseUri = "http://localhost:9001/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c",
    transactionData = null,
)
const val AUTH_REQUEST_JWT =
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVlVEc4OHdwUGhNenVEUnZMUlRUeU5NeUppcDVlNlRMbXNqeXZQaVNZVUZrNyN6RG5hZWVURzg4d3BQaE16dURSdkxSVFR5Tk15SmlwNWU2VExtc2p5dlBpU1lVRms3IiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6ImVlYTdiNDhlLTE4NjYtNDFiNC1iZWFlLTAzYjk1ZDQxNjcwYyIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiWXp0QU5nbFJkbVA0Q2h4c3JjUzhVY0dZb1BXd2tnaVVJbWtCclFtZ1drVSIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzIjp7ImRjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiJdfX19LCJjbGllbnRfaWQiOiJkaWQ6a2V5OnpEbmFlZVRHODh3cFBoTXp1RFJ2TFJUVHlOTXlKaXA1ZTZUTG1zanl2UGlTWVVGazciLCJjbGllbnRfaWRfc2NoZW1lIjoiZGlkIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIxYjlkNmJjZC1iYmZkLTRiMmQtOWI1ZC1hYjhkZmJiZDRiZWQiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJJZGVudGl0eS0xIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmN0Il0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYW4gaWRlbnRpdHkiLCJmb3JtYXQiOnsiZGMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdfX19XX0sInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9yZXNwb25zZSJ9.dV0RXxaAJTjnAqGNuPUzMor93gsEkXpoqVRj9-J638lV7mkka4ixXZJ3VIQ0Iqhb7GvCIr0D-7_bWp_xnIYAVA"

const val AUTH_REQUEST_JWT_WITH_TRANSACTION_DATA =
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVYSGd3b1dpUkpNNkxWVlNndTdrTkpLc1MzTDRyc1ZoVEJQUlNTajllZzVWWiN6RG5hZVhIZ3dvV2lSSk02TFZWU2d1N2tOSktzUzNMNHJzVmhUQlBSU1NqOWVnNVZaIiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4gaWRfdG9rZW4iLCJzY29wZSI6Im9wZW5pZCIsImlkX3Rva2VuX3R5cGUiOiJzdWJqZWN0X3NpZ25lZF9pZF90b2tlbiIsInRyYW5zYWN0aW9uX2RhdGEiOlsiZXlKMGVYQmxJam9pZEhsd1pURWlMQ0pqY21Wa1pXNTBhV0ZzWDJsa2N5STZXeUpKWkdWdWRHbDBlUzB4SWwwc0luUnlZVzV6WVdOMGFXOXVYMlJoZEdGZmFHRnphR1Z6WDJGc1p5STZXeUp6YUdFdE1qVTJJbDE5Il0sInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6IkNOZXhCWnFQcGxmRF9QV2pnWTZFT2ZpWGpJLWF1TWNCODA5SVZBUVpSUjQiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJkYytzZC1qd3QiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiXX0sImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5Il19fSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDprZXkiXSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJlbmMiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtEQlhjOU5Ubnk6UDI1NjoiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImVvWDdheXliZkZtSldpcjNoNzJYVi1LVy1BRk9oY3gyUjlfUVA2UjBCZEkiLCJ5IjoiSUtDSUo3MGoyQjEzNGU4aEZYM0ZhMGQxeWllQTNXMmZHck9JNmlpbHpFbyJ9XX0sImVuY3J5cHRlZF9yZXNwb25zZV9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMjU2R0NNIl0sImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIn0sImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVYSGd3b1dpUkpNNkxWVlNndTdrTkpLc1MzTDRyc1ZoVEJQUlNTajllZzVWWiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiZjY0ZWRjOTktMmI3OS00NWNlLWFkMzYtNWUzNDZlYmZjNmVjIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsXzEifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuZW1haWwud29yayJdLCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC51c2VybmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuY291bnRyeSJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiVVMifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuYWdlX292ZXJfMTgiXSwiZmlsdGVyIjp7InR5cGUiOiJib29sZWFuIiwiY29uc3QiOnRydWV9LCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfV19LCJuYW1lIjoiSWRlbnRpdHkgVkMiLCJwdXJwb3NlIjoiV2Ugd2FudCBhbiBpZGVudGl0eSIsImZvcm1hdCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl19fX0seyJpZCI6InJlc2lkZW50LWNhcmQiLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC50eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoiYXJyYXkiLCJjb250YWlucyI6eyJjb25zdCI6IlBlcm1hbmVudFJlc2lkZW50Q2FyZCJ9fSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYSByZXNpZGVudCBjYXJkIiwiZm9ybWF0Ijp7ImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5Il19fX0seyJpZCI6ImFsdW1uaS1jYXJkIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJBbHVtbmlDcmVkZW50aWFsIn19LCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfV19LCJuYW1lIjoiVW5pdmVyc2l0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGEgZGlwbG9tYSIsImZvcm1hdCI6eyJsZHBfdmMiOnsicHJvb2ZfdHlwZSI6WyJFY2RzYVJkZmMyMDE5IiwiRWREc2FSZGZjMjAyMiJdfX19XSwibmFtZSI6IkV4YW1wbGUgd2l0aCBzZWxlY3RpdmUgZGlzY2xvc3VyZSJ9LCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwOTgvcHJlc2VudCJ9.Zce8XVbP9Zf1tYIXupYDHiL50a7udE0U734Nwu4iTCjZL-Wz5ZMWIj6jIJS4plfDC2VlsoiIpa1hMHzWWKNU9A"
const val VC =
    "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~"

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
                    "did:key:zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM#zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM"
                val credential = Credential(format = VcFormat.SD_JWT_VC, payload = VC)
                val metadata = resolveMetadata(credential, didAndKeyMetadata.keyMetadata)

                holder = Oid4vpHolderBuilder(inMemKms, inMemVault, CLIENT_ID, ReqwestHttpClient.insecure(),
                    MockNonceHandler("some_nonce")).build()

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
                .setBody(AUTH_REQUEST_JWT_WITH_TRANSACTION_DATA)
                .setHeader("content-type", "application/oauth-authz-req+jwt")
        )

        val authorizationRequest = holder.getAuthorizationRequest(REQUEST_URI_FOR_TRANSACTION_DATA)

        val transactionData = listOf(TransactionDataItem(
            type = "type1",
            credentialIds = listOf("Identity-1"),
            transactionDataHashesAlg = listOf("sha-256")
        ))
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
        holder.getAuthorizationRequest("openid4vp://?client_id=did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri_method=post&request_uri=http://localhost:9002/request")
        val request = mockServer.takeRequest()
        val body = request.body.readUtf8();
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

        val redirectUri = holder.presentCredentialsAuto(
            authRequest,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null)
        )
        assertNull(redirectUri)
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
        val redirectUri = holder.presentCredentialsAuto(
            authRequestWithDirectPostJwt,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null)
        )
        val request = customMockServer.takeRequest()
        assert(request.body.readUtf8().startsWith("response=ey"))
        assertNull(redirectUri)
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
        val credentials = credentialsMapping.map { (key, findVCsResult) ->
            val data = findVCsResult.data
            when (data) {
                is CredentialsSearchResult.Credentials -> {
                    val credential = data.v1.firstOrNull()
                        ?: throw IllegalStateException("No credentials found for key: $key")
                    key to credential
                }

                is CredentialsSearchResult.Reasons -> {
                    throw IllegalStateException("Find vcs for presentation returned reasons of failure: $data")
                }
            }
        }.toMap()

        holder.presentCredentials(
            authRequest,
            credentials,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null)
        )
    }

    @Test
    fun findVcsForPresentationReturnsCredentials() = runTest {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("")
                .setHeader("content-type", "text/plain")
        )

        val credentialsMapping = holder.findVcsForPresentation(authRequest)
        credentialsMapping.map { (key, findVCsResult) ->
            val data = findVCsResult.data
            when (data) {
                is CredentialsSearchResult.Credentials -> {
                    val credential = data.v1.firstOrNull()
                        ?: throw IllegalStateException("No credentials found for key: $key")
                    key to credential
                }

                is CredentialsSearchResult.Reasons -> {
                    throw IllegalStateException("Find vcs for presentation returned reasons of failure: $data")
                }
            }
        }

    }

    @Test
    fun findVcsForPresentationReturnsReasonsOfFailure() = runTest {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("")
                .setHeader("content-type", "text/plain")
        )

        val credentialsMapping = holder.findVcsForPresentation(authRequestFake)

        credentialsMapping.map { (key, findVCsResult) ->
            val data = findVCsResult.data
            when (data) {
                is CredentialsSearchResult.Credentials -> {
                    throw IllegalStateException("Find vcs for presentation returned credentials instead of reasons of failure: $key -> $data")
                }

                is CredentialsSearchResult.Reasons -> {
                    if (data.v1.size != 1) {
                        throw IllegalStateException("Expected exactly 1 reason group for key: $key, but got ${data.v1.size}")
                    }

                    val reasonGroup = data.v1[0]
                    if (reasonGroup.size != 1) {
                        throw IllegalStateException("Expected exactly 1 reason in the group for key: $key, but got ${reasonGroup.size}")
                    }

                    val reason = reasonGroup[0]
                    if (reason.paths != listOf("$.vct") || reason.type != "const") {
                        throw IllegalStateException(
                            "Unexpected reason for key: $key\n" +
                            "Expected paths = [\"$.vct\"], type = \"const\"\n" +
                            "But got: paths = ${reason.paths}, type = ${reason.type}"
                        )
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
            "error=access_denied&error_description=consent+to+share+the+presentation+is+not+given&state=eea7b48e-1866-41b4-beae-03b95d41670c",
            request
        )
    }
}