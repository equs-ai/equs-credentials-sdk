import com.bci.HolderVCITest.Companion.ISSUER_ENDPOINT
import com.bci.HolderVCITest.Companion.SD_JWT_CRED
import com.bci.MockNonceHandler
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import com.bci.asdk.setJniLibPath
import com.bci.asdk.*
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

import kotlinx.serialization.json.Json
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.RecordedRequest
import java.util.concurrent.TimeUnit
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

val presentationDefinitionJson = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()
val presentationDefinitionJsonFake = Json.parseToJsonElement(
    """{"presentation_definition": {"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential_1"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]}}"""
).toString()

//
val clientMetadata = Json.parseToJsonElement("""{"vp_formats":{"dc+sd-jwt":{"alg":["EdDSA","ES256"]}}}""").toString()
const val CLIENT_ID = "wallet-dev"
const val REQUEST_URI =
    "openid4vp://?client_id=did%3Akey%3AzDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7&request_uri=http%3A%2F%2Flocalhost%3A9001"
val authRequest = AuthorizationRequest(
    clientId = "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadata,
    presentationDefinition = presentationDefinitionJson,
    responseType = "vp_token",
    responseMode = "direct_post",
    responseUri = "http://localhost:9001/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c"
)
val authRequestFake = AuthorizationRequest(
    clientId = "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
    clientMetadata = clientMetadata,
    presentationDefinition = presentationDefinitionJsonFake,
    responseType = "vp_token",
    responseMode = "direct_post",
    responseUri = "http://localhost:9001/response",
    nonce = "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
    state = "eea7b48e-1866-41b4-beae-03b95d41670c"
)
const val AUTH_REQUEST_JWT =
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVlVEc4OHdwUGhNenVEUnZMUlRUeU5NeUppcDVlNlRMbXNqeXZQaVNZVUZrNyN6RG5hZWVURzg4d3BQaE16dURSdkxSVFR5Tk15SmlwNWU2VExtc2p5dlBpU1lVRms3IiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6ImVlYTdiNDhlLTE4NjYtNDFiNC1iZWFlLTAzYjk1ZDQxNjcwYyIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiWXp0QU5nbFJkbVA0Q2h4c3JjUzhVY0dZb1BXd2tnaVVJbWtCclFtZ1drVSIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzIjp7ImRjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiJdfX19LCJjbGllbnRfaWQiOiJkaWQ6a2V5OnpEbmFlZVRHODh3cFBoTXp1RFJ2TFJUVHlOTXlKaXA1ZTZUTG1zanl2UGlTWVVGazciLCJjbGllbnRfaWRfc2NoZW1lIjoiZGlkIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIxYjlkNmJjZC1iYmZkLTRiMmQtOWI1ZC1hYjhkZmJiZDRiZWQiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJJZGVudGl0eS0xIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmN0Il0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYW4gaWRlbnRpdHkiLCJmb3JtYXQiOnsiZGMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdfX19XX0sInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9yZXNwb25zZSJ9.dV0RXxaAJTjnAqGNuPUzMor93gsEkXpoqVRj9-J638lV7mkka4ixXZJ3VIQ0Iqhb7GvCIr0D-7_bWp_xnIYAVA"
const val VC =
    "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~"


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
                    data.v1.forEach { reason ->
                        if (reason.paths != listOf("$.vct") || reason.type != "const") {
                            throw IllegalStateException(
                                "Unexpected reason for key: $key\nExpected paths = [\"$.vct\"], type = \"const\"\nBut got: paths = ${reason.paths}, type = ${reason.type}"
                            )
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
            "error=access_denied&error_description=consent+to+share+the+presentation+is+not+given&state=eea7b48e-1866-41b4-beae-03b95d41670c",
            request
        )
    }
}