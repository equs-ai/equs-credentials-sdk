package com.bci

import com.bci.asdk.*
import com.bci.asdk.setJniLibPath
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals


class Oid4VciMetadataDiscovery {
    companion object {
        private lateinit var mockServer: MockWebServer

        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
            mockServer = MockWebServer()
            mockServer.start(9081)

            val dispatcher: Dispatcher = object : Dispatcher() {
                @Throws(InterruptedException::class)
                override fun dispatch(request: RecordedRequest): MockResponse {
                    val mockResponse = MockResponse().setHeader("content-type", "application/json")

                    return when (request.path) {
                        "/.well-known/openid-credential-issuer" -> mockResponse.setResponseCode(200)
                            .setBody(HolderVCITest.issuerMetadata.toString())

                        "/auth/.well-known/openid-configuration" -> mockResponse.setResponseCode(200)
                            .setBody(HolderVCITest.authServerMetadata.toString())

                        else -> mockResponse.setResponseCode(404)
                    }
                }
            }

            mockServer.dispatcher = dispatcher
        }

        @JvmStatic
        @AfterAll
        fun after_all() {
            mockServer.shutdown()
        }
    }

    @Test
    fun discoverIssuerMetadata() = runTest {
        val metadata = MetadataDiscovery(ReqwestHttpClient.insecure())
            .discoverIssuerMetadata(HolderVCITest.ISSUER_ENDPOINT)

        val actual = Json.parseToJsonElement(metadata)

        assertEquals(HolderVCITest.issuerMetadata, actual)
    }

    @Test
    fun discoverAuthorizationServerMetadata() = runTest {
        val metadata = MetadataDiscovery(ReqwestHttpClient.insecure())
                .discoverAuthServerMetadata(HolderVCITest.AUTH_SERVER_ENDPOINT)

        val actual = Json.parseToJsonElement(metadata)

        assertEquals(HolderVCITest.authServerMetadata, actual)
    }
}