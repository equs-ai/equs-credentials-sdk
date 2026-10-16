package com.equs

import com.equs.credentials.*
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Http {
    companion object {
        lateinit var mockServer: MockWebServer

        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()

            mockServer = MockWebServer()
            mockServer.start(9000)
        }

        @JvmStatic
        @AfterAll
        fun after_all() {
            mockServer.shutdown()
        }
    }

    @Test
    fun asyncCall() = runTest {
        val client = MockHttpClient()
        val request = HttpRequest(
            url = "http://localhost:1512",
            method = HttpMethod.GET,
            headers = mapOf(
                "Content-Type" to "application/json",
            ),
            body = "{\"message\": \"are you ok?\"}"
        )
        val response = client.asyncCall(request)

        assertEquals("{\"message\": \"ok\"}", response.body)
    }

    @Test
    fun reqwestInsecureAsyncCall() = runTest {
        mockServer.enqueue(
            MockResponse().setResponseCode(200).setBody("{\"message\": \"ok\"}")
                .setHeader("content-type", "application/json")
        )
        val client = ReqwestHttpClient.insecure()
        val request = HttpRequest(
            url = "http://localhost:9000",
            method = HttpMethod.GET,
            headers = mapOf(
                "accept" to "application/json",
            ),
            body = null
        )
        val response = client.asyncCall(request)

        assertEquals("{\"message\": \"ok\"}", response.body)
    }

    @Test
    fun reqwestInsecureAsyncCallShouldThrowErrorOnSecureUrl() = runTest {
        val client = ReqwestHttpClient()
        val request = HttpRequest(
            url = "http://localhost:9000/get",
            method = HttpMethod.GET,
            headers = mapOf(
                "accept" to "application/json",
            ),
            body = null
        )

        val exception = assertFailsWith<Exception.HttpAsyncCall> {
            client.asyncCall(request)
        }
        assertEquals(
            "v1=HTTP error: builder error for url (http://localhost:9000/get)",
            exception.message
        )
    }

    fun reqwestSecureAsyncCall() {
        TODO()
    }
}


class MockHttpClient : HttpClient {

    override suspend fun asyncCall(request: HttpRequest): HttpResponse {
        assertEquals(request.body, "{\"message\": \"are you ok?\"}")
        assertEquals(request.method, HttpMethod.GET)
        return HttpResponse(
            statusCode = 200.toUShort(),
            headers = mapOf(
                "Content-Type" to "application/json",
            ),
            body = "{\"message\": \"ok\"}"
        )
    }

}