package com.equs

import com.equs.credentials.*
import com.equs.credentials.setJniLibPath
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals

const val AuthServerMetadata =
    "{\"issuer\":\"http://localhost:9001/auth\",\"authorization_endpoint\":\"http://localhost:9001/auth\",\"token_endpoint\":\"http://localhost:9001/auth/token\",\"introspection_endpoint\":\"http://localhost:9001/auth/introspection\",\"jwks_uri\":\"http://localhost:9001/auth/jwks\",\"grant_types_supported\":[\"authorization_code\"],\"response_types_supported\":[\"code\",\"token\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"ES256\"],\"pushed_authorization_request_endpoint\":\"http://localhost:9001/auth/par/request\"}"

const val CredOfferWithPreAuthGrant =
    "{\"credential_issuer\":\"http://localhost:9001\",\"credential_configuration_ids\":[\"IDENTITY_SD_JWT\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"code\",\"authorization_server\":\"http://localhost:9001/auth\"}},\"extra_field\":\"extra_value\"}"

class CredentialOfferResolverTest {

    companion object {
        lateinit var mockServer: MockWebServer

        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()

            mockServer = MockWebServer()
            mockServer.start(9001)
        }

        @JvmStatic
        @AfterAll
        fun after_all() {
            mockServer.shutdown()
        }
    }

    @Test
    fun resolveOfferByReferenceWithPreAuthorizedCodeGrant() = runTest {

        mockServer.enqueue(
            MockResponse().setResponseCode(200).setBody(CredOfferWithPreAuthGrant)
                .setHeader("content-type", "application/json")
        )
        mockServer.enqueue(
            MockResponse().setResponseCode(200).setBody(AuthServerMetadata)
        )

        val resolver = CredentialOfferResolver(ReqwestHttpClient.insecure())

        val resolvedOffer =
            resolver.resolve("openid-credential-offer://?credential_offer_uri=http://localhost:9001/credential_offer")

        assertEquals(CredOfferWithPreAuthGrant, resolvedOffer)
    }

    @Test
    fun resolveOfferByValueWithPreAuthorizedCodeGrant() = runTest {

        val resolver = CredentialOfferResolver(ReqwestHttpClient.insecure())

        val resolvedOffer =
            resolver.resolve("openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9001%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22authorization_server%22:%22http://localhost:9001/auth%22}},%22extra_field%22:%22extra_value%22}")

        assertEquals(CredOfferWithPreAuthGrant, resolvedOffer)
    }
}


