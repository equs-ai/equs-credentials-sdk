package com.bci

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import com.bci.asdk.setJniLibPath
import com.bci.asdk.*
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals


class HolderVCITest {
    companion object {
        const val SCOPE = "SD_JWT_cred"
        const val ACCESS_TOKEN =
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA"
        const val ISSUER_ENDPOINT = "http://localhost:9081"
        const val SD_JWT_CRED =
            "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~"

        val issuerMetadata = Json.parseToJsonElement(
            """
                {
                  "credential_issuer": "$ISSUER_ENDPOINT",
                  "authorization_servers": ["$ISSUER_ENDPOINT/auth"],
                  "credential_endpoint": "$ISSUER_ENDPOINT/credential",
                  "credential_configurations_supported": {
                    "IDENTITY_SD_JWT": {
                      "format": "dc+sd-jwt",
                      "scope": "$SCOPE",
                      "cryptographic_binding_methods_supported": ["jwk"],
                      "credential_signing_alg_values_supported": ["ES256"],
                      "proof_types_supported": {
                        "jwt": {
                          "proof_signing_alg_values_supported":  ["ES256"]
                        }
                      },
                      "vct": "SD_JWT_cred",
                      "claims": {
                        "given_name": {
                          "display": [{ "name": "Name" }],
                          "mandatory": true,
                          "value_type": "string"
                        },
                        "family_name": {
                          "display": [{ "name": "Surname" }],
                          "mandatory": true,
                          "value_type": "string"
                        },
                        "dob": {
                          "display": [{ "name": "Date of birth" }],
                          "mandatory": true,
                          "value_type": "number"
                        }
                      }  
                    }
                  }
                }
            """
        )

        val authServerMetadata = Json.parseToJsonElement(
            """
                {
                  "issuer": "$ISSUER_ENDPOINT/auth",
                  "authorization_endpoint": "$ISSUER_ENDPOINT/auth",
                  "token_endpoint": "$ISSUER_ENDPOINT/auth/token",
                  "introspection_endpoint": "$ISSUER_ENDPOINT/auth/introspection",
                  "jwks_uri": "$ISSUER_ENDPOINT/auth/jwks",
                  "grant_types_supported": ["authorization_code"],
                  "response_types_supported": ["code", "token"],
                  "subject_types_supported": ["public"],
                  "id_token_signing_alg_values_supported": ["ES256"],
                  "pushed_authorization_request_endpoint": "$ISSUER_ENDPOINT/auth/par/request"
                }
            """
        )

        val pushedAuthResponse = Json.parseToJsonElement(
            """
                {
                  "request_uri": "urn:ietf:params:oauth:request_uri:code",
                  "expires_in": 86400
                }
               """
        )

        val tokenResponse = Json.parseToJsonElement(
            """
                {
                  "access_token": "$ACCESS_TOKEN", 
                  "token_type": "bearer",
                  "scope": "SD_JWT_cred",
                  "c_nonce": "tZignsnFbp",
                  "expires_in": 86400
                }
              """
        )

        val credentialResponse = Json.parseToJsonElement(
            """
                {
                  "format": "dc+sd-jwt",
                  "credential": "$SD_JWT_CRED",
                  "c_nonce": "0GtZieAoAL_3Zafyn6TgCA",
                  "c_nonce_expires_in": 86400,
                  "notification_id": "1111"
                }
            """
        )

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
                            .setBody(issuerMetadata.toString())

                        "/auth/.well-known/openid-configuration" -> mockResponse.setResponseCode(200)
                            .setBody(authServerMetadata.toString())

                        "/auth/par/request" -> mockResponse.setResponseCode(201).setBody(pushedAuthResponse.toString())
                        "/auth/token" -> mockResponse.setResponseCode(200).setBody(tokenResponse.toString())
                        "/credential" -> mockResponse.setResponseCode(200).setBody(credentialResponse.toString())
                        else -> mockResponse.setResponseCode(404)
                    }
                }
            }

            mockServer.dispatcher = dispatcher;
        }

        @JvmStatic
        @AfterAll
        fun after_all() {
            mockServer.shutdown()
        }
    }

    @Test
    fun testGetIssuerMetadata() = runTest {
        val actual = buildHolder().getIssuerMetadata()

        assertEquals(issuerMetadata, Json.parseToJsonElement(actual))
    }

    @Test
    fun testAuthzCodeFlowWithScope() = runTest {
        val expected = TokenResponse(
            accessToken = ACCESS_TOKEN,
            tokenType = "bearer",
            expiresIn = 86400U,
            refreshToken = null,
            scopes = arrayListOf("SD_JWT_cred"),
            cNonce = "tZignsnFbp",
            cNonceExpiresIn = null,
            authorizationDetails = null,
        )

        val authCodeCallback = object : AuthCodeCallback {
            override suspend fun authenticate(url: String): String {
                assertEquals(
                    url,
                    "http://localhost:9081/auth?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Acode&client_id=client_id"
                )

                return "code"
            }
        }

        val actual = buildHolder().authzCodeFlowWithScope(SCOPE, authCodeCallback)

        assertEquals(expected, actual)
    }

    @Test
    fun testGetAccessTokenUsingOfferWithPreAuthCode() = runTest {
        val expected = TokenResponse(
            accessToken = ACCESS_TOKEN,
            tokenType = "bearer",
            expiresIn = 86400U,
            refreshToken = null,
            scopes = arrayListOf("SD_JWT_cred"),
            cNonce = "tZignsnFbp",
            cNonceExpiresIn = null,
            authorizationDetails = null,
        )

        val credOffer = Json.parseToJsonElement(
            """
                {
                  "credential_issuer": "$ISSUER_ENDPOINT",
                  "credential_configuration_ids": ["SD_JWT_cred"],
                  "grants": {
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                      "pre-authorized_code": "code",
                      "tx_code": null,
                      "interval": null,
                      "authorization_server": "$ISSUER_ENDPOINT/auth"
                    }
                  }
                }
            """
        ).toString()

        val authCodeCallback = object : AuthCallback {
            override suspend fun authenticate(authzFlow: AuthzFlow): String {
                assertEquals(authzFlow, AuthzFlow.Preauthorized)

                return "txCode"
            }
        }

        val actual = buildHolder().getAccessToken(credOffer, authCodeCallback)

        assertEquals(expected, actual)
    }

    @Test
    fun testRequestCredential() = runTest {
        val inMemKms = InMemKms();
        val didAndKeyMetadata = createDidAndKeyMetadata(inMemKms)

        val nonce = NonceData("KB50VOm9I-kPLT9mAACV8g", 1728732136, 86400)

        val actual = buildHolder(inMemKms).requestCredential(ACCESS_TOKEN, "IDENTITY_SD_JWT", nonce, didAndKeyMetadata.keyMetadata)

        assertEquals(CredentialResultEnum.Immediate(
            credential = Credential(format = VcFormat.SD_JWT_VC, payload = SD_JWT_CRED),
            notificationId = "1111",
        ), actual.data)
        assertEquals("0GtZieAoAL_3Zafyn6TgCA", actual.nonceData?.value)
        assertEquals( 86400, actual.nonceData?.expiresIn)
    }

    @Test
    fun storeCredential() = runTest {
        val inMemKms = InMemKms()
        val inMemVault = InMemVault()

        val didAndKeyMetadata = createDidAndKeyMetadata(inMemKms)
        val credential = Credential(format = VcFormat.SD_JWT_VC, payload = SD_JWT_CRED)
        val metadata = resolveMetadata(credential, didAndKeyMetadata.keyMetadata)

        val credentialId = buildHolder(inMemKms, inMemVault).storeCredential(credential, metadata)

        val entry = inMemVault.getCredential(credentialId)

        assertEquals(credential, entry?.credential)
    }

    private suspend fun buildHolder(kms: InMemKms = InMemKms(), vault: InMemVault = InMemVault()) =
        Oid4vciHolderBuilder(kms, vault, "client_id", IssuerDiscoveryEnum.Url(ISSUER_ENDPOINT)).build()
}