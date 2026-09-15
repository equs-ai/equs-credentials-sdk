package com.equs

import com.equs.credentials.*
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
import com.equs.credentials.Kms as EqusSdkKms
import com.equs.credentials.Vault as EqusSdkVault


class HolderVCITest {
    companion object {
        const val SCOPE = "SD_JWT_cred"
        const val ACCESS_TOKEN =
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA"
        const val ISSUER_ENDPOINT = "http://localhost:9081"
        const val AUTH_SERVER_ENDPOINT = "$ISSUER_ENDPOINT/auth"
        const val SD_JWT_CRED =
            "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~"
        const val SD_JWT_CRED_DID_WEB_ISS =
            "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6d2ViOmxvY2FsaG9zdCUzQTkwODEiLCJpYXQiOjE3NTk3NTk4NDYsImV4cCI6MjA3NTI3ODIyNCwidmN0IjoiU0RfSldUX2NyZWQiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlbnBudENrWG5EQ25hRGs2Mkx4TnFQYzRDTWQzMmZiaGlWc1pWNUtwUFRHMmMiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19LCJfc2QiOlsiOGp0WjZXOTRzZ1RMVGN5Q0VqUDUxVnFCOWtqQ1ZtaTEwX0ZRUW9TYlVlVSIsIkFpbUlmd0JJRUN1OEJzWkdCd1RheDQ1MU9pMlFDemd3YUZQa2ZvNmowY1kiLCJYNEdKbmFxbXVOMFY5QzZrWWtRSUZjLThCRXFrY0IzX3l5bjk3c013RlVjIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.8zRC9-8ZEoXRk3Edsh2QOwFSaAcnOAALJfwqLOs06EnEt625_T1K1-a7ZFB4-yqyGuGcZDmGl-UgaII9ROOwUQ~WyJiZTdlZjk3ZDFhZTNjOGM0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJhYWQxMWQ1NTRlMDAzZWU1IiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI1OTQzYTlmZWViNTAwMTEyIiwiZG9iIiwiMDkvMDkvMTk4OSJd~"

        val issuerMetadata = Json.parseToJsonElement(
            """
                {
                    "credential_issuer": "$ISSUER_ENDPOINT",
                    "authorization_servers": ["$AUTH_SERVER_ENDPOINT"],
                    "credential_endpoint": "$ISSUER_ENDPOINT/credential",
                    "deferred_credential_endpoint": "$ISSUER_ENDPOINT/deferred_credential",
                    "notification_endpoint": "$ISSUER_ENDPOINT/notification",
                    "nonce_endpoint": "$ISSUER_ENDPOINT/nonce",
                    "batch_credential_issuance": {
                        "batch_size": 2
                    },
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
                            "credential_metadata": {
                                "claims": [
                                    {
                                        "path": ["given_name"],
                                        "display": [{ "name": "Name" }],
                                        "mandatory": true
                                    },
                                    {
                                        "path": ["family_name"],
                                        "display": [{ "name": "Surname" }],
                                        "mandatory": true
                                    },
                                    {
                                        "path": ["dob"],
                                        "display": [{ "name": "Date of birth" }],
                                        "mandatory": true
                                    }
                                ]
                            }
                        }
                    }
                }
            """
        )

        val authServerMetadata = Json.parseToJsonElement(
            """
                {
                    "issuer": "$AUTH_SERVER_ENDPOINT",
                    "authorization_endpoint": "$AUTH_SERVER_ENDPOINT",
                    "token_endpoint": "$AUTH_SERVER_ENDPOINT/token",
                    "introspection_endpoint": "$AUTH_SERVER_ENDPOINT/introspection",
                    "jwks_uri": "$AUTH_SERVER_ENDPOINT/jwks",
                    "grant_types_supported": ["authorization_code"],
                    "response_types_supported": ["code", "token"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["ES256"],
                    "pushed_authorization_request_endpoint": "$AUTH_SERVER_ENDPOINT/par/request",
                    "code_challenge_methods_supported": null,
                    "pre-authorized_grant_anonymous_access_supported": false,
                    "registration_endpoint": null,
                    "require_pushed_authorization_requests": false,
                    "response_modes_supported": [
                        "query",
                        "fragment"
                    ],
                    "revocation_endpoint": null,
                    "scopes_supported": null
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
                    "expires_in": 86400
                }
                """
        )

        val batchCredentialResponse = Json.parseToJsonElement(
            """
                {
                    "credentials": [{"credential":"$SD_JWT_CRED"}, {"credential":"$SD_JWT_CRED"}],
                    "notification_id": "1111"
                }
            """
        )

        val deferredCredentialResponse = Json.parseToJsonElement(
            """
                {
                    "transaction_id": "8xLOxBtZp8",
                    "interval": 300
                }
            """
        )

        val nonceResponse = Json.parseToJsonElement(
            """
                {
                    "c_nonce": "0GtZieAoAL_3Zafyn6TgCA"
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

                        "/.well-known/oauth-authorization-server/auth" -> mockResponse.setResponseCode(200)
                            .setBody(authServerMetadata.toString())

                        "/auth/par/request" -> mockResponse.setResponseCode(201)
                            .setBody(pushedAuthResponse.toString())

                        "/auth/token" -> mockResponse.setResponseCode(200)
                            .setBody(tokenResponse.toString())

                        "/credential" ->
                            mockResponse.setResponseCode(200)
                                .setBody(batchCredentialResponse.toString())

                        "/deferred_credential" ->
                            mockResponse.setResponseCode(202)
                                .setBody(deferredCredentialResponse.toString())

                        "/notification" -> {
                            mockResponse.setResponseCode(204)
                        }

                        "/nonce" -> mockResponse.setResponseCode(200)
                            .setBody(nonceResponse.toString())

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
    fun testRequestMultipleCredentials() = runTest {
        val inMemKms = InMemKms()
        val didAndKeyMetadata1 = createDidAndKeyMetadata(inMemKms)
        val didAndKeyMetadata2 = createDidAndKeyMetadata(inMemKms)

        val actual = buildHolder(inMemKms).requestCredential(
            ACCESS_TOKEN,
            "IDENTITY_SD_JWT",
            arrayListOf(didAndKeyMetadata1.keyMetadata, didAndKeyMetadata2.keyMetadata)
        )

        assertEquals(
            CredentialResultEnum.Immediate(
                credentials = arrayListOf(
                    Credential(format = VcFormat.SD_JWT_VC, payload = SD_JWT_CRED),
                    Credential(format = VcFormat.SD_JWT_VC, payload = SD_JWT_CRED)
                ),
                notificationId = "1111",
            ), actual.data
        )
    }

    @Test
    fun testRequestDeferredCredentials() = runTest {
        val inMemKms = InMemKms()

        val actual = buildHolder(inMemKms).requestDeferredCredential(
            ACCESS_TOKEN,
            "transaction_id",
        )

        assertEquals(
            CredentialResultEnum.Deferred(
                transactionId = "8xLOxBtZp8",
                interval = 300u,
            ), actual.data
        )
    }

    @Test
    fun testNotification() = runTest {
        val inMemKms = InMemKms()

        buildHolder(inMemKms).sendNotification(
            ACCESS_TOKEN,
            Notification(
                notificationId = "3fwe98js",
                event = NotificationEvent.CREDENTIAL_ACCEPTED,
                eventDescription = "Issued credential has been accepted"
            )
        )
    }

    @Test
    fun verifyCredentialExtra() = runTest {
        val inMemKms = InMemKms()
        val inMemVault = InMemVault()
        val holder = buildHolder(inMemKms, inMemVault)

        val credential = Credential(format = VcFormat.SD_JWT_VC, payload = SD_JWT_CRED_DID_WEB_ISS)

        holder.verifyCredentialExtra(credential)
    }

    @Test
    fun storeCredential() = runTest {
        val inMemKms = InMemKms()
        val inMemVault = InMemVault()

        val didAndKeyMetadata = createDidAndKeyMetadata(inMemKms)
        didAndKeyMetadata.keyMetadata.didUrl =
            "did:key:zDnaenpntCkXnDCnaDk62LxNqPc4CMd32fbhiVsZV5KpPTG2c#zDnaenpntCkXnDCnaDk62LxNqPc4CMd32fbhiVsZV5KpPTG2c"

        val credential = Credential(format = VcFormat.SD_JWT_VC, payload = SD_JWT_CRED)
        val metadata = resolveMetadata(credential, didAndKeyMetadata.keyMetadata)

        val credentialId = buildHolder(inMemKms, inMemVault).storeCredential(credential, metadata)

        val entry = inMemVault.getCredential(credentialId)

        assertEquals(credential, entry?.credential)
    }

    private suspend fun buildHolder(kms: EqusSdkKms = InMemKms(), vault: EqusSdkVault = InMemVault()) =
        Oid4vciHolderBuilder(
            kms,
            vault,
            "client_id",
            IssuerDiscoveryEnum.Url(ISSUER_ENDPOINT),
            ReqwestHttpClient.insecure(),
            ProofOfPossessionMetadataBuilder()
                .withNotBefore(ProofOfPossessionNotBefore.Leeway(300))
                .withLifetime(300)
                .build(),
            arrayListOf(CredentialExtraVerification.CREDENTIAL_ISSUER_IDENTIFIER)
        ).build()
}