package com.equs

import com.equs.credentials.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.Base64
import kotlin.test.assertEquals
import com.equs.credentials.Kms as EqusSdkKms
import com.equs.credentials.Vault as EqusSdkVault


class HolderVCITest {
    companion object {
        const val SCOPE = "SD_JWT_cred"
        val ACCESS_TOKEN = Fixtures.token("accessToken")
        const val ISSUER_ENDPOINT = "http://localhost:9081"
        const val AUTH_SERVER_ENDPOINT = "$ISSUER_ENDPOINT/auth"
        val SD_JWT_CRED = Fixtures.token("sdJwtCreds")

        // `iss` here must be `did:web:localhost%3A9081` -- the `did:web` derived from
        // `ISSUER_ENDPOINT` -- for `verifyCredentialExtra`'s `CredentialIssuerIdentifier` check to
        // match. `Holder::verify_credential_issuer_identifier` reads this via
        // `SdJwtAPI::extract_issuer_identifier`, which calls `ssi::claims::jws::decode_unverified`
        // (see `src/vc/formats/sd_jwt_vc.rs`) -- it never checks the signature, so no bundle key or
        // resolvable `did:web` document is needed; a freshly signed, self-contained JWS with the
        // right `iss` claim is sufficient and keeps this a real (if unverified-here) SD-JWT VC
        // rather than a hand-typed string.
        lateinit var SD_JWT_CRED_DID_WEB_ISS: String

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

            runBlocking {
                val kms = InMemKms()
                val kid = kms.create(KeyType.P256)
                val keyHandle = kms.get(kid)

                val header = buildJsonObject {
                    put("typ", "dc+sd-jwt")
                    put("alg", "ES256")
                }
                val payload = buildJsonObject {
                    put("iss", "did:web:localhost%3A9081")
                    put("iat", 1759759846L)
                    put("exp", 2075278224L)
                    put("vct", "SD_JWT_cred")
                    put("_sd_alg", "sha-256")
                }
                val signingInput =
                    "${Base64.getUrlEncoder().withoutPadding().encodeToString(header.toString().toByteArray())}." +
                        Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toString().toByteArray())
                val signature = keyHandle.inner.sign(signingInput.toByteArray())
                SD_JWT_CRED_DID_WEB_ISS =
                    "$signingInput.${Base64.getUrlEncoder().withoutPadding().encodeToString(signature)}"
            }

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
        val subject = Fixtures.claim(SD_JWT_CRED, "sub")!!
        didAndKeyMetadata.keyMetadata.didUrl = "$subject#${subject.removePrefix("did:key:")}"

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