import com.equs.Fixtures
import com.equs.MockNonceHandler
import com.equs.credentials.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
val VERIFIER_CLIENT_ID: String by lazy { "decentralized_identifier:${fixtureDidKey(FixtureKey.VERIFIER)}" }
val ENCODED_VERIFIER_CLIENT_ID: String by lazy { VERIFIER_CLIENT_ID.replace(":", "%3A") }
const val CLIENT_ID = "did:key:zDnaekPT1E2PbmXnD7ZHu4My3jCykZUyCVv9FSN5dR6jQrGDo"
val REQUEST_URI: String by lazy {
    "openid4vp://?client_id=$ENCODED_VERIFIER_CLIENT_ID&request_uri=http%3A%2F%2Flocalhost%3A9001"
}
val REQUEST_URI_FOR_TRANSACTION_DATA: String by lazy {
    "openid4vp://?client_id=$ENCODED_VERIFIER_CLIENT_ID&request_uri=http%3A%2F%2Flocalhost%3A9005"
}
val authRequest: AuthorizationRequest by lazy {
    AuthorizationRequest(
        clientId = VERIFIER_CLIENT_ID,
        clientMetadata = clientMetadata,
        presentationDefinition = presentationDefinitionJson,
        responseType = "vp_token",
        responseMode = "direct_post",
        responseUri = "http://localhost:9001/response",
        nonce = "F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M",
        state = "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
        transactionData = listOf(
            TransactionDataItem(
                credentialIds = listOf("Identity-1"),
                transactionDataHashesAlg = listOf(HashAlgorithm.SHA256),
                content = TransactionDataItemTypeContent.Unknown(type = "type1", data = "{}"),
            )
        ),
        expectedOrigins = null,
    )
}

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
val TRANSACTION_DATA: String =
    Fixtures.base64Url("""{"type":"type1","credential_ids":["Identity-1"],"transaction_data_hashes_alg":["sha-256"]}""")
val AUTH_REQUEST_JWT: String by lazy {
    fixtureJws(
        """{"alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.VERIFIER)}","typ":"application/oauth-authz-req+jwt"}""",
        """{"response_type":"vp_token","state":"1d8b0d93-86e8-4135-87d4-524bb0500bf3","transaction_data":["$TRANSACTION_DATA"],"response_mode":"direct_post","nonce":"F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M","client_metadata":{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["EdDSA","ES256"],"kb-jwt_alg_values":["EdDSA","ES256"]}},"jwks":{"keys":[{"use":"enc","alg":"ES256","kid":"5QsdgXUGuH:P256:","kty":"EC","crv":"P-256","x":"Cb_uJhiPN7H9KXdQN4PQN0uWC6LmEwIz4j03wX1rBAw","y":"yEZ8-uX5hGhCuN9NrIz4ShNH0T1y4fQts5siiCH0Q7w"}]},"encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"],"subject_syntax_types_supported":["did:key"]},"client_id":"$VERIFIER_CLIENT_ID","presentation_definition":{"id":"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed","input_descriptors":[{"id":"Identity-1","constraints":{"fields":[{"path":["$.vct"],"filter":{"type":"string","const":"https://credentials.example.com/identity_credential"},"predicate":null,"intent_to_retain":false},{"path":["$.name"],"optional":true,"predicate":null,"intent_to_retain":false}]},"name":"Identity VC","purpose":"We want an identity","format":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","EdDSA"],"kb-jwt_alg_values":["ES256","EdDSA"]}}}]},"response_uri":"http://localhost:9001/response"}""",
        FixtureKey.VERIFIER,
    )
}
val VC: String by lazy {
    fixtureSdJwt(
        """{"typ":"dc+sd-jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
        """{"sub":"${fixtureDidKey(FixtureKey.HOLDER)}","vct":"https://credentials.example.com/identity_credential","iat":1760606075,"_sd_alg":"sha-256","iss":"${fixtureDidKey(FixtureKey.ISSUER)}","exp":2075966075,"nbf":1760606075,"cnf":{"jwk":${fixturePublicJwk(FixtureKey.HOLDER)}}}""",
        listOf("""["SknIWuK1_VVXSB2EoYuRRw", "name", "John"]"""),
        FixtureKey.ISSUER,
    )
}
val STATUS_LIST: String by lazy {
    fixtureJws(
        """{"typ":"statuslist+jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
        """{"status_list":{"lst":"eNqbwMwABgAEnQCU","bits":2},"sub":"http://localhost:9001/status_list","iat":1763025623,"_sd_alg":"sha-256"}""",
        FixtureKey.ISSUER,
    ) + "~"
}
val VC_WITH_STATUS: String by lazy {
    fixtureSdJwt(
        """{"typ":"dc+sd-jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
        """{"address":"221B Baker Street","iat":1753054448,"date":"09/09/1989","sub":"${fixtureDidKey(FixtureKey.HOLDER)}","vct":"https://credentials.example.com/identity_credential","status":{"status_list":{"uri":"http://localhost:9001/status_list","idx":1}},"_sd_alg":"sha-256","iss":"${fixtureDidKey(FixtureKey.ISSUER)}","exp":1753055048,"nbf":1753054448,"cnf":{"jwk":${fixturePublicJwk(FixtureKey.HOLDER)}}}""",
        listOf(
            """["uxLNTemWQkc1VO6LgsArlQ", "name", "John"]""",
            """["2CBudCWI5EImahgzdcU1Vw", "surname", "Doe"]""",
        ),
        FixtureKey.ISSUER,
    )
}

val DELEGATE_JWK: String by lazy { fixturePublicJwk(FixtureKey.VERIFIER) }
/** An identity credential (`name`, `surname`) issued to the holder [did] and bound to its key [jwk]. */
fun delegationVc(did: String, jwk: String): String = issuedSdJwt(
    did, jwk, "https://credentials.example.com/identity_credential",
    listOf("""["SknIWuK1_VVXSB2EoYuRRw", "name", "John"]""", """["2CBudCWI5EImahgzdcU1Vw", "surname", "Doe"]"""),
)
/** A membership card (`member_id`) issued to the holder [did] and bound to its key [jwk]. */
fun membershipVc(did: String, jwk: String): String = issuedSdJwt(
    did, jwk, "https://credentials.example.com/membership_card", listOf("""["Tq0b3hBr8Ue5eYyM2xkZ1w", "member_id", "M-1"]"""),
)
private fun issuedSdJwt(did: String, jwk: String, vct: String, disclosures: List<String>): String = fixtureSdJwt(
    """{"typ":"dc+sd-jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
    """{"sub":"$did","vct":"$vct","iat":1760606075,"_sd_alg":"sha-256","iss":"${fixtureDidKey(FixtureKey.ISSUER)}","exp":2075966075,"nbf":1760606075,"cnf":{"jwk":$jwk}}""",
    disclosures,
    FixtureKey.ISSUER,
)
val DELEGATE_PAYLOAD_DISCLOSURE: String by lazy {
    Fixtures.base64Url("""["test-salt-for-delegation",{"purchase_id":"p-42","cnf":{"jwk":$DELEGATE_JWK}}]""")
}
const val IDENTITY_DCQL_QUERY =
    """{"credentials":[{"id":"Identity-1","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]},"claims":[{"path":["name"]}]}]}"""
const val IDENTITY_AND_MEMBERSHIP_DCQL_QUERY =
    """{"credentials":[{"id":"Identity-1","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]},"claims":[{"path":["name"]}]},{"id":"Membership-1","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/membership_card"]},"claims":[{"path":["member_id"]}]}]}"""
// Both items are written in the SDK's serialization order, so the hash of the received string is
// also the hash an SDK verifier computes for them.
val DELEGATE_TRANSACTION_DATA: String by lazy {
    Fixtures.base64Url("""{"credential_ids":["Identity-1"],"transaction_data_hashes_alg":null,"type":"delegate","format":"dSD-JWT+KB","delegate_payload_disclosure":"$DELEGATE_PAYLOAD_DISCLOSURE"}""")
}
val PAYMENT_TRANSACTION_DATA: String =
    Fixtures.base64Url("""{"credential_ids":["Identity-1"],"transaction_data_hashes_alg":null,"type":"payment","payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}}""")

fun transactionDataHash(encodedItem: String): String =
    Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(encodedItem.toByteArray()))
val REQUEST_URI_FOR_DELEGATION: String by lazy {
    "openid4vp://?client_id=$ENCODED_VERIFIER_CLIENT_ID&request_uri=http%3A%2F%2Flocalhost%3A9006"
}
val DELEGATION_AUTH_REQUEST_JWT: String by lazy {
    fixtureJws(
        """{"alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.VERIFIER)}","typ":"application/oauth-authz-req+jwt"}""",
        """{"response_type":"vp_token","state":"1d8b0d93-86e8-4135-87d4-524bb0500bf3","transaction_data":["$DELEGATE_TRANSACTION_DATA","$PAYMENT_TRANSACTION_DATA"],"response_mode":"direct_post","nonce":"F3vbCyXV4Bkj-RConeiG1iKdA5XuaEHHaycOICINu2M","client_metadata":$clientMetadata,"client_id":"$VERIFIER_CLIENT_ID","dcql_query":$IDENTITY_DCQL_QUERY,"response_uri":"http://localhost:9006/response"}""",
        FixtureKey.VERIFIER,
    )
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

                val didAndKeyMetadata = createDidAndKeyMetadata(inMemKms)
                didAndKeyMetadata.keyMetadata.didUrl = fixtureDidKeyUrl(FixtureKey.HOLDER)
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
                credentialIds = listOf("Identity-1"),
                transactionDataHashesAlg = listOf(HashAlgorithm.SHA256),
                content = TransactionDataItemTypeContent.Unknown(type = "type1", data = "{}"),
            )
        )
        assert(transactionData == authorizationRequest.transactionData)
        mockServer.shutdown()

    }

    @Test
    fun testDelegateTransactionDataYieldsDelegationGrant() = runTest {
        val (wallet, credentials) = delegatingWallet(::delegationVc)
        val server = MockWebServer()
        server.start(9006)
        val authorizationRequest = try {
            server.enqueue(
                MockResponse()
                    .setResponseCode(200)
                    .setBody(DELEGATION_AUTH_REQUEST_JWT)
                    .setHeader("content-type", "application/oauth-authz-req+jwt")
            )
            wallet.getAuthorizationRequest(REQUEST_URI_FOR_DELEGATION)
        } finally {
            server.shutdown()
        }

        val (delegateItem, paymentItem) = authorizationRequest.transactionData!!
        assertEquals(listOf("Identity-1"), delegateItem.credentialIds)
        assertEquals(delegateContent(DELEGATE_PAYLOAD_DISCLOSURE), delegateItem.content)
        val paymentContent = paymentItem.content as TransactionDataItemTypeContent.Unknown
        assertEquals("payment", paymentContent.type)
        assertEquals(
            Json.parseToJsonElement("""{"payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}}"""),
            Json.parseToJsonElement(paymentContent.data),
        )

        val origin = "https://agent.example.org"
        val result = wallet.presentCredentialsAuto(
            authorizationRequest.copy(responseMode = "dc_api", responseUri = null),
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = origin),
        ) as PresentationResult.AuthResponse
        val response = (result.v1 as AuthorizationResponse.Plain).v1

        assertDelegationGrant(
            presentationFor("Identity-1", response.vpToken),
            credentials.single(),
            typ = "kb+sd-jwt+kb",
            delegatePayload = """{"purchase_id":"p-42","cnf":{"jwk":$DELEGATE_JWK},"aud":"origin:$origin","nonce":"${authorizationRequest.nonce}"}""",
        )
        assertEquals(
            listOf(DELEGATE_TRANSACTION_DATA, PAYMENT_TRANSACTION_DATA).map(::transactionDataHash),
            response.transactionDataHashes,
        )
    }

    @Test
    fun testDelegateGrantIsPostedToTheVerifier() = runTest {
        val (wallet, credentials) = delegatingWallet(::delegationVc)
        val server = MockWebServer()
        server.start(9006)
        try {
            server.enqueue(
                MockResponse()
                    .setResponseCode(200)
                    .setBody(DELEGATION_AUTH_REQUEST_JWT)
                    .setHeader("content-type", "application/oauth-authz-req+jwt")
            )
            server.enqueue(MockResponse().setResponseCode(200).setBody("").setHeader("content-type", "text/plain"))
            val authorizationRequest = wallet.getAuthorizationRequest(REQUEST_URI_FOR_DELEGATION)

            wallet.presentCredentialsAuto(
                authorizationRequest,
                AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = null),
            ) as PresentationResult.Presented

            server.takeRequest(3, TimeUnit.SECONDS)!!
            val form = formFields(String(server.takeRequest(3, TimeUnit.SECONDS)!!.body.readByteArray()))
            assertDelegationGrant(
                presentationFor("Identity-1", form.getValue("vp_token")),
                credentials.single(),
                typ = "kb+sd-jwt+kb",
                delegatePayload = """{"purchase_id":"p-42","cnf":{"jwk":$DELEGATE_JWK},"aud":"$VERIFIER_CLIENT_ID","nonce":"${authorizationRequest.nonce}"}""",
            )
            assertEquals(
                listOf(DELEGATE_TRANSACTION_DATA, PAYMENT_TRANSACTION_DATA).map(::transactionDataHash),
                Json.parseToJsonElement(form.getValue("transaction_data_hashes")).jsonArray.map { it.jsonPrimitive.content },
            )
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun testOpenDelegationYieldsAGrantWithoutCnf() = runTest {
        val (wallet, credentials) = delegatingWallet(::delegationVc)
        val openItem = TransactionDataItem(
            credentialIds = listOf("Identity-1"),
            transactionDataHashesAlg = null,
            content = TransactionDataItemTypeContent.DelegateSdJwt(
                DelegateSdJwtTransactionData(
                    format = DelegateSdJwtTransactionDataFormat.OPEN,
                    delegatePayloadDisclosure = Fixtures.base64Url("""["test-salt",{"purchase_id":"p-7"}]"""),
                    delegateDisclosures = null,
                )
            ),
        )
        val origin = "https://agent.example.org"
        val request = dcApiRequest(listOf(openItem))

        val result = wallet.presentCredentialsAuto(
            request,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = origin),
        ) as PresentationResult.AuthResponse

        assertDelegationGrant(
            presentationFor("Identity-1", (result.v1 as AuthorizationResponse.Plain).v1.vpToken),
            credentials.single(),
            typ = "kb+sd-jwt",
            delegatePayload = """{"purchase_id":"p-7","aud":"origin:$origin","nonce":"${request.nonce}"}""",
        )
    }

    @Test
    fun testPresentCredentialsAnswersADelegateItem() = runTest {
        val (wallet, credentials) = delegatingWallet(::delegationVc)
        val origin = "https://agent.example.org"
        val request = dcApiRequest(listOf(identityDelegateItem(delegateContent(DELEGATE_PAYLOAD_DISCLOSURE))))

        val result = wallet.presentCredentials(
            request,
            credResultsToCredMapping(wallet.findVcsForPresentation(request)),
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = origin),
        ) as PresentationResult.AuthResponse

        assertDelegationGrant(
            presentationFor("Identity-1", (result.v1 as AuthorizationResponse.Plain).v1.vpToken),
            credentials.single(),
            typ = "kb+sd-jwt+kb",
            delegatePayload = """{"purchase_id":"p-42","cnf":{"jwk":$DELEGATE_JWK},"aud":"origin:$origin","nonce":"${request.nonce}"}""",
        )
    }

    @Test
    fun testDelegateItemOnlyTurnsItsOwnCredentialIntoAGrant() = runTest {
        val (wallet, credentials) = delegatingWallet(::delegationVc, ::membershipVc)
        val (identity, membership) = credentials
        val origin = "https://agent.example.org"
        val request = dcApiRequest(
            listOf(identityDelegateItem(delegateContent(DELEGATE_PAYLOAD_DISCLOSURE))),
            dcqlQuery = IDENTITY_AND_MEMBERSHIP_DCQL_QUERY,
        )

        val result = wallet.presentCredentialsAuto(
            request,
            AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = origin),
        ) as PresentationResult.AuthResponse
        val vpToken = (result.v1 as AuthorizationResponse.Plain).v1.vpToken

        assertDelegationGrant(
            presentationFor("Identity-1", vpToken),
            identity,
            typ = "kb+sd-jwt+kb",
            delegatePayload = """{"purchase_id":"p-42","cnf":{"jwk":$DELEGATE_JWK},"aud":"origin:$origin","nonce":"${request.nonce}"}""",
        )
        // The credential the item does not target is presented as usual: its disclosure and a KB-JWT.
        val presentation = presentationFor("Membership-1", vpToken)
        val issuedComponents = membership.split("~")
        val kbJwt = presentation.substringAfterLast("~")
        assertEquals(listOf(issuedComponents[0], issuedComponents[1], kbJwt), presentation.split("~"))
        val kbParts = Fixtures.jwtParts(kbJwt)
        assertEquals("kb+jwt", kbParts.header["typ"]!!.jsonPrimitive.content)
        assertEquals("origin:$origin", kbParts.payload["aud"]!!.jsonPrimitive.content)
        assertEquals(request.nonce, kbParts.payload["nonce"]!!.jsonPrimitive.content)
        assertEquals(Fixtures.sha256(presentation.removeSuffix(kbJwt)), kbParts.payload["sd_hash"]!!.jsonPrimitive.content)
        assertTrue(Fixtures.verifiesEs256(kbJwt, Fixtures.cnfJwk(issuedComponents[0])))
    }

    @Test
    fun testNestedDelegateDisclosuresAreRejected() = runTest {
        val (wallet, _) = delegatingWallet(::delegationVc)
        val nested = TransactionDataItemTypeContent.DelegateSdJwt(
            DelegateSdJwtTransactionData(
                format = DelegateSdJwtTransactionDataFormat.HOLDER_BINDING,
                delegatePayloadDisclosure = DELEGATE_PAYLOAD_DISCLOSURE,
                delegateDisclosures = listOf(Fixtures.base64Url("""["test-salt","role","buyer"]""")),
            )
        )

        val error = assertThrows<Exception.Oid4vpHolder> {
            runBlocking {
                wallet.presentCredentialsAuto(
                    dcApiRequest(listOf(identityDelegateItem(nested))),
                    AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = "https://agent.example.org"),
                )
            }
        }
        assertTrue(error.message.contains("delegate_disclosures"), error.message)
    }

    private fun dcApiRequest(transactionData: List<TransactionDataItem>, dcqlQuery: String = IDENTITY_DCQL_QUERY) =
        authRequest.copy(
            presentationDefinition = """{"dcql_query":$dcqlQuery}""",
            responseMode = "dc_api",
            responseUri = null,
            transactionData = transactionData,
        )

    private fun identityDelegateItem(content: TransactionDataItemTypeContent) =
        TransactionDataItem(credentialIds = listOf("Identity-1"), transactionDataHashesAlg = null, content = content)

    private fun presentationFor(credentialId: String, vpToken: String): String =
        Json.parseToJsonElement(vpToken).jsonObject[credentialId]!!.jsonArray.single().jsonPrimitive.content

    private fun formFields(body: String): Map<String, String> =
        body.split("&").associate { field ->
            val (name, value) = field.split("=", limit = 2)
            URLDecoder.decode(name, Charsets.UTF_8) to URLDecoder.decode(value, Charsets.UTF_8)
        }

    /** A one-hop grant over the identity [credential] whose single delegate payload is [delegatePayload]. */
    private fun assertDelegationGrant(grant: String, credential: String, typ: String, delegatePayload: String) {
        val components = grant.split("~")
        val issuedComponents = credential.split("~")
        val link = components.getOrElse(3) { "" }
        // The issuer JWT, only the requested disclosure (`name`, not `surname`), the empty
        // component that precedes a chain link, the link and the trailing empty component.
        assertEquals(listOf(issuedComponents[0], issuedComponents[1], "", link, ""), components)
        val linkParts = Fixtures.jwtParts(link)
        assertEquals(typ, linkParts.header["typ"]!!.jsonPrimitive.content)
        assertEquals(Json.parseToJsonElement("[$delegatePayload]"), linkParts.payload["delegate_payload"])
        // What a verifier checks: the link binds to the issuer JWT and is signed by the key in its `cnf`.
        assertEquals(Fixtures.sha256(issuedComponents[0]), linkParts.payload["issuer_jwt_hash"]!!.jsonPrimitive.content)
        assertTrue(Fixtures.verifiesEs256(link, Fixtures.cnfJwk(issuedComponents[0])))
        assertFalse(Fixtures.verifiesEs256(link, Json.parseToJsonElement(DELEGATE_JWK).jsonObject))
    }

    @Test
    fun testTransactionDataHashCoversTheItemPayload() = runTest {
        suspend fun hashFor(data: String): String {
            val request = authRequest.copy(
                responseMode = "dc_api",
                responseUri = null,
                transactionData = listOf(unknownItem("payment", data)),
            )
            val result = holder.presentCredentialsAuto(
                request,
                AuthorizationResponseMetadata(claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = "https://example.verifier.org"),
            ) as PresentationResult.AuthResponse
            return (result.v1 as AuthorizationResponse.Plain).v1.transactionDataHashes!!.single()
        }
        // The item as the SDK serializes it for hashing: its own fields first, then `type` and `data`.
        fun expectedHash(payload: String): String = transactionDataHash(
            Fixtures.base64Url("""{"credential_ids":["Identity-1"],"transaction_data_hashes_alg":null,"type":"payment"$payload}""")
        )

        assertEquals(expectedHash(""), hashFor("{}"))
        assertEquals(
            expectedHash(""","payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}"""),
            hashFor("""{"payee":"merchant-1","amount":{"value":"42.00","currency":"EUR"}}"""),
        )
        assertEquals(
            expectedHash(""","amount":100000000000000000000"""),
            hashFor("""{"amount":100000000000000000000}"""),
        )
    }

    private fun unknownItem(type: String, data: String) = TransactionDataItem(
        credentialIds = listOf("Identity-1"),
        transactionDataHashesAlg = null,
        content = TransactionDataItemTypeContent.Unknown(type = type, data = data),
    )

    private fun delegateContent(disclosure: String) = TransactionDataItemTypeContent.DelegateSdJwt(
        DelegateSdJwtTransactionData(
            format = DelegateSdJwtTransactionDataFormat.HOLDER_BINDING,
            delegatePayloadDisclosure = disclosure,
            delegateDisclosures = null,
        )
    )

    /**
     * A wallet, opted in unless [allowDelegation] says otherwise (`null` leaves the builder's default), and the
     * credentials it holds, each issued to the wallet's own key, so the links and KB-JWTs it signs verify against
     * their `cnf`.
     */
    private suspend fun delegatingWallet(
        vararg issue: (did: String, jwk: String) -> String,
        allowDelegation: Boolean? = true,
    ): Pair<Oid4vpHolder, List<String>> {
        val kms = InMemKms()
        val vault = InMemVault()
        val didAndKeyMetadata = createDidAndKeyMetadata(kms)
        val jwk = kms.get(didAndKeyMetadata.keyMetadata.kid).inner.jwk()!!
        val credentials = issue.map { it(didAndKeyMetadata.did, jwk) }
        for (payload in credentials) {
            val credential = Credential(format = VcFormat.SD_JWT_VC, payload = payload)
            vault.storeCredential(credential, resolveMetadata(credential, didAndKeyMetadata.keyMetadata))
        }
        val wallet = Oid4vpHolderBuilder(
            kms, vault, CLIENT_ID, ReqwestHttpClient.insecure(), MockNonceHandler("some_nonce"), allowDelegation
        ).build()
        return wallet to credentials
    }

    private suspend fun declineAndReadResponse(item: TransactionDataItem, wallet: Oid4vpHolder = holder): String {
        val server = MockWebServer()
        server.start(9007)
        try {
            server.enqueue(MockResponse().setResponseCode(200).setBody("").setHeader("content-type", "text/plain"))
            wallet.declineAuthorizationRequest(
                authRequest.copy(responseUri = "http://localhost:9007/response", transactionData = listOf(item))
            )
            return String(server.takeRequest(3, TimeUnit.SECONDS)!!.body.readByteArray())
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun testDelegationIsOffByDefault() = runTest {
        // A stored credential that matches the request, so each refusal below can only come from the gate.
        val (wallet, _) = delegatingWallet(::delegationVc, allowDelegation = null)
        val item = identityDelegateItem(delegateContent(DELEGATE_PAYLOAD_DISCLOSURE))
        val request = dcApiRequest(listOf(item))
        val metadata = AuthorizationResponseMetadata(
            claimsToExclude = null, idTokenMetadata = null, dcApiOrigin = "https://agent.example.org",
        )
        // Without the delegate item the same request finds the credential.
        val credentials = credResultsToCredMapping(wallet.findVcsForPresentation(request.copy(transactionData = null)))
        assertEquals(setOf("Identity-1"), credentials.keys)

        fun assertRefused(name: String, call: suspend () -> Unit) {
            val error = assertThrows<Exception.Oid4vpHolder>(name) { runBlocking { call() } }
            assertTrue(error.message.contains("delegation is not enabled"), "$name: ${error.message}")
        }
        assertRefused("presentCredentialsAuto") { wallet.presentCredentialsAuto(request, metadata) }
        assertRefused("findVcsForPresentation") { wallet.findVcsForPresentation(request) }
        assertRefused("presentCredentials") { wallet.presentCredentials(request, credentials, metadata) }

        assertTrue(declineAndReadResponse(item, wallet).startsWith("error=access_denied"))
    }

    @Test
    fun testDeclineWorksWithUnrecognizedDelegateItem() = runTest {
        val body = declineAndReadResponse(
            unknownItem("delegate", """{"format":"dSD-JWT+XYZ","delegate_payload_disclosure":"x"}""")
        )
        assertTrue(body.startsWith("error=access_denied"))
    }

    @Test
    fun testDeclineWorksWithLargeIntegerPayload() = runTest {
        val body = declineAndReadResponse(unknownItem("payment", """{"amount":100000000000000000000}"""))
        assertTrue(body.startsWith("error=access_denied"))
    }

    @Test
    fun testUnrecognizedDelegateItemsAreRejected() = runTest {
        // Upstream parses a `delegate` item without its fields, or with an unknown `format`, as `Unknown`.
        val reasons = mapOf(
            """{"delegate_payload_disclosure":"x"}""" to "has no `format`",
            """{"format":"dSD-JWT+XYZ","delegate_payload_disclosure":"x"}""" to "has an unsupported `format`",
            """{"format":"dSD-JWT+KB"}""" to "has no `delegate_payload_disclosure`",
        )
        val (wallet, _) = delegatingWallet(::delegationVc)
        for ((data, reason) in reasons) {
            val error = assertThrows<Exception.Oid4vpHolder> {
                runBlocking {
                    wallet.findVcsForPresentation(authRequest.copy(transactionData = listOf(unknownItem("delegate", data))))
                }
            }
            assertTrue(error.message.contains(reason), error.message)
        }
    }

    @Test
    fun testMalformedJsonArgumentsRaiseParseErrors() = runTest {
        val notAnObject = assertThrows<Exception.Parse> {
            runBlocking {
                holder.findVcsForPresentation(
                    authRequest.copy(transactionData = listOf(unknownItem("payment", "\"secret-value\"")))
                )
            }
        }
        assertTrue(notAnObject.message.contains("must be a JSON object"), notAnObject.message)
        assertFalse(notAnObject.message.contains("secret-value"))
        val notJson = assertThrows<Exception.Parse> {
            runBlocking { holder.findVcsForPresentation(authRequest.copy(clientMetadata = "{secret-value")) }
        }
        assertFalse(notJson.message.contains("secret-value"))
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
        holder.getAuthorizationRequest("openid4vp://?client_id=$VERIFIER_CLIENT_ID&request_uri_method=post&request_uri=http://localhost:9002/request")
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
    fun testDeclineAuthorizationRequestWithReason() = runTest {
        val server = MockWebServer()
        server.start(9007)
        try {
            server.enqueue(MockResponse().setResponseCode(200).setBody("").setHeader("content-type", "text/plain"))
            holder.declineAuthorizationRequest(
                authRequest.copy(responseUri = "http://localhost:9007/response"),
                DeclineAuthorizationRequest(DeclineAuthorizationRequestReason.INVALID_TRANSACTION_DATA, "unsupported currency")
            )
            val request = String(server.takeRequest(3, TimeUnit.SECONDS)!!.body.readByteArray())
            assertEquals(
                "error=invalid_transaction_data&error_description=unsupported+currency&state=1d8b0d93-86e8-4135-87d4-524bb0500bf3",
                request
            )
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun testDeclineAuthorizationRequestRejectsNonAsciiDescription() = runTest {
        val error = assertThrows<Exception.Oid4vpHolder> {
            runBlocking {
                holder.declineAuthorizationRequest(authRequest, DeclineAuthorizationRequest(DeclineAuthorizationRequestReason.ACCESS_DENIED, "отказано"))
            }
        }
        assertTrue(error.message.contains("decline description must be non-empty"), error.message)
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