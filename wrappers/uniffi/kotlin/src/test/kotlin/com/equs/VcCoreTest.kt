package com.equs

import com.equs.credentials.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VcCoreTest {
    companion object {
        lateinit var mockServer: MockWebServer
        lateinit var keyMetadata: KeyMetadata
        lateinit var sharedKms: InMemKms
        lateinit var statusListJwt: String

        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
            mockServer = MockWebServer().apply { start(9001) }
            sharedKms = InMemKms()
            keyMetadata =
                runBlocking { createDidAndKeyMetadata(sharedKms).keyMetadata }
            statusListJwt =
                runBlocking {
                    val statusIssuer =
                        VcCoreStatusIssuer(
                            sharedKms,
                            VcCoreFixtures.statusIssuerMetadata(keyMetadata),
                        )
                    (statusIssuer.issueStatusList(
                        VcCoreFixtures.STATUS_LIST_ID,
                        VcStatusesData.StatusListToken(listOf(StatusEntry(1u, 0u))),
                    ) as StatusList.StatusListTokenJwt)
                        .v1
                }
            mockServer.dispatcher =
                object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse {
                        return if (request.path?.contains("status_list") == true) {
                            MockResponse()
                                .setResponseCode(200)
                                .setBody(statusListJwt)
                                .setHeader(
                                    "content-type",
                                    "application/statuslist+jwt",
                                )
                        } else {
                            MockResponse().setResponseCode(404)
                        }
                    }
                }
        }

        @JvmStatic
        @AfterAll
        fun tearDown() {
            mockServer.shutdown()
        }

        private fun newResolver(): UniversalDidResolver = UniversalDidResolver(null)
    }

    // -----------------------------------------------------------------
    // StatusIssuer
    // -----------------------------------------------------------------

    @Test
    fun statusIssuerIssuesStatusList() = runTest {
        val statusIssuer =
            VcCoreStatusIssuer(sharedKms, VcCoreFixtures.statusIssuerMetadata(keyMetadata))

        val result =
            statusIssuer.issueStatusList(
                VcCoreFixtures.STATUS_LIST_ID,
                VcStatusesData.StatusListToken(listOf(StatusEntry(1u, 0u))),
            )

        val jwt = (result as StatusList.StatusListTokenJwt).v1
        assertTrue(jwt.isNotEmpty(), "Expected non-empty JWT status list")
    }

    @Test
    fun statusIssuerBuilderProducesUsableInstance() = runTest {
        val builder =
            Oid4vciStatusIssuerBuilder(
                sharedKms,
                VcCoreFixtures.statusIssuerMetadata(keyMetadata),
            )
        val statusIssuer = builder.build()

        val result =
            statusIssuer.issueStatusList(
                VcCoreFixtures.STATUS_LIST_ID,
                VcStatusesData.StatusListToken(listOf(StatusEntry(2u, 1u))),
            )

        assertNotNull(result)
        assertTrue(result is StatusList.StatusListTokenJwt)
    }

    // -----------------------------------------------------------------
    // Issuer
    // -----------------------------------------------------------------

    @Test
    fun issuerOffersCredential() = runTest {
        val issuer =
            VcCoreIssuer(
                sharedKms,
                VcCoreFixtures.issuerMetadata(keyMetadata),
                newResolver(),
            )
        val offer = issuer.offerCredential(VcCoreFixtures.SCOPE, null)
        assertEquals(VcCoreFixtures.ISSUER_ID, offer.issuerId)
        assertEquals(VcCoreFixtures.SCOPE, offer.credDefId)
    }

    // -----------------------------------------------------------------
    // Holder
    // -----------------------------------------------------------------

    @Test
    fun holderRequestStoreAndVerifyCredential() = runTest {
        val vault = InMemVault()
        val resolver = newResolver()
        val issuer =
            VcCoreIssuer(
                sharedKms,
                VcCoreFixtures.issuerMetadata(keyMetadata),
                resolver,
            )
        val holder =
            VcCoreHolder(
                sharedKms,
                vault,
                VcCoreFixtures.holderMetadata(),
                resolver,
                ReqwestHttpClient.insecure(),
            )

        val offer = issuer.offerCredential(VcCoreFixtures.SCOPE, null)
        val credentialRequest =
            holder.requestCredential(offer, VcCoreFixtures.NONCE, keyMetadata)
        assertTrue(credentialRequest.proof.proof.isNotEmpty())

        val credential =
            issuer.issueCredential(
                credentialRequest,
                VcCoreFixtures.claims,
                VcCoreFixtures.NONCE,
                VcCoreFixtures.credStatusInfo,
            )
        holder.verifyCredential(credential)

        val metadata = resolveMetadata(credential, keyMetadata)
        val storedId = holder.storeCredential(credential, metadata)
        assertTrue(storedId.isNotEmpty())
    }

    @Test
    fun holderFindsAndPresentsCredential() = runTest {
        val vault = InMemVault()
        val resolver = newResolver()

        val issuer =
            VcCoreIssuer(
                sharedKms,
                VcCoreFixtures.issuerMetadata(keyMetadata),
                resolver,
            )
        val holder =
            VcCoreHolder(
                sharedKms,
                vault,
                VcCoreFixtures.holderMetadata(),
                resolver,
                ReqwestHttpClient.insecure(),
            )

        // Pre-issue + store one credential.
        val offer = issuer.offerCredential(VcCoreFixtures.SCOPE, null)
        val credentialRequest =
            holder.requestCredential(offer, VcCoreFixtures.NONCE, keyMetadata)
        val credential =
            issuer.issueCredential(
                credentialRequest,
                VcCoreFixtures.claims,
                VcCoreFixtures.NONCE,
                VcCoreFixtures.credStatusInfo,
            )
        holder.storeCredential(credential, resolveMetadata(credential, keyMetadata))

        // Find for presentation
        val findResult = holder.findVcsForPresentation(VcCoreFixtures.presentationInput())
        val data = findResult.data
        assertTrue(data is CredentialsSearchResult.Credentials, "expected credentials, got $data")
        assertTrue((data as CredentialsSearchResult.Credentials).v1.isNotEmpty())

        // Auto-present
        val binder =
            HolderBinder(
                nonce = VcCoreFixtures.NONCE,
                verifierId = VcCoreFixtures.VERIFIER_ID,
                responseUri = null,
            )
        val presentation =
            holder.createPresentationAuto(binder, VcCoreFixtures.presentationInput())
        assertTrue(presentation is Presentation.SdJwtVp, "Expected SdJwtVp presentation")
        assertTrue((presentation as Presentation.SdJwtVp).v1.isNotEmpty(), "Expected non-empty presentation payload")

        // Explicit-credential presentation
        val explicit =
            holder.createPresentation(
                binder,
                VcCoreFixtures.presentationInput(),
                data.v1.first(),
            )
        assertTrue(explicit is Presentation.SdJwtVp)
        assertTrue((explicit as Presentation.SdJwtVp).v1.isNotEmpty())
    }

    @Test
    fun holderCreatesDelegatedCredential() = runTest {
        val resolver = newResolver()
        val issuer = VcCoreIssuer(sharedKms, VcCoreFixtures.issuerMetadata(keyMetadata), resolver)
        val holder = VcCoreHolder(
            sharedKms, InMemVault(), VcCoreFixtures.holderMetadata(), resolver, ReqwestHttpClient.insecure(),
        )
        val offer = issuer.offerCredential(VcCoreFixtures.SCOPE, null)
        val credentialRequest = holder.requestCredential(offer, VcCoreFixtures.NONCE, keyMetadata)
        val credential = issuer.issueCredential(
            credentialRequest, VcCoreFixtures.claims, VcCoreFixtures.NONCE, VcCoreFixtures.credStatusInfo,
        )

        val grant = holder.createDelegatedCredential(
            CredentialEntry(credential = credential, kid = keyMetadata.kid, id = "entry-1"),
            DelegationParams(
                delegatePayloads = listOf("""{"scope":"purchase"}"""),
                binding = ChainBindingMode.ISSUER_JWT_HASH,
            ),
        )

        val components = grant.split("~")
        val link = components.getOrElse(2) { "" }
        // The issuer JWT, no forwarded disclosures, the empty component that precedes a chain
        // link, the link and the trailing empty component.
        assertEquals(listOf(credential.payload.split("~")[0], "", link, ""), components)
        val linkParts = Fixtures.jwtParts(link)
        assertEquals("kb+sd-jwt", linkParts.header["typ"]!!.jsonPrimitive.content)
        assertEquals(Json.parseToJsonElement("""[{"scope":"purchase"}]"""), linkParts.payload["delegate_payload"])
    }

    @Test
    fun holderPassesEveryDelegationParameter() = runTest {
        val (holder, credential) = holderWithIssuedCredential()
        val holderJwk = sharedKms.get(keyMetadata.kid).inner.jwk()!!

        val grant = holder.createDelegatedCredential(
            CredentialEntry(credential = credential, kid = keyMetadata.kid, id = "entry-1"),
            DelegationParams(
                delegatePayloads = listOf("""{"scope":"purchase","cnf":{"jwk":$holderJwk}}"""),
                claimsToDisclose = """{"name":true}""",
                aud = "https://agent.example.org",
                nonce = "n-42",
            ),
        )

        val components = grant.split("~")
        val link = components.getOrElse(3) { "" }
        // The issuer JWT, only the `name` disclosure, the empty component before the chain link,
        // the link and the trailing empty component.
        assertEquals(listOf(credential.payload.split("~")[0], disclosureOf(credential, "name"), "", link, ""), components)
        val linkParts = Fixtures.jwtParts(link)
        assertEquals("kb+sd-jwt+kb", linkParts.header["typ"]!!.jsonPrimitive.content)
        // `binding` was left out, so the link binds through `sd_hash`.
        assertNotNull(linkParts.payload["sd_hash"])
        assertNull(linkParts.payload["issuer_jwt_hash"])
        assertEquals(
            Json.parseToJsonElement("""[{"scope":"purchase","cnf":{"jwk":$holderJwk},"aud":"https://agent.example.org","nonce":"n-42"}]"""),
            linkParts.payload["delegate_payload"],
        )
    }

    @Test
    fun holderDropsDisclosuresWhenRedelegating() = runTest {
        val (holder, credential) = holderWithIssuedCredential()
        val holderJwk = sharedKms.get(keyMetadata.kid).inner.jwk()!!
        val name = disclosureOf(credential, "name")
        val firstHop = holder.createDelegatedCredential(
            CredentialEntry(credential = credential, kid = keyMetadata.kid, id = "entry-1"),
            DelegationParams(
                delegatePayloads = listOf("""{"scope":"purchase","cnf":{"jwk":$holderJwk}}"""),
                claimsToDisclose = """{"name":true}""",
                binding = ChainBindingMode.ISSUER_JWT_HASH,
            ),
        )
        assertTrue(firstHop.split("~").contains(name))

        val grant = CredentialEntry(
            credential = Credential(format = VcFormat.SD_JWT_VC, payload = firstHop),
            kid = keyMetadata.kid,
            id = "entry-2",
        )
        val secondHop = holder.createDelegatedCredential(
            grant,
            DelegationParams(
                delegatePayloads = listOf("""{"scope":"checkout"}"""),
                dropDisclosures = listOf(name),
                binding = ChainBindingMode.ISSUER_JWT_HASH,
            ),
        )

        assertFalse(secondHop.split("~").contains(name))
        val lastLink = secondHop.split("~").last { it.isNotEmpty() }
        assertEquals(
            Json.parseToJsonElement("""[{"scope":"checkout"}]"""),
            Fixtures.jwtParts(lastLink).payload["delegate_payload"],
        )
        assertThrows<Exception.Core> {
            runBlocking {
                holder.createDelegatedCredential(
                    grant,
                    DelegationParams(
                        delegatePayloads = listOf("""{"scope":"checkout"}"""),
                        dropDisclosures = listOf("not-a-disclosure"),
                    ),
                )
            }
        }
    }

    private suspend fun holderWithIssuedCredential(): Pair<VcCoreHolder, Credential> {
        val resolver = newResolver()
        val issuer = VcCoreIssuer(sharedKms, VcCoreFixtures.issuerMetadata(keyMetadata), resolver)
        val holder = VcCoreHolder(
            sharedKms, InMemVault(), VcCoreFixtures.holderMetadata(), resolver, ReqwestHttpClient.insecure(),
        )
        val offer = issuer.offerCredential(VcCoreFixtures.SCOPE, null)
        val credentialRequest = holder.requestCredential(offer, VcCoreFixtures.NONCE, keyMetadata)
        val credential = issuer.issueCredential(
            credentialRequest, VcCoreFixtures.claims, VcCoreFixtures.NONCE, VcCoreFixtures.credStatusInfo,
        )
        return holder to credential
    }

    /** The disclosure of the issued SD-JWT that discloses [claim]. */
    private fun disclosureOf(credential: Credential, claim: String): String =
        credential.payload.split("~").drop(1).filter { it.isNotEmpty() }.single { disclosure ->
            val decoded = String(Base64.getUrlDecoder().decode(disclosure))
            Json.parseToJsonElement(decoded).jsonArray[1].jsonPrimitive.content == claim
        }

    @Test
    fun holderRejectsInvalidDelegation() = runTest {
        val holder = VcCoreHolder(
            sharedKms, InMemVault(), VcCoreFixtures.holderMetadata(), newResolver(), ReqwestHttpClient.insecure(),
        )
        val notSdJwt = CredentialEntry(
            credential = Credential(format = VcFormat.JWT_VC_JSON, payload = "eyJhbGciOiJub25lIn0.e30."),
            kid = keyMetadata.kid,
            id = "entry-2",
        )
        val params = DelegationParams(delegatePayloads = listOf("""{"scope":"purchase"}"""))

        assertThrows<Exception.Core> {
            runBlocking { holder.createDelegatedCredential(notSdJwt, params) }
        }
        assertThrows<Exception.Parse> {
            runBlocking { holder.createDelegatedCredential(notSdJwt, params.copy(claimsToDisclose = "[]")) }
        }
    }

    // -----------------------------------------------------------------
    // Verifier
    // -----------------------------------------------------------------

    @Test
    fun verifierVerifiesPresentation() = runTest {
        val vault = InMemVault()
        val resolver = newResolver()

        val issuer =
            VcCoreIssuer(
                sharedKms,
                VcCoreFixtures.issuerMetadata(keyMetadata),
                resolver,
            )
        val holder =
            VcCoreHolder(
                sharedKms,
                vault,
                VcCoreFixtures.holderMetadata(),
                resolver,
                ReqwestHttpClient.insecure(),
            )
        val verifier = VcCoreVerifier(VcCoreFixtures.VERIFIER_ID, resolver, ReqwestHttpClient.insecure())

        val offer = issuer.offerCredential(VcCoreFixtures.SCOPE, null)
        val credentialRequest =
            holder.requestCredential(offer, VcCoreFixtures.NONCE, keyMetadata)
        val credential =
            issuer.issueCredential(
                credentialRequest,
                VcCoreFixtures.claims,
                VcCoreFixtures.NONCE,
                VcCoreFixtures.credStatusInfo,
            )
        holder.storeCredential(credential, resolveMetadata(credential, keyMetadata))

        val binder =
            HolderBinder(
                nonce = VcCoreFixtures.NONCE,
                verifierId = VcCoreFixtures.VERIFIER_ID,
                responseUri = null,
            )
        val presentation =
            holder.createPresentationAuto(binder, VcCoreFixtures.presentationInput())

        val claimsJson =
            verifier.verifyPresentation(binder, presentation)
        assertTrue(
            claimsJson.contains("221B Baker Street"),
            "Expected verified claims to contain the address; got $claimsJson",
        )
        assertTrue(claimsJson.contains(VcCoreFixtures.VCT))
    }
}
