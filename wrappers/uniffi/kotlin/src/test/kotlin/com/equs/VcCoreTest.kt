package com.equs

import com.equs.credentials.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
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
