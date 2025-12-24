package com.bci

import com.bci.asdk.*
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test

class DidWebTest {
    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun generateDidDocument() = runTest {
        val did = "did:web:test.example.com"
        val kms = InMemKms()
        val kid = kms.create(KeyType.P256)
        val keyHandle = kms.get(kid)

        val verificationMethodKey = VerificationMethodKey(
            keyHandle,
            listOf(VerificationRelationshipType.KEY_AGREEMENT, VerificationRelationshipType.AUTHENTICATION)
        )

        val didWeb = DidWeb(ReqwestHttpClient.insecure())

        val documentString = didWeb.generateDidDocument(did, listOf(verificationMethodKey))
        val document = Json.parseToJsonElement(documentString).jsonObject
        val vmm = document["verificationMethod"]?.jsonArray?.get(0)?.jsonObject



        assertEquals("did:web:test.example.com", document["id"]?.jsonPrimitive?.content)
        assertEquals(
            listOf("https://www.w3.org/ns/did/v1", "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019"),
            document["@context"]?.jsonArray?.map { it.jsonPrimitive.content }
        )
        assertEquals(
            listOf("did:web:test.example.com#key-0"),
            document["keyAgreement"]?.jsonArray?.map { it.jsonPrimitive.content })

        assertEquals("did:web:test.example.com", vmm?.get("controller")?.jsonPrimitive?.content)
        assertEquals("did:web:test.example.com#key-0", vmm?.get("id")?.jsonPrimitive?.content)
        assertEquals("EcdsaSecp256r1VerificationKey2019", vmm?.get("type")?.jsonPrimitive?.content)
        assertEquals(true, vmm?.get("publicKeyMultibase")?.jsonPrimitive?.isString)

    }
}


