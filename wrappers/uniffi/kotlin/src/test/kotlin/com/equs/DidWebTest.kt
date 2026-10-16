package com.equs

import com.equs.credentials.*
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
        // The key is used for keyAgreement, so it is published as JsonWebKey2020 /
        // publicKeyJwk (rather than multibase) with the JWK `kid` pinned to the
        // verification method id, so a JWE encryptor can address the exact key.
        assertEquals(
            listOf("https://www.w3.org/ns/did/v1", "https://w3id.org/security#JsonWebKey2020"),
            document["@context"]?.jsonArray?.map { it.jsonPrimitive.content }
        )
        assertEquals(
            listOf("did:web:test.example.com#key-0"),
            document["keyAgreement"]?.jsonArray?.map { it.jsonPrimitive.content })

        assertEquals("did:web:test.example.com", vmm?.get("controller")?.jsonPrimitive?.content)
        assertEquals("did:web:test.example.com#key-0", vmm?.get("id")?.jsonPrimitive?.content)
        assertEquals("JsonWebKey2020", vmm?.get("type")?.jsonPrimitive?.content)

        val jwk = vmm?.get("publicKeyJwk")?.jsonObject
        assertEquals("EC", jwk?.get("kty")?.jsonPrimitive?.content)
        assertEquals("P-256", jwk?.get("crv")?.jsonPrimitive?.content)
        assertEquals("did:web:test.example.com#key-0", jwk?.get("kid")?.jsonPrimitive?.content)
        assertEquals(true, jwk?.get("x")?.jsonPrimitive?.isString)
        assertEquals(true, jwk?.get("y")?.jsonPrimitive?.isString)

    }
}


