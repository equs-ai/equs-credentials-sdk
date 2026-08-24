package com.equs

import com.equs.sdk.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class UniversalDIDResolver {
    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun customResolversSucceed() = runTest {
        val mockDIDResolver = MockDIDResolver("mock")
        val anotherMockDIDResolver = MockDIDResolver("anothermock")
        val universalDidResolver = UniversalDidResolver(arrayOf(mockDIDResolver, anotherMockDIDResolver).toList())

        val result1 = universalDidResolver.resolve("did:mock:12345")
        val result2 = universalDidResolver.resolve("did:anothermock:12345")

        assertEquals(didResolutionDocument("mock"), result1.document)
        assertEquals(didResolutionDocument("anothermock"), result2.document)
    }

    @Test
    fun multipleAdditionOfSameDidMethodFails() = runTest {
        val mockDIDResolver = MockDIDResolver("mock")

        val exception = assertFailsWith<Exception.DidResolver> {
            UniversalDidResolver(arrayOf(mockDIDResolver, mockDIDResolver).toList())
        }
        assertEquals(
            "v1=Method already exists: mock",
            exception.message
        )
    }
}


class MockDIDResolver : DidResolver {
    var method: String


    constructor(methodName: String) {
        method = methodName
    }

    override suspend fun resolveRepresentation(
        did: String,
        options: DidResolutionOptions
    ): DidResolution {
        return DidResolution(
            document = didResolutionDocument(method),
            metadata = DidMetadata(
                contentType = "application/did+ld+json"
            ),
            documentMetadata = DidDocMetadata(
                deactivated = null
            )
        )
    }

    override fun methodName(): String {
        return method
    }
}

fun didResolutionDocument(method: String): String {
    return "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/multikey/v1\"],\"id\":\"did:${method}:12345\",\"authentication\":[\"did:${method}:12345#key-1\"],\"assertionMethod\":[\"did:${method}:12345#key-1\"],\"verificationMethod\":[{\"id\":\"did:${method}:12345\",\"type\":\"Multikey\",\"controller\":\"did:${method}:12345\",\"publicKeyMultibase\":\"z1BcDfGmZ\"}]}"
}