package com.equs

import com.equs.credentials.Alg
import com.equs.credentials.KeyHandle as EqusSdkKeyHandle
import com.equs.credentials.setJniLibPath
import com.equs.credentials.wrapKeyHandleForTests
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals

class KeyHandle {
    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun getAlg() = runTest {
        val keyHandle = mockKeyHandle()
        val alg = keyHandle.alg()

        assertEquals(Alg.ES256, alg)
    }

    @Test
    fun getPublicKey() = runTest {
        val keyHandle = mockKeyHandle()
        val pubKey = keyHandle.pubKey()

        assertEquals("testKey", String(pubKey, Charsets.UTF_8))
    }

    @Test
    fun getJwk() = runTest {
        val keyHandle = mockKeyHandle()
        val jwk = keyHandle.jwk()

        assertEquals(
            "{\"crv\":\"P-256\",\"kid\":\"618d228e-4767-4aa2-8683-c35c86d7025c\",\"kty\":\"EC\",\"x\":\"huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs\",\"y\":\"4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg\"}",
            jwk,
        )
    }

    @Test
    fun sign() = runTest {
        val keyHandle = mockKeyHandle()
        val payload = "testPayload".toByteArray()
        val result = keyHandle.sign(payload)

        assertEquals(String(payload, Charsets.UTF_8), String(result, Charsets.UTF_8))
    }

    @Test
    fun verify() = runTest {
        val keyHandle = mockKeyHandle()
        val data = "testData".toByteArray()
        val signature = "testSignature".toByteArray()
        keyHandle.verify(data, signature)
    }

    private fun mockKeyHandle(): EqusSdkKeyHandle {
        return wrapKeyHandleForTests(MockKeyHandle())
    }
}

class MockKeyHandle : EqusSdkKeyHandle {
    override fun pubKey(): ByteArray {
        return "testKey".toByteArray()
    }

    override fun jwk(): String? {
        return "{\"crv\":\"P-256\",\"kid\":\"618d228e-4767-4aa2-8683-c35c86d7025c\",\"kty\":\"EC\",\"x\":\"huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs\",\"y\":\"4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg\"}"
    }

    override fun alg(): Alg {
        return Alg.ES256
    }

    override suspend fun sign(payload: ByteArray): ByteArray {
        return payload
    }

    override suspend fun verify(data: ByteArray, signature: ByteArray) {
        assertEquals(String(data, Charsets.UTF_8), "testData")
        assertEquals(String(signature, Charsets.UTF_8), "testSignature")
    }
}