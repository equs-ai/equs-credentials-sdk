package com.bci

import com.bci.asdk.KeyType
import com.bci.asdk.WrappedKeyHandle
import com.bci.asdk.setJniLibPath
import com.bci.asdk.wrapKmsForTests
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import com.bci.asdk.Kms as ASDKKms

class Kms {
    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun create() = runTest {
        val kms = mockKms()
        val kid = kms.create(KeyType.P256)

        assertEquals(kid, "TestString")
    }

    @Test
    fun getByKeyId() = runTest {
        val kms = mockKms()
        val keyHandle = kms.get("TestString")

        assertEquals("testKey", String(keyHandle.inner.pubKey(), Charsets.UTF_8))
    }

    @Test
    fun getByPublicKey() = runTest {
        val kms = mockKms()
        val keyHandle = kms.getByPublicKey("testKey".toByteArray())

        assertEquals("testKey", String(keyHandle.inner.pubKey(), Charsets.UTF_8))
    }

    private fun mockKms(): ASDKKms {
        return wrapKmsForTests(MockKms())
    }
}


class MockKms : ASDKKms {
    override suspend fun create(kt: KeyType): String {
        return "TestString"
    }

    override suspend fun get(kid: String): WrappedKeyHandle {
        return WrappedKeyHandle(MockKeyHandle())
    }

    override suspend fun getByPublicKey(publicKey: ByteArray): WrappedKeyHandle {
        return WrappedKeyHandle(MockKeyHandle())
    }

}