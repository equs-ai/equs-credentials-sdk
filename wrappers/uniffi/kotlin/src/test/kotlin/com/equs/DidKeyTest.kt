package com.equs

import com.equs.sdk.DidKey
import com.equs.sdk.InMemKms
import com.equs.sdk.KeyType
import com.equs.sdk.setJniLibPath
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertContains

class DidKeyTest {
    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun generateDid() = runTest {
        val kms = InMemKms()
        val kid = kms.create(KeyType.P256)
        val keyHandle = kms.get(kid)

        val didKey = DidKey()

        val did = didKey.generate(keyHandle)

        assertContains(did, "did:key")
    }
}


