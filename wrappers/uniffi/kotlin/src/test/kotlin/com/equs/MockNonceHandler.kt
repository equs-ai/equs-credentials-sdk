package com.equs

import com.equs.credentials.NonceHandler

class MockNonceHandler(private val nonce: String): NonceHandler {
    override suspend fun generate(): String {
        return this.nonce
    }

    override suspend fun validate(nonce: String): Boolean {
        return true
    }

}