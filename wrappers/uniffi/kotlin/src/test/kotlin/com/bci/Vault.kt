package com.bci

import com.bci.asdk.Credential
import com.bci.asdk.CredentialEntry
import com.bci.asdk.CredentialMetadata
import com.bci.asdk.VaultFetchOptions
import com.bci.asdk.VcFormat
import com.bci.asdk.setJniLibPath
import com.bci.asdk.wrapVaultForTests
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals
import com.bci.asdk.Vault as ASDKVault

class Vault {
    val credentialId = "cred:12345"
    val criteria = arrayOf("$.vct", "$.name").toList()
    val credentialEntries = arrayOf(
        CredentialEntry(
            Credential(
                VcFormat.SD_JWT_VC,
                "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~"
            ),
            "kid", this.credentialId
        )
    ).toList()
    val metadata = CredentialMetadata(
        "vc_type",
        VcFormat.SD_JWT_VC,
        "kid",
        null,
        arrayOf("$.vct", "$.name").toList(),
    )

    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun getCredential() = runTest {
        val vault = mockVault()
        val credential = vault.getCredential(credentialId)

        assertEquals(credentialEntries[0], credential)
    }

    @Test
    fun getAbsentCredential() = runTest {
        val vault = mockVault()
        val credential = vault.getCredential("cred:56789")

        assertEquals(null, credential)
    }

    @Test
    fun getCredentials() = runTest {
        val vault = mockVault()
        val credentials = vault.getCredentials(null)

        assertEquals(credentialEntries, credentials)
    }

    @Test
    fun findCredentials() = runTest {
        val vault = mockVault()
        val credentials = vault.findCredentials(criteria, null)

        assertEquals(credentialEntries, credentials)
    }

    @Test
    fun storeCredential() = runTest {
        val vault = mockVault()
        val storedCredentialId = vault.storeCredential(credentialEntries[0].credential, metadata)

        assertEquals(credentialId, storedCredentialId)
    }

    @Test
    fun deleteCredential() = runTest {
        val vault = mockVault()
        vault.deleteCredential(credentialId)
    }

    private fun mockVault(): ASDKVault {
        return wrapVaultForTests(
            MockVault(
                this.credentialId,
                this.criteria,
                this.credentialEntries,
                this.metadata
            )
        )
    }
}


class MockVault(
    private val credentialId: String,
    private val criteria: List<String>,
    private val credentialEntries: List<CredentialEntry>,
    private val metadata: CredentialMetadata
) : ASDKVault {

    override suspend fun storeCredential(
        credential: Credential,
        metadata: CredentialMetadata
    ): String {
        assertEquals(this.credentialEntries[0].credential, credential)
        assertEquals(this.metadata, metadata)
        return this.credentialId
    }

    override suspend fun deleteCredential(id: String) {
        assertEquals(this.credentialId, id)
    }

    override suspend fun getCredential(id: String): CredentialEntry? {
        if (id != this.credentialId || this.credentialEntries.isEmpty()) {
            return null
        }

        return this.credentialEntries[0]
    }

    override suspend fun getCredentials(pagination: VaultFetchOptions?): List<CredentialEntry> {
        return this.credentialEntries
    }

    override suspend fun findCredentials(
        fields: List<String>,
        pagination: VaultFetchOptions?
    ): List<CredentialEntry> {
        assertEquals(this.criteria, fields)

        return this.credentialEntries
    }

}