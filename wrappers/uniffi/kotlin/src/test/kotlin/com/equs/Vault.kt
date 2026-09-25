package com.equs

import com.equs.credentials.Credential
import com.equs.credentials.CredentialEntry
import com.equs.credentials.CredentialMetadata
import com.equs.credentials.VaultFetchOptions
import com.equs.credentials.VcFormat
import com.equs.credentials.setJniLibPath
import com.equs.credentials.wrapVaultForTests
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals
import com.equs.credentials.Vault as EqusSdkVault

class Vault {
    val credentialId = "cred:12345"
    val criteria = arrayOf("$.vct", "$.name").toList()
    val credentialEntries = arrayOf(
        CredentialEntry(
            Credential(
                VcFormat.SD_JWT_VC,
                Fixtures.token("vc")
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

    private fun mockVault(): EqusSdkVault {
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
) : EqusSdkVault {

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