package com.equs

import com.equs.credentials.Credential
import com.equs.credentials.CredentialData
import com.equs.credentials.VcFormat
import com.equs.credentials.setJniLibPath
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals
import com.equs.credentials.parseClaims as EqusSdkParseClaims


val SdJwt =
    "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~"

class Utils {
    companion object {

        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun parseClaims() = runTest {
        val result = EqusSdkParseClaims(Credential(VcFormat.SD_JWT_VC, SdJwt))

        assertEquals("John", result["name"]?.trim('"'))
        assertEquals("1728882611", result["iat"])
        assertEquals("https://credentials.example.com/identity_credential", result["vct"]?.trim('"'))
        assertEquals("did:key:zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM", result["sub"]?.trim('"'))
        assertEquals("did:key:zDnaexeh3T1CziWWSEeWpyuTkXqiT5ikiCw5iZQRBv4HXuex6", result["iss"]?.trim('"'))
        assertEquals("1760418611", result["exp"])
        assertEquals("1728882611", result["nbf"])
    }
}