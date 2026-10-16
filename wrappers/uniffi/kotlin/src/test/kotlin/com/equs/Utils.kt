package com.equs

import com.equs.credentials.Credential
import com.equs.credentials.CredentialData
import com.equs.credentials.VcFormat
import com.equs.credentials.FixtureKey
import com.equs.credentials.fixtureDidKey
import com.equs.credentials.setJniLibPath
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals
import com.equs.credentials.parseClaims as EqusSdkParseClaims


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
        val result = EqusSdkParseClaims(Credential(VcFormat.SD_JWT_VC, Fixtures.identitySdJwt))

        assertEquals("John", result["name"]?.trim('"'))
        assertEquals("1728882611", result["iat"])
        assertEquals("https://credentials.example.com/identity_credential", result["vct"]?.trim('"'))
        assertEquals(fixtureDidKey(FixtureKey.HOLDER), result["sub"]?.trim('"'))
        assertEquals(fixtureDidKey(FixtureKey.ISSUER), result["iss"]?.trim('"'))
        assertEquals("1760418611", result["exp"])
        assertEquals("1728882611", result["nbf"])
    }
}