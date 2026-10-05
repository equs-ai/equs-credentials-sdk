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
        val sdJwt = Fixtures.token("vc")
        val result = EqusSdkParseClaims(Credential(VcFormat.SD_JWT_VC, sdJwt))

        // Independent expectation: a naive, unverified decode of the payload segment
        // (registered claims only -- "name" sits behind a disclosure `parseClaims` must merge
        // itself, so it isn't visible here). `name: "John"` is a fixed default the fixture
        // crate's SD-JWT VC builder always discloses; everything else (`sub`/`iss`/timestamps)
        // is a fresh value on every bundle regeneration.
        assertEquals("John", result["name"]?.trim('"'))
        assertEquals(Fixtures.claim(sdJwt, "iat"), result["iat"])
        assertEquals(Fixtures.claim(sdJwt, "vct"), result["vct"]?.trim('"'))
        assertEquals(Fixtures.claim(sdJwt, "sub"), result["sub"]?.trim('"'))
        assertEquals(Fixtures.claim(sdJwt, "iss"), result["iss"]?.trim('"'))
        assertEquals(Fixtures.claim(sdJwt, "exp"), result["exp"])
        assertEquals(Fixtures.claim(sdJwt, "nbf"), result["nbf"])
    }
}