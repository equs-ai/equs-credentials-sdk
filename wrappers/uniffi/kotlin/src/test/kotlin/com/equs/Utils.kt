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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

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
        val payload = Json.parseToJsonElement(
            String(java.util.Base64.getUrlDecoder().decode(sdJwt.split(".")[1]))
        ).jsonObject

        assertEquals("John", result["name"]?.trim('"'))
        assertEquals(payload["iat"]?.jsonPrimitive?.content, result["iat"])
        assertEquals(payload["vct"]?.jsonPrimitive?.content, result["vct"]?.trim('"'))
        assertEquals(payload["sub"]?.jsonPrimitive?.content, result["sub"]?.trim('"'))
        assertEquals(payload["iss"]?.jsonPrimitive?.content, result["iss"]?.trim('"'))
        assertEquals(payload["exp"]?.jsonPrimitive?.content, result["exp"])
        assertEquals(payload["nbf"]?.jsonPrimitive?.content, result["nbf"])
    }
}