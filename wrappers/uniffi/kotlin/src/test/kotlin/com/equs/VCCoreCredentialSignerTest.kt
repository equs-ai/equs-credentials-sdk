package com.equs

import com.equs.sdk.DidKey
import com.equs.sdk.InMemKms
import com.equs.sdk.KeyType
import com.equs.sdk.UniversalDidResolver
import com.equs.sdk.VcCoreCredentialSigner
import com.equs.sdk.VcFormat
import com.equs.sdk.createDidAndKeyMetadata
import com.equs.sdk.setJniLibPath
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class VCCoreCredentialSignerTest {
    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun signsSdJwtUnsignedViaExternallyTaggedWireFormat() = runTest {
        val kms = InMemKms()

        val issuer = createDidAndKeyMetadata(kms)
        val holder = createDidAndKeyMetadata(kms)

        val holderJwk = kms.get(holder.keyMetadata.kid).inner.jwk()
            ?: fail("holder key handle should expose a JWK")

        val now = System.currentTimeMillis() / 1000
        val claims = mapOf(
            "iss" to issuer.did,
            "sub" to holder.did,
            "vct" to "https://example.com/credentials/test",
            "iat" to now,
            "nbf" to now,
            "exp" to now + 60 * 60 * 24 * 365,
            "name" to "Alice",
        )
        val claimsJson = claims.entries.joinToString(prefix = "{", postfix = "}") { (k, v) ->
            val value = when (v) {
                is String -> "\"$v\""
                else -> v.toString()
            }
            "\"$k\":$value"
        }

        val unsignedJson = """
            {
              "SdJwt": {
                "claims": $claimsJson,
                "disclosure_strategy": "AllLevels",
                "holder_key": $holderJwk,
                "extra_headers": {
                  "typ": "vc+sd-jwt",
                  "kid": "${issuer.keyMetadata.didUrl}"
                },
                "issuer_key_id": "${issuer.keyMetadata.kid}"
              }
            }
        """.trimIndent()

        val signer = VcCoreCredentialSigner(kms, UniversalDidResolver(null))

        val credential = signer.signCredential(unsignedJson)

        assertEquals(VcFormat.SD_JWT_VC, credential.format)
        // Compact SD-JWT: 3 base64url segments separated by '.', then disclosures with '~'.
        assertTrue(
            credential.payload.matches(Regex("""^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~.*""")),
            "unexpected SD-JWT payload shape: ${credential.payload}",
        )
    }
}
