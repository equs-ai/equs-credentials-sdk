package com.equs

import com.equs.credentials.FixtureKey
import com.equs.credentials.fixtureDidKey
import com.equs.credentials.fixtureDidKeyUrl
import com.equs.credentials.fixturePublicJwk
import com.equs.credentials.fixtureSdJwt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64

object Fixtures {
    fun kid(role: FixtureKey): String =
        Json.parseToJsonElement(fixturePublicJwk(role)).jsonObject["kid"]!!.jsonPrimitive.content

    fun base64Url(text: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray())

    /** Payload of the last KB-SD-JWT link of a dSD-JWT grant. */
    fun lastLinkPayload(grant: String): JsonObject {
        val link = grant.split("~").last { it.isNotEmpty() }
        return Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(link.split(".")[1]))).jsonObject
    }

    val identitySdJwt: String by lazy {
        fixtureSdJwt(
            """{"typ":"vc+sd-jwt","alg":"ES256","kid":"${fixtureDidKeyUrl(FixtureKey.ISSUER)}"}""",
            """{"vct":"https://credentials.example.com/identity_credential","sub":"${fixtureDidKey(FixtureKey.HOLDER)}","nbf":1728882611,"_sd_alg":"sha-256","iss":"${fixtureDidKey(FixtureKey.ISSUER)}","iat":1728882611,"exp":1760418611,"cnf":{"jwk":${fixturePublicJwk(FixtureKey.HOLDER)}}}""",
            listOf("""["8zQfBB-KqYHuJqnpTDvsUQ", "name", "John"]"""),
            FixtureKey.ISSUER,
        )
    }
}
