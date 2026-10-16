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
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

object Fixtures {
    fun kid(role: FixtureKey): String =
        Json.parseToJsonElement(fixturePublicJwk(role)).jsonObject["kid"]!!.jsonPrimitive.content

    fun base64Url(text: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray())

    /** Header and payload of a compact JWT. */
    data class JwtParts(val header: JsonObject, val payload: JsonObject)

    fun jwtParts(jwt: String): JwtParts {
        val (header, payload) = jwt.split(".").take(2)
            .map { Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(it))).jsonObject }
        return JwtParts(header, payload)
    }

    /** base64url SHA-256 of [text], the SD-JWT digest. */
    fun sha256(text: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.toByteArray()))

    /** The `cnf.jwk` of an issuer-signed JWT: the key its holder signs with. */
    fun cnfJwk(jwt: String): JsonObject = jwtParts(jwt).payload["cnf"]!!.jsonObject["jwk"]!!.jsonObject

    /** Whether [jws] carries a valid ES256 signature by the P-256 [jwk]. */
    fun verifiesEs256(jws: String, jwk: JsonObject): Boolean {
        val (header, payload, signature) = jws.split(".")
        fun coordinate(name: String) = BigInteger(1, Base64.getUrlDecoder().decode(jwk[name]!!.jsonPrimitive.content))
        val curve = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val key = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(ECPoint(coordinate("x"), coordinate("y")), curve))
        return Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(key)
            update("$header.$payload".toByteArray())
            verify(Base64.getUrlDecoder().decode(signature))
        }
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
