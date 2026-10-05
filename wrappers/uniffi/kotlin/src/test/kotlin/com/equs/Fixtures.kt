package com.equs

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File

/**
 * Reads the generated fixture bundle (`equs-test-fixtures`'s `fixture_gen` binary output) from
 * the path in `EQUS_FIXTURE_BUNDLE`, the same mechanism the TypeScript suites use
 * (`wrappers/test/js_common/test/bundle.ts`).
 *
 * The Gradle `fixtureGen` task runs the generator and sets this variable on the `test` task, so a
 * `./gradlew test` run never sees it unset. A developer running a single test through an IDE (which
 * bypasses Gradle's task graph) needs to run `./gradlew fixtureGen` once first, or set the variable
 * themselves; the error message below says so.
 */
object Fixtures {
    private const val GENERATE_HINT =
        "run: cd wrappers/uniffi/kotlin && ./gradlew fixtureGen (or ./gradlew test, which depends on it)"

    private val bundle: JsonObject by lazy {
        val path = System.getenv("EQUS_FIXTURE_BUNDLE")
            ?: error("EQUS_FIXTURE_BUNDLE unset — $GENERATE_HINT")

        val text = try {
            File(path).readText()
        } catch (cause: java.io.FileNotFoundException) {
            throw IllegalStateException("fixture bundle missing at $path — $GENERATE_HINT", cause)
        }

        Json.parseToJsonElement(text).jsonObject
    }

    fun token(name: String): String =
        bundle[name]?.jsonPrimitive?.content
            ?: error("fixture $name is not a token")

    /**
     * A naive, unverified decode of a compact JWS's payload segment — the same trick the
     * TypeScript suites' `jwt-decode` performs. Used only to pull a claim (e.g. `sub`) out of a
     * bundle token whose subject is a fresh random DID on every generation, so a test can assert
     * against it without hardcoding a value the bundle can no longer produce.
     */
    fun claim(token: String, name: String): String? {
        val payload = token.substringAfter(".").substringBefore(".")
        val json = String(java.util.Base64.getUrlDecoder().decode(payload))
        return Json.parseToJsonElement(json).jsonObject[name]?.jsonPrimitive?.content
    }
}
