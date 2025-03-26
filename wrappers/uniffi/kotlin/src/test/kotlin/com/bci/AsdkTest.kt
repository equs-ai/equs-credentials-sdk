import com.bci.asdk.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

const val DID = "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6"
const val DID_DOCUMENT = "{" +
        "\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/multikey/v1\"]," +
        "\"id\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"," +
        "\"authentication\":[\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"]," +
        "\"assertionMethod\":[\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"]," +
        "\"verificationMethod\":[{\"id\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"," +
        "\"type\":\"Multikey\"," +
        "\"controller\":\"did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"," +
        "\"publicKeyMultibase\":\"zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6\"}]" +
        "}"

class AsdkTest {

    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            setJniLibPath()
        }
    }

    @Test
    fun testResolve() = runTest {
        val universalDidResolver = UniversalDidResolver()

        val expected = DidResolution(
            document = DID_DOCUMENT,
            documentMetadata = DidDocMetadata(deactivated = null),
            metadata = DidMetadata(contentType = "application/did+ld+json")
        )

        val actual = universalDidResolver.resolve(DID)

        assertEquals(expected, actual)
    }
    
    @Test
    fun testResolveVerificationMethod() = runTest {
        val universalDidResolver = UniversalDidResolver()

        val expected = VerificationMethod(
            id = "$DID#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6",
            type = "Multikey",
            controller = DID,
            properties = mapOf("publicKeyMultibase" to "zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6"),
        )
        
        val actual = universalDidResolver.resolveVerificationMethod(DID)

        assertEquals(expected, actual)
    }
}