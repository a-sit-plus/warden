import at.asitplus.attestation.decodeBase64ToArray
import at.asitplus.attestation.parseToPublicKey
import at.asitplus.attestation.toAnsi
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import java.security.interfaces.ECPublicKey

class KeyConversionTests : FreeSpec({
    "Given an X509-encoded key" - {
        val x509Key =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFT1XwEeF8NftY84GfnqTFBoxHNkdG7wZHcOkLKwT4W6333Jqmga1XkKySq/ApnslBPNZE1Os363SAv8X85ZIrQ==".decodeBase64ToArray()
        "it should be parsable" - {
            val parsedKey = x509Key.parseToPublicKey()
            "and encodable to ANSI X9.62" - {
                val ansBytes = (parsedKey as ECPublicKey).toAnsi()
                "and decodable" - {
                    val decoded = ansBytes.parseToPublicKey()
                    "to match the original X5095-encoded key" {
                        decoded.encoded shouldBe x509Key
                    }
                }
            }
        }
    }
})