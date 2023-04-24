package at.asitplus.attestation

import at.asitplus.attestation.data.AttestationData
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.core.spec.style.scopes.FreeSpecContainerScope
import io.kotest.datatest.withData
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Test
import java.security.Security
import java.security.interfaces.ECPublicKey
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class TemporalOffsetTest : FreeSpec() {

    private val exactStartOfValidity: Map<String, AttestationData> = mapOf(
        "iOS" to ios16,
        "KeyMint 200" to pixel6KeyMint200Good
    )

    init {
        "Exact Time of Validity" - {
            withData(exactStartOfValidity) {
                attestationService(timeSource = FixedTimeClock(it.verificationDate.time)).verifyAttestation(
                    it.attestationProof,
                    it.challenge
                ).apply {
                    shouldNotBeInstanceOf<AttestationResult.Error>()
                }
            }
        }

        "Exact Time of Validity + 1D" - {
            withData(exactStartOfValidity) {
                attestationService(
                    timeSource = FixedTimeClock(it.verificationDate.time),
                    offset = 1.days
                ).verifyAttestation(
                    it.attestationProof,
                    it.challenge,
                ).apply {
                    shouldNotBeInstanceOf<AttestationResult.Error>()
                }
            }
        }

        "Exact Time of Validity - 1D" - {
            withData(exactStartOfValidity) {
                attestationService(
                    timeSource = FixedTimeClock(it.verificationDate.time),
                    offset = (-1).days
                ).verifyAttestation(
                    it.attestationProof,
                    it.challenge,
                ).apply {
                    shouldBeInstanceOf<AttestationResult.Error>()
                        .cause.shouldBeInstanceOf<AttestationException.Certificate>()

                }
            }
        }

        "KeyMint eternal leaves - 1D" - {
            withData("eternal" to true, "expiring" to false) {
                attestationService(
                    timeSource = FixedTimeClock(pixel6KeyMint200Good.verificationDate.time),
                    offset = (-1).days
                ).verifyAttestation(
                    pixel6KeyMint200Good.attestationProof,
                    pixel6KeyMint200Good.challenge,
                ).apply {
                    shouldBeInstanceOf<AttestationResult.Error>()
                        .cause.shouldBeInstanceOf<AttestationException.Certificate>()

                }
            }

        }
    }
}


