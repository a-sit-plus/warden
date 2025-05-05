package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.data.AttestationCreator
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

class GeneratedAttestationTests : FreeSpec(
    {

        val challenge = "42".encodeToByteArray()
        val packageName = "fa.ke.it.till.you.make.it"
        val signatureDigest = Random.nextBytes(32)
        val appVersion = 5
        val androidVersion = 11

        val attestationProof = AttestationCreator.createAttestation(
            challenge,
            packageName,
            signatureDigest,
            appVersion,
            androidVersion
        )

        val attestationService = Warden(
            androidAttestationConfiguration = AndroidAttestationConfiguration(
                applications = listOf(
                    AndroidAttestationConfiguration.AppData(
                        packageName = packageName,
                        signatureDigests = listOf(signatureDigest),
                        appVersion = appVersion
                    )
                ),
                androidVersion = androidVersion,
                patchLevel = PatchLevel(2021, 8),
                requireStrongBox = false,
                allowBootloaderUnlock = false,
                ignoreLeafValidity = false,
                hardwareAttestationTrustAnchors = setOf(attestationProof.last().publicKey)
            ),
            iosAttestationConfiguration = IOSAttestationConfiguration(
                applications = listOf(
                    IOSAttestationConfiguration.AppData(
                        teamIdentifier = "9CYHJNG644",
                        bundleIdentifier = "at.asitplus.attestation-client"
                    )
                )
            )
        )

        "Generated Attestation Test" {
            attestationService.verifyAttestation(attestationProof = attestationProof.map { it.encoded }, challenge)
                .shouldBeInstanceOf<AttestationResult.Android.Verified>().attestationCertificate shouldBe attestationProof.first()

            val dbg = attestationService.collectDebugInfo(attestationProof.map { it.encoded }, challenge).serialize()

            WardenDebugAttestationStatement.deserialize(dbg).replayGenericAttestation()
                .shouldBeInstanceOf<AttestationResult.Android.Verified>().attestationCertificate shouldBe attestationProof.first()
        }

    })