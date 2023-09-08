package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.data.AttestationData
import com.google.android.attestation.ParsedAttestationRecord
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.datetime.toKotlinInstant
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.time.Duration.Companion.days


@OptIn(ExperimentalStdlibApi::class)
class DefaultAttestationServiceTest : FreeSpec() {

    private val theGood = androidGood + iosGood

    init {
        "The Good" - {
            theGood.forEach { recordedAttestation ->
                recordedAttestation.name - {
                    "OK" - {
                        "no version check" - {
                            attestationService(
                                androidVersion = null,
                                iosVersion = null,
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                )
                            ).apply {
                                "Generic" {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).apply {
                                        also { println(it) }
                                        shouldNotBeInstanceOf<AttestationResult.Error>()
                                    }
                                }
                                "Key Attestation" {
                                    verifyKeyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                        recordedAttestation.publicKey!!
                                    ).apply {
                                        also { println(it) }
                                        isSuccess.shouldBeTrue()
                                        attestedPublicKey.shouldNotBeNull()
                                        attestedPublicKey!!.encoded shouldBe recordedAttestation.publicKey?.encoded
                                    }
                                }
                            }
                        }

                        "time drift" - {
                            withData(nameFn = {
                                "${
                                    recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                } + ${it.toIsoString()}"
                            }, 3000.days, (-3000).days) { leeway ->
                                attestationService(
                                    androidPatchLevel = null,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant() - leeway
                                    ),
                                    offset = leeway
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).apply {
                                    shouldNotBeInstanceOf<AttestationResult.Error>()
                                }
                            }
                        }
                    }

                    "Fail" - {

                        "time of verification" - {
                            "too early" {
                                attestationService(
                                    unlockedBootloaderAllowed = false,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant() - 3000.days
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                            }

                            "too late" {
                                attestationService(
                                    unlockedBootloaderAllowed = false,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant() + 3000.days
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                            }
                        }

                        "package name / bundle identifier" {
                            attestationService(
                                androidPackageName = "org.wrong.package.name",
                                iosBundleIdentifier = "org.wrong.bundle.identifier",
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant()
                                        .toKotlinInstant()
                                )
                            ).verifyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge
                            ).shouldBeInstanceOf<AttestationResult.Error>()
                                .cause.shouldBeInstanceOf<AttestationException.Content>()
                        }

                        "OS Version" {
                            attestationService(
                                androidVersion = 200000,
                                iosVersion = "99.0",
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant()
                                        .toKotlinInstant()
                                )
                            ).verifyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge
                            ).apply {
                                shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }
                        }

                        "Key Attestation PubKey Mismatch" {
                            attestationService(
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant()
                                        .toKotlinInstant()
                                )
                            ).verifyKeyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge,
                                KeyPairGenerator.getInstance("EC")
                                    .apply {
                                        initialize(ECGenParameterSpec("secp256r1"))
                                    }.genKeyPair().public
                            ).apply {
                                isSuccess.shouldBeFalse()
                                details.shouldBeInstanceOf<AttestationResult.Error>().also { println(it) }
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }
                        }
                    }
                }
            }

            "iOS Specific" - {
                iosGood.forEach { recordedAttestation ->
                    recordedAttestation.name - {
                        "OK" - {
                            withData("14", "15.0.1", "16", "16.0.2", "16.2", "16.2.0") { version ->
                                attestationService(
                                    iosVersion = version,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).apply {
                                    also { println(it) }
                                    shouldBeInstanceOf<AttestationResult.IOS>()
                                }
                            }
                        }
                    }


                    "Fail" - {

                        "borked team identifier" {
                            attestationService(
                                iosTeamIdentifier = "1234567890",
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant()
                                        .toKotlinInstant()
                                )
                            ).verifyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge
                            ).apply {
                                shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()

                            }
                        }
                    }
                }
            }



            "Android Specific" - {
                androidGood.forEach { recordedAttestation ->
                    recordedAttestation.name - {
                        "OK" - {
                            "no patch level" {
                                attestationService(
                                    androidPatchLevel = null,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                            }

                            "enforce locked bootloader" {
                                attestationService(
                                    unlockedBootloaderAllowed = false,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                            }

                            "allow unlocked bootloader" {
                                attestationService(
                                    unlockedBootloaderAllowed = true,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                            }
                        }


                        "Wrongfully disabled HW attestation" - {
                            val clock =
                                FixedTimeClock(recordedAttestation.verificationDate.toInstant().toKotlinInstant())
                            "Software-Only" {
                                DefaultAttestationService(
                                    androidAttestationConfiguration = AndroidAttestationConfiguration(
                                        listOf(
                                            AndroidAttestationConfiguration.AppData(
                                                ANDROID_PACKAGE_NAME,
                                                ANDROID_SIGNATURE_DIGESTS
                                            )
                                        ),
                                        disableHardwareAttestation = true,
                                        enableSoftwareAttestation = true,
                                        ignoreLeafValidity = true
                                    ),
                                    DEFAULT_IOS_ATTESTATION_CFG,
                                    clock = clock
                                ).apply {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).shouldBeInstanceOf<AttestationResult.Error>()
                                        .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                                }
                            }

                            "Nougat attestation" {
                                DefaultAttestationService(
                                    androidAttestationConfiguration = AndroidAttestationConfiguration(
                                        listOf(
                                            AndroidAttestationConfiguration.AppData(
                                                ANDROID_PACKAGE_NAME,
                                                ANDROID_SIGNATURE_DIGESTS
                                            )
                                        ),
                                        disableHardwareAttestation = true,
                                        enableNougatAttestation = true,
                                        ignoreLeafValidity = true
                                    ),
                                    DEFAULT_IOS_ATTESTATION_CFG,
                                    clock = clock
                                ).apply {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).shouldBeInstanceOf<AttestationResult.Error>()
                                        .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                                }
                            }
                            "Software + Nougat attestation" {
                                DefaultAttestationService(
                                    androidAttestationConfiguration = AndroidAttestationConfiguration(
                                        listOf(
                                            AndroidAttestationConfiguration.AppData(
                                                ANDROID_PACKAGE_NAME,
                                                ANDROID_SIGNATURE_DIGESTS
                                            )
                                        ),
                                        disableHardwareAttestation = true,
                                        enableNougatAttestation = true,
                                        enableSoftwareAttestation = true,
                                        ignoreLeafValidity = true
                                    ),
                                    DEFAULT_IOS_ATTESTATION_CFG,
                                    clock = clock
                                ).apply {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).shouldBeInstanceOf<AttestationResult.Error>().also { println(it) }
                                        .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                                }
                            }
                        }

                        "Fail" - {
                            "borked cert chain" - {
                                withData(
                                    listOf(0, 0, 0),
                                    listOf(0, 1, 0),
                                    listOf(0, 2, 1)

                                ) {
                                    val chain = recordedAttestation.attestationProof.slice(it)
                                    attestationService(
                                        unlockedBootloaderAllowed = false,
                                        timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                        )
                                    ).verifyAttestation(
                                        chain,
                                        recordedAttestation.challenge
                                    ).apply {//makes interactive debugging easier
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                                    }

                                    attestationService(
                                        unlockedBootloaderAllowed = false,
                                        timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                        )
                                    ).verifyAttestation(
                                        chain,
                                        recordedAttestation.challenge
                                    ).apply {//makes interactive debugging easier
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                                    }

                                    attestationService(
                                        unlockedBootloaderAllowed = false,
                                        timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                        )
                                    ).verifyAttestation(
                                        chain,
                                        recordedAttestation.challenge
                                    ).apply { //makes interactive debugging easier
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                                    }
                                }
                            }

                            "require StrongBox" {
                                attestationService(
                                    requireStrongBox = true,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }

                            "wrong signature digests" {
                                attestationService(
                                    androidAppSignatureDigest = listOf(
                                        byteArrayOf(0, 32, 55, 29, 120, 22, 0),
                                        /*this one's an invalid digest and must not affect the tests*/
                                        "LvfTC77F/uSecSfJDeLdxQ3gZrVLHX8+NNBp7AiUO0E=".decodeBase64ToArray()!!
                                    ), timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }

                            //just to check whether this propagates
                            "no signature digests, cannot instantiate" {
                                shouldThrow<at.asitplus.attestation.android.exceptions.AttestationException> {
                                    attestationService(
                                        androidAppSignatureDigest = listOf(), timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant()
                                                .toKotlinInstant()
                                        )
                                    )
                                }
                            }

                            "app version" {
                                attestationService(
                                    androidAppVersion = 200000,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()

                            }

                            "patch level" {
                                attestationService(
                                    androidPatchLevel = PatchLevel(2030, 1),
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }

                            "rollback resistance" {
                                attestationService(
                                    requireRollbackResistance = true,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }
                        }
                    }
                }
            }
        }

        "The Bad" - {
            "Software-Only Keystore" - {
                AttestationData(
                    "Android Emulator",
                    challengeB64 = "RN9CjU7I5zpvCh7D3vi/aA==",
                    attestationProofB64 = listOf(
                        """MIIC+jCCAqCgAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVB
                    AgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZ
                    DE7MDkGA1UEAwwyQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlc
                    m1lZGlhdGUwHhcNNzAwMTAxMDAwMDAwWhcNNjkxMjMxMjM1OTU5WjAfMR0wGwYDVQQDDBRBb
                    mRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIEAthaOZ2+nZ
                    ZyYdoeLYNL5yZozzfMdrfrZcG2RI1juriVparubkzxZGCs4KcReh1aDhWFsDxQWYAeJLcFN8
                    rOjggFhMIIBXTALBgNVHQ8EBAMCB4AwggErBgorBgEEAdZ5AgERBIIBGzCCARcCAQQKAQACA
                    SkKAQAEEETfQo1OyOc6bwoew974v2gEADCB8qEIMQYCAQICAQOiAwIBA6MEAgIBAKUIMQYCA
                    QICAQSqAwIBAb+DdwIFAL+FPQgCBgGHj7zJmL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAA
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                    AAAAAAAAL+FQQUCAwGtsL+FQgUCAwMVG7+FRU8ETTBLMSUwIwQeYXQuYXNpdHBsdXMuYXR0Z
                    XN0YXRpb25fY2xpZW50AgEBMSIEIDS5dixNbJDUhDGUDFe95zFCWLJkIO/hasf3J08NMwrVM
                    AAwHwYDVR0jBBgwFoAUP/ys1hqxOp6BILjVJRzFZbsekakwCgYIKoZIzj0EAwIDSAAwRQIgW
                    CsSigJsOLe9hli462AL/TuPqLuuIKelSVEe/PsnrWUCIQC+JExSC5l3slEBhDKxMD3otjwr0
                    DK0Jav50CzyK80ILg==
                    """,
                        """MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDV
                    QQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nb
                    GUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU
                    29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2M
                    DlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ
                    2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlI
                    FNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49A
                    wEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZ
                    jW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfB
                    gNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA
                    1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqR
                    Z9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7
                    """,
                        """MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVU
                    zETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UEC
                    gwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtle
                    XN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwM
                    TA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVB
                    AcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kc
                    m9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb
                    290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/S
                    Q59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEF
                    Mit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPM
                    A8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho
                    ++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytT
                    ySn502vQX3xvw==
                    """
                    ),
                    isoDate = "2023-04-18T00:00:00Z",
                    pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgQC2Fo5nb6dlnJh2h4tg0vnJmjPN8x2t+tlwbZEjWO6uJWlqu5uTPFkYKzgpxF6HVoOFYWwPFBZgB4ktwU3ysw=="
                ).apply {

                    val clock = FixedTimeClock(verificationDate.toInstant().toKotlinInstant())
                    "HW Attestation should fail" {
                        attestationService(
                            timeSource = clock
                        ).verifyAttestation(
                            attestationProof,
                            challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                    }

                    "Nougat Hybrid attestation should fail" {
                        DefaultAttestationService(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        ANDROID_PACKAGE_NAME,
                                        ANDROID_SIGNATURE_DIGESTS
                                    )
                                ),
                                disableHardwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                attestationProof,
                                challenge
                            ).shouldBeInstanceOf<AttestationResult.Error>()
                                .cause.shouldBeInstanceOf<AttestationException.Content>()
                        }
                    }

                    "HW Attestation and Nougat Hybrid attestation combined should fail" {
                        DefaultAttestationService(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        ANDROID_PACKAGE_NAME,
                                        ANDROID_SIGNATURE_DIGESTS
                                    )
                                ),
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                attestationProof,
                                challenge
                            ).shouldBeInstanceOf<AttestationResult.Error>()
                                .cause.shouldBeInstanceOf<AttestationException.Content>()
                        }
                    }

                    "Software attestation should work" - {

                        "stand-alone" {
                            DefaultAttestationService(
                                androidAttestationConfiguration = AndroidAttestationConfiguration(
                                    listOf(
                                        AndroidAttestationConfiguration.AppData(
                                            ANDROID_PACKAGE_NAME,
                                            ANDROID_SIGNATURE_DIGESTS
                                        )
                                    ),
                                    disableHardwareAttestation = true,
                                    enableSoftwareAttestation = true,
                                    ignoreLeafValidity = true
                                ),
                                DEFAULT_IOS_ATTESTATION_CFG,
                                clock = clock
                            ).apply {
                                verifyAttestation(
                                    attestationProof,
                                    challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                                    .attestationRecord
                            }
                        }

                        "with Nougat attestation" {
                            DefaultAttestationService(
                                androidAttestationConfiguration = AndroidAttestationConfiguration(
                                    listOf(
                                        AndroidAttestationConfiguration.AppData(
                                            ANDROID_PACKAGE_NAME,
                                            ANDROID_SIGNATURE_DIGESTS
                                        )
                                    ),
                                    disableHardwareAttestation = true,
                                    enableNougatAttestation = true,
                                    enableSoftwareAttestation = true,
                                    ignoreLeafValidity = true
                                ),
                                DEFAULT_IOS_ATTESTATION_CFG,
                                clock = clock
                            ).apply {
                                verifyAttestation(
                                    attestationProof,
                                    challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                                    .attestationRecord
                            }
                        }

                        "with Nougat and HW attestation" {
                            DefaultAttestationService(
                                androidAttestationConfiguration = AndroidAttestationConfiguration(
                                    listOf(
                                        AndroidAttestationConfiguration.AppData(
                                            ANDROID_PACKAGE_NAME,
                                            ANDROID_SIGNATURE_DIGESTS
                                        )
                                    ),
                                    enableNougatAttestation = true,
                                    enableSoftwareAttestation = true,
                                    ignoreLeafValidity = true
                                ),
                                DEFAULT_IOS_ATTESTATION_CFG,
                                clock = clock
                            ).apply {
                                verifyAttestation(
                                    attestationProof,
                                    challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                                    .attestationRecord
                            }
                        }
                    }
                }
            }

            "Nougat to Oreo (LineageOS) bq Aquaris X" - {
                val data = AttestationData(
                    "bq Aquaris X with LineageOS",
                    "foobdar".encodeToByteArray().encodeBase64(),
                    listOf(
                        "MIICkDCCAjagAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDE7MDkGA1UEAwwyQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoX5eWkxsJOk2z6S5tclt6bOyJhS3b+2+ULx3O3zZAwFNrbWP52YnQzp/lsexI99lx/Z5NRzJ9x0aDLdIcR/AyqOB9jCB8zALBgNVHQ8EBAMCB4AwgcIGCisGAQQB1nkCAREEgbMwgbACAQIKAQACAQEKAQEEB2Zvb2JkYXIEADBev4U9BwIFAKtq1Vi/hUVPBE0wSzElMCMEHmNvbS5leGFtcGxlLnRydXN0ZWRhcHBsaWNhdGlvbgIBATEiBCCI5cOT6u82gpgAtB33hqUv8KWCFYUMqKZQc4Wa3PAZDzA3oQgxBgIBAgIBA6IDAgEDowQCAgEApQgxBgIBAAIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FPwIFADAfBgNVHSMEGDAWgBQ//KzWGrE6noEguNUlHMVlux6RqTAKBggqhkjOPQQDAgNIADBFAiBiMBtVeUV4j1VOiRU8DnGzq9/xtHfl0wra1xnsmxG+LAIhAJAroVhVcxxItgYZEMN1AaWqmZUXFtktQeLXh7u2F3d+",
                        "MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7",
                        "MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw=="
                    ),
                    isoDate = "2023-09-10T00:00:00Z"
                )
                val signatureDigests = listOf(
                    "88E5C393EAEF36829800B41DF786A52FF0A58215850CA8A65073859ADCF0190F".hexToByteArray(HexFormat.UpperCase)
                )
                val packageName = "com.example.trustedapplication"

                val clock = FixedTimeClock(data.verificationDate.toInstant().toKotlinInstant())

                "Nougat Hybrid attestation should work" - {
                    "stand-alone" {
                        DefaultAttestationService(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                disableHardwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }

                        }
                    }


                    "with Hardware attestation" {
                        DefaultAttestationService(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }

                        }
                    }

                    "with Hardware + Sowftware Attestation " {
                        DefaultAttestationService(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                enableSoftwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }

                        }
                    }

                    "with Software Attestation" {
                        DefaultAttestationService(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                disableHardwareAttestation = true,
                                enableSoftwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }

                        }
                    }
                }

                "Hardware attestation should fail" {
                    DefaultAttestationService(
                        androidAttestationConfiguration = AndroidAttestationConfiguration(
                            listOf(
                                AndroidAttestationConfiguration.AppData(
                                    packageName,
                                    signatureDigests
                                )
                            ),
                            ignoreLeafValidity = true
                        ),
                        DEFAULT_IOS_ATTESTATION_CFG,
                        clock = clock
                    ).apply {
                        verifyAttestation(
                            data.attestationProof,
                            data.challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Certificate>()
                    }
                }

                "Hardware + SW attestation should fail" {
                    DefaultAttestationService(
                        androidAttestationConfiguration = AndroidAttestationConfiguration(
                            listOf(
                                AndroidAttestationConfiguration.AppData(
                                    packageName,
                                    signatureDigests
                                )
                            ),
                            enableSoftwareAttestation = true,
                            ignoreLeafValidity = true
                        ),
                        DEFAULT_IOS_ATTESTATION_CFG,
                        clock = clock
                    ).apply {
                        verifyAttestation(
                            data.attestationProof,
                            data.challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                    }
                }

                "SW attestation should fail" {
                    DefaultAttestationService(
                        androidAttestationConfiguration = AndroidAttestationConfiguration(
                            listOf(
                                AndroidAttestationConfiguration.AppData(
                                    packageName,
                                    signatureDigests
                                )
                            ),
                            disableHardwareAttestation = true,
                            enableSoftwareAttestation = true,
                            ignoreLeafValidity = true
                        ),
                        DEFAULT_IOS_ATTESTATION_CFG,
                        clock = clock
                    ).apply {
                        verifyAttestation(
                            data.attestationProof,
                            data.challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                    }
                }
            }

            //TODO bootloader unlocked
            //TODO jailbroken iphone
        }

        "And the Samsung" {
            //TODO eternal leaves for samsung devices
        }
    }
}

