package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationChecker
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.assertion.AssertionChallengeValidator
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.receipt.ReceiptException
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.google.android.attestation.ParsedAttestationRecord
import kotlinx.datetime.Clock
import net.swiftzer.semver.SemVer
import org.bouncycastle.cert.X509CertificateHolder
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.*
import kotlin.time.Duration
import kotlin.time.toJavaDuration
import kotlin.time.toKotlinDuration
import at.asitplus.attestation.AttestationException as AttException

/**
 * Configuration class for Apple App Attestation
 */
data class IOSAttestationConfiguration @JvmOverloads constructor(

    /**
     * Nomen est omen
     */
    val teamIdentifier: String,

    /**
     * Nomen est omen
     */
    val bundleIdentifier: String,

    /**
     * Specifies whether the to-be-attested app targets a production or sandbox environment
     */
    val sandbox: Boolean = false,

    /**
     * Optional parameter. If present the iOS version of the attested app must be greater or equal to this parameter
     * Uses [SemVer](https://semver.org/) syntax
     */
    val iosVersion: String? = null,
)

interface AttestationService {

    /**
     * Convenience method to verifies both Android Key Attestation or Apple App Attestation
     * structures of the client (in [attestationProof]) if the device can be verified and [challenge] matches
     * the attestation challenge. On Android, this is simply the certificate chain from the attestation certificate
     * (i.e. the certificate corresponding to the key to be attested) up to one of the [Google hardware attestation root
       certificates](https://developer.android.com/training/articles/security-key-attestation#root_certificate).
     * on iOS this contains at least the [AppAttest attestation statement](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643).
     * Calls [verifyAttestationAndroid] or [verifyAttestationApple] depending on the kind of attestation proof prpvoded.
     *
     * For iOS clients it is optionally possible to pass [clientData]. In this case [attestationProof] must also
     * contain an [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * at index `1`, which, by default, is verified to match [clientData].
     * The signature counter in the attestation must be `0` and the signature counter in the assertion must be `1`.
     *
     * Passing a public key created in the same app on the iDevice's secure hardware as [clientData] effectively
     * emulates Android's key attestation: Attesting such a secondary key through an assertion, proves that
     * it was also created within the same app, on the same device, resulting in an attested key, which can then be used
     * for general-purpose crypto. **BEWARE if you pass the public key on iOS to be signed as is. iOS uses the ANSI X9.63
     * format represent public keys, so conversion is needed**
     *
     * @see verifyAttestationApple
     * @see verifyAttestationAndroid
     *
     * @return [AttestationResult] indicating whether Android or iOS was successfully attested,
     * [AttestationResult.Error] in case attestation failed
     */
    fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray? = null
    ): AttestationResult


    /**
     * Verifies key attestation for both Android and Apple devices.
     *
     *
     * Succeeds if attestation data structures of the client (in [attestationProof]) can be verified and [expectedChallenge] matches
     * the attestation challenge. For Android clients, this function Makes sure that [keyToBeAttested] matches the key contained in the attestation certificate.
     * For iOS this key needs to be specified explicitly anyhow to emulate key attestation
     *
     * @param attestationProof On Android, this is simply the certificate chain from the attestation certificate
     * (i.e. the certificate corresponding to the key to be attested) up to one of the [Google hardware attestation root
     * certificates](https://developer.android.com/training/articles/security-key-attestation#root_certificate).
     * on iOS this must contain the [AppAttest attestation statement](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643)
     * at index `0` and an [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * at index `1`, which, is verified for integrity and to match [keyToBeAttested].
     * The signature counter in the attestation must be `0` and the signature counter in the assertion must be `1`.
     *
     * Passing a public key created in the same app on the iDevice's secure hardware as `clientData` to create an assertion effectively
     * emulates Android's key attestation: Attesting such a secondary key through an assertion, proves that
     * it was also created within the same app, on the same device, resulting in an attested key, which can then be used
     * for general-purpose crypto. **BEWARE: supports only EC key on iOS (either the ANSI X9.63 encoded or DER encoded).
     * The key can be passed in either encoding to the secure enclave for assertion/attestation**
     *
     * @param expectedChallenge
     * @param keyToBeAttested
     *
     * @return [KeyAttestation] containing the attested public key on success or null in case of failure (see [KeyAttestation])
     */
    fun <T : PublicKey> verifyKeyAttestation(
        attestationProof: List<ByteArray>,
        expectedChallenge: ByteArray,
        keyToBeAttested: T
    ): KeyAttestation<T> =
        when (val firstTry = verifyAttestation(attestationProof, expectedChallenge, keyToBeAttested.encoded)) {
            is AttestationResult.Android -> {
                if (keyToBeAttested.encoded contentEquals firstTry.attestationCertificate.publicKey.encoded) KeyAttestation(
                    keyToBeAttested,
                    firstTry
                )
                else {
                    ("Android attestation failed: keyToBeAttested (${keyToBeAttested.encoded.encodeBase64()}) does not match " +
                            "key from attestation certificate: ${firstTry.attestationCertificate.publicKey.encoded.encodeBase64()}").let {
                        KeyAttestation(
                            null,
                            AttestationResult.Error(
                                explanation = it, cause = AttException.Content(platform = Platform.ANDROID, it)
                            )
                        )
                    }
                }
            }

            is AttestationResult.Error -> when (val secondTry =
                kotlin.runCatching {
                    verifyAttestation(attestationProof, expectedChallenge, (keyToBeAttested as ECPublicKey).toAnsi())
                }.getOrElse { return KeyAttestation(null, firstTry) }) {
                is AttestationResult.Android -> throw RuntimeException("WTF?")
                is AttestationResult.Error -> KeyAttestation(null, firstTry)
                is AttestationResult.IOS -> KeyAttestation(keyToBeAttested, secondTry)
            }

            is AttestationResult.IOS -> KeyAttestation(keyToBeAttested, firstTry)
        }


    /**
     * Groups ios-specific API to reduce toplevel clutter.
     *
     * Exposes iOS-specific functionality in a more expressive, and less confusing manner
     */
    val ios: IOS

    interface IOS {
        /**
         * convenience method for [verifyAttestation] specific to iOS, which only verifies App Attestation and no assertion
         * @param attestationObject the AppAttest attestation object to verify
         * @param challenge the challenge to verify against
         */
        fun verifyAppAttestation(
            attestationObject: ByteArray,
            challenge: ByteArray,
        ): AttestationResult

        /**
         * Verifies an App Attestation in conjunction with an assertion for some client data.
         *
         * First, it verifies the app attestation, afterwards it verifies, the assertion, checks whether at most [counter] many signatures
         * have been performed using the key bound to the attestation before signing the assertion and verifies whether the client data
         * referenced within the assertion matches [referenceClientData]
         *
         * @param attestationObject the AppAttest attestation object to verify
         * @param assertionFromDevice the assertion data created on the device.
         * @param referenceClientData the expected client data to be contained in [assertionFromDevice]
         * @param counter the highest expected value of the signature counter prior to creating the assertion.
         */
        fun verifyAssertion(
            attestationObject: ByteArray,
            assertionFromDevice: ByteArray,
            referenceClientData: ByteArray,
            challenge: ByteArray,
            counter: Long = 0
        ): AttestationResult
    }

    val android: Android

    interface Android {
        /**
         * convenience method for [verifyKeyAttestation] specific to Android. Attests the public key contained in the leaf
         * @param attestationCerts attestation certificate chain
         * @param expectedChallenge attestation challenge
         */
        fun verifyKeyAttestation(
            attestationCerts: List<X509Certificate>,
            expectedChallenge: ByteArray
        ): KeyAttestation<PublicKey>
    }
}

/**
 * Pairs an Apple [AppAttest](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
 * assertion with the referenced `clientData` value
 */
@JvmInline
value class AssertionData private constructor(private val pair: Pair<ByteArray, ByteArray>) {

    /**
     * Pairs an Apple AppAttest  assertion with the referenced clientData value
     */
    constructor(assertion: ByteArray, clientData: ByteArray) : this(assertion to clientData)

    val assertion get() = pair.first
    val clientData get() = pair.second
}

/**
 * Attestation result class. Successful results contain attested data.
 */
sealed class AttestationResult {
    /**
     * Successful Android Key Attestation result. [attestationCertificate] contains the attested certificate.
     *
     * All attested information in [attestationRecord] for further processing, should this be desired.
     * Note: this will fail when using the [NoopAttestationService]!
     */
    @Suppress("MemberVisibilityCanBePrivate")
    abstract class Android(val attestationCertificateChain: List<X509Certificate>) :
        AttestationResult() {
        abstract val attestationRecord: ParsedAttestationRecord

        val attestationCertificate by lazy { attestationCertificateChain.first() }

        internal class NOOP internal constructor(attestationCertificateChain: List<ByteArray>) :
            Android(attestationCertificateChain.mapNotNull { it.parseToCertificate() }) {
            override val attestationRecord: ParsedAttestationRecord by lazy {
                ParsedAttestationRecord.createParsedAttestationRecord(
                    attestationCertificateChain.mapNotNull { it.parseToCertificate() }
                )
            }
        }

        class Verified(attestationCertificateChain: List<X509Certificate>) : Android(attestationCertificateChain) {
            override val attestationRecord: ParsedAttestationRecord =
                ParsedAttestationRecord.createParsedAttestationRecord(
                    attestationCertificateChain
                )

        }
    }


    /**
     * Successful iOS attestation. If `clientData` and an assertion object were passed to
     * [AttestationService.verifyAttestation], it is contained in [clientData] for convenience.
     * The [DefaultAttestationService], returns [IOS.Verbose], also seting [attestation] and [assertion] (if
     * `clientData` was passed). The [NoopAttestationService] does not (which is useful to as it enables skipping any
     * and all attestation checks for unit testing, when used with dependency injection, for example.
     */
    @Suppress("MemberVisibilityCanBePrivate")
    open class IOS(val clientData: ByteArray?) : AttestationResult() {
        class Verbose(val attestation: ValidatedAttestation, val assertedClientData: Pair<ByteArray, Assertion>?) :
            IOS(assertedClientData?.first)
    }

    /**
     * Represents an attestation verification failure. Always contains an  [explanation] about what went wrong.
     */
    class Error(val explanation: String, val cause: AttException? = null) : AttestationResult() {
        override fun toString() = "Attestation Error: $explanation" + cause?.let { ". Cause: ${cause.message}" }
    }

}

/**
 * Result type returned by [AttestationService.verifyKeyAttestation].
 * [attestedPublicKey] contains attested public key if attestation was successful (null otherwise)
 * [details] contains the detailed attestation result (see [AttestationResult] for more details)
 *
 */
data class KeyAttestation<T : PublicKey> internal constructor(
    val attestedPublicKey: T?,
    val details: AttestationResult
) {
    val isSuccess get() = attestedPublicKey != null

    fun <R> fold(
        onError: (AttestationResult.Error) -> R,
        onSuccess: (T, AttestationResult) -> R
    ): R =
        if (isSuccess) onSuccess(attestedPublicKey!!, details)
        else {
            onError(details as AttestationResult.Error)
        }
}

/**
 * NOOP attestation service. Useful during unit tests for disabling attestation integrated into service endpoints.
 * Simply forwards inputs but performs no attestation whatsoever.
 *
 * Do not use in production!
 */

object NoopAttestationService : AttestationService {

    private val log = LoggerFactory.getLogger(this.javaClass)
    override fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray?
    ): AttestationResult =
        if (attestationProof.size > 2) AttestationResult.Android.NOOP(attestationProof)
        else AttestationResult.IOS(clientData)

    override val ios: AttestationService.IOS
        get() = object : AttestationService.IOS {
            override fun verifyAppAttestation(attestationObject: ByteArray, challenge: ByteArray) =
                verifyAttestation(listOf(attestationObject), challenge, clientData = null)

            override fun verifyAssertion(
                attestationObject: ByteArray,
                assertionFromDevice: ByteArray,
                referenceClientData: ByteArray,
                challenge: ByteArray,
                counter: Long
            ) = verifyAttestation(listOf(attestationObject, assertionFromDevice), challenge, referenceClientData)

        }
    override val android: AttestationService.Android
        get() = TODO("Not yet implemented")
}

/**
 * Default, functional Android Key Attestation and Apple App Attestation in all its glory.
 *
 * Once configured, this class provides a streamlined interface for mobile client attestation
 *
 * @param androidAttestationConfiguration Configuration for Android key attestation. See [AndroidAttestationConfiguration]
 * for details
 * @param iosAttestationConfiguration IOS AppAttest configuration.  See [IOSAttestationConfiguration] for details.
 * @param clock a clock to set the time of verification (used for certificate validity checks)
 * @param verificationTimeOffset allows for fine-grained clock drift compensation (this duration is added to the certificate
 * validity checks; can be negative.
 */
class DefaultAttestationService(
    androidAttestationConfiguration: AndroidAttestationConfiguration,
    private val iosAttestationConfiguration: IOSAttestationConfiguration,
    private val clock: Clock = Clock.System,
    private val verificationTimeOffset: Duration = Duration.ZERO
) : AttestationService {

    /**
     * Java-friendly constructor with `java.time` types
     *
     * @param androidAttestationConfigurationJ Configuration for Android key attestation. See [AndroidAttestationConfiguration]
     * @param iosAttestationConfigurationJ IOS AppAttest configuration.  See [IOSAttestationConfiguration] for details.
     * @param verificationTimeOffsetJ allows for fine-grained clock drift compensation (this duration is added to the certificate
     *                                validity checks; can be negative.
     * @param javaClock a clock to set the time of verification (used for certificate validity checks)
     */
    @JvmOverloads
    constructor(
        androidAttestationConfigurationJ: AndroidAttestationConfiguration,
        iosAttestationConfigurationJ: IOSAttestationConfiguration,
        verificationTimeOffsetJ: java.time.Duration = java.time.Duration.ZERO,
        javaClock: java.time.Clock = java.time.Clock.systemUTC()
    ) : this(
        androidAttestationConfigurationJ,
        iosAttestationConfigurationJ,
        javaClock.toKotlinClock(),
        verificationTimeOffsetJ.toKotlinDuration()
    )

    private val log = LoggerFactory.getLogger(this.javaClass)

    private val androidAttestationChecker =
        AndroidAttestationChecker(androidAttestationConfiguration) { expected, actual -> expected contentEquals actual }

    private val appleAppAttest = AppleAppAttest(
        app = App(iosAttestationConfiguration.teamIdentifier, iosAttestationConfiguration.bundleIdentifier),
        appleAppAttestEnvironment = if (iosAttestationConfiguration.sandbox) AppleAppAttestEnvironment.DEVELOPMENT else AppleAppAttestEnvironment.PRODUCTION,
    )


    private val appAttestReader = ObjectMapper(CBORFactory())
        .registerKotlinModule()
        .readerFor(AttestationObject::class.java)

    private val appAttestClock = java.time.Clock.offset(
        clock.toJavaClock(),
        verificationTimeOffset.toJavaDuration()
    )
    private val attestationValidator = appleAppAttest.createAttestationValidator(
        clock = appAttestClock,
        receiptValidator = appleAppAttest.createReceiptValidator(
            clock = appAttestClock,
            maxAge = (verificationTimeOffset.absoluteValue * 2).toJavaDuration()
                .plus(ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE)
        )
    )

    override val ios = object : AttestationService.IOS {
        override fun verifyAppAttestation(attestationObject: ByteArray, challenge: ByteArray) =
            verifyAttestationApple(attestationObject, challenge, assertionData = null, counter = 0L)

        override fun verifyAssertion(
            attestationObject: ByteArray,
            assertionFromDevice: ByteArray,
            referenceClientData: ByteArray,
            challenge: ByteArray,
            counter: Long
        ) = verifyAttestationApple(
            attestationObject,
            challenge,
            assertionData = AssertionData(assertionFromDevice, referenceClientData),
            counter
        )
    }

    override val android = object : AttestationService.Android {
        override fun verifyKeyAttestation(
            attestationCerts: List<X509Certificate>,
            expectedChallenge: ByteArray
        ) = verifyKeyAttestation<PublicKey>(
            attestationCerts.map { it.encoded },
            expectedChallenge,
            attestationCerts.first().publicKey
        )
    }

    override fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray?
    ): AttestationResult {
        log.debug("attestation proof length: ${attestationProof.size}")
        return if (attestationProof.isEmpty()) AttestationResult.Error("Attestation proof is empty")
        else if (attestationProof.size > 2)
            verifyAttestationAndroid(attestationProof, challenge)
        else {
            kotlin.runCatching {
                verifyAttestationApple(
                    attestationProof.first(),
                    challenge,
                    clientData?.let { AssertionData(attestationProof[1], it) },
                    counter = 0L
                )

            }.getOrElse {
                //if attestationProof contains no assertion, but clientData is set, for example
                log.warn("Could not verify attestation proof: {}", attestationProof.map { it.encodeBase64() })
                return if (it is IndexOutOfBoundsException)
                    AttestationResult.Error(
                        "Invalid length of attestation proof: ${it.message}. " +
                                "Possible reason: passed 'clientData' but no assertion"
                    )
                else AttestationResult.Error(
                    "Could not verify client integrity due to internal error: " +
                            "${it::class.simpleName}${it.message?.let { ". $it" }}"
                )

            }
        }
    }

    /**
     * Verifies [Android Key Attestation](https://developer.android.com/training/articles/security-key-attestation) based
     * the provided certificate chain (the leaf ist the attestation certificate, the root must be one of the
     * [Google Hardware Attestation Root certificates](https://developer.android.com/training/articles/security-key-attestation#root_certificate).
     *
     * @param attestationCerts certificate chain from the attestation certificate up to a Google Hardware Attestation Root certificate
     * @param expectedChallenge the challenge to be verified against
     *
     * @return [AttestationResult.Android] on success [AttestationResult.Error] in case attestation failed
     */
    private fun verifyAttestationAndroid(
        attestationCerts: List<ByteArray>,
        expectedChallenge: ByteArray
    ): AttestationResult = runCatching {
        log.debug("Verifying Android attestation")
        if (attestationCerts.isEmpty()) return AttestationResult.Error("Attestation proof is empty")
        val certificates = attestationCerts.mapNotNull { it.parseToCertificate() }
        if (certificates.size != attestationCerts.size)
            return AttestationResult.Error("Could not parse Android attestation certificate chain")

        //throws exception on fail
        androidAttestationChecker.verifyAttestation(
            certificates,
            (clock.now() + verificationTimeOffset).toJavaDate(),
            expectedChallenge
        )

        AttestationResult.Android.Verified(certificates)
    }.getOrElse {
        AttestationResult.Error(
            "Android Attestation Error: " + (it.message ?: it::class.simpleName),
            if (it is CertificateException || it is CertificateInvalidException) AttException.Certificate(
                Platform.ANDROID,
                cause = it
            )
            else AttException.Content(Platform.ANDROID, cause = it)
        )
    }

    /**
     * Verifies an Apple [AppAttest attestation statement](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643)
     * It is optionally possible to pass an [assertionData] pair, mapping an
     * [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * to a `clientData` [ByteArray].
     * The signature counter in the attestation must be `0` and the signature counter in the assertion must be `1`,
     * meaning that a fresh attestation statement must have been created. If [assertionData] is present, this freshly
     * attested key must have been used exactly once to sign the `clientData` object contained within [assertionData]
     *
     * Passing a public key created in the same app on the iDevice's secure hardware as `clientData` effectively
     * emulates Android's key attestation: Attesting such a secondary key through an assertion, proves that
     * it was also created within the same app, on the same device, resulting in an attested key, which can then be used
     * for general-purpose crypto. **BEWARE if you pass the public key on iOS to be signed as is. iOS uses the ANSI X9.63
     * format represent public keys, so conversion is needed**
     *
     * @param attestationObject the AppAttest Attestation object. Must be freshly created (i.e. signature counter must be zero)
     * @param expectedChallenge the challenge to be verified against
     * @param assertionData optional assertion data containing `clientData` and an [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * @param counter highest expected value of the signature counter before the assertion was created (if present). Defaults to 0
     *
     * @return [AttestationResult.IOS.Verbose] on success when using the [DefaultAttestationService] ([AttestationResult.IOS]
     * when using [NoopAttestationService]) and [AttestationResult.Error] when attestation fails.
     *
     */
    private fun verifyAttestationApple(
        attestationObject: ByteArray,
        expectedChallenge: ByteArray,
        assertionData: AssertionData?,
        counter: Long
    ): AttestationResult = runCatching {
        log.debug("Verifying iOS attestation")

        val parsedAttestationCert =
            X509CertificateHolder(appAttestReader.readValue<AttestationObject>(attestationObject).attStmt.x5c.first())

        val result: ValidatedAttestation = attestationValidator.validate(
            attestationObject = attestationObject,
            keyIdBase64 = MessageDigest.getInstance("SHA-256")
                .digest(parsedAttestationCert.subjectPublicKeyInfo.publicKeyData.bytes)
                .encodeBase64(),
            serverChallenge = expectedChallenge,
        )

        iosAttestationConfiguration.iosVersion?.let {
            val parsedVersion = SemVer.parse(
                result.iOSVersion ?: return AttestationResult.Error(
                    "Could not parse iOS version from AppAttest",
                    AttException.Content(Platform.IOS)
                )
            )
            val configuredVersion = SemVer.parse(it)
            if (parsedVersion < configuredVersion)
                return AttestationResult.Error(
                    "iOS version  $parsedVersion <$configuredVersion",
                    AttException.Content(Platform.IOS)
                )
        }

        return assertionData?.let { assertionData ->
            runCatching {
                val assertion = appleAppAttest.createAssertionValidator(object : AssertionChallengeValidator {
                    override fun validate(
                        assertionObj: Assertion,
                        clientData: ByteArray,
                        attestationPublicKey: ECPublicKey,
                        challenge: ByteArray,
                    ) = challenge contentEquals expectedChallenge
                }).validate(
                    assertionData.assertion,
                    assertionData.clientData,
                    result.certificate.publicKey as ECPublicKey,
                    counter,
                    expectedChallenge
                )
                return if (assertion.authenticatorData.signCount != 1L) AttestationResult.Error(
                    "iOS Assertion counter is ${assertion.authenticatorData.signCount}, but should be 1",
                    AttException.Content(Platform.IOS)
                )
                else AttestationResult.IOS.Verbose(result, assertionData.clientData to assertion)
            }.getOrElse {
                AttestationResult.Error(
                    it.message ?: "iOS Assertion validation error due to ${it::class.simpleName}",
                    if (it is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidCertificateChain || it is ReceiptException.InvalidCertificateChain) AttException.Certificate(
                        Platform.IOS,
                        cause = it
                    ) else AttException.Content(Platform.IOS, cause = it)

                )
            }
        } ?: AttestationResult.IOS(null)

    }.getOrElse {
        AttestationResult.Error(
            it.message ?: "iOS Attestation failed due to ${it::class.simpleName}",
            if (it is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidCertificateChain || it is ReceiptException.InvalidCertificateChain) AttException.Certificate(
                Platform.IOS,
                cause = it
            ) else AttException.Content(Platform.IOS, cause = it)
        )
    }

}
