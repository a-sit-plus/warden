package at.asitplus.attestation

import at.asitplus.attestation.AttestationException
import at.asitplus.attestation.IOSAttestationConfiguration.AppData
import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.fromJcaPublicKey
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import com.google.android.attestation.AttestationApplicationId
import com.google.android.attestation.ParsedAttestationRecord
import kotlinx.datetime.Clock
import net.swiftzer.semver.SemVer
import org.slf4j.LoggerFactory
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*
import kotlin.jvm.optionals.getOrNull
import at.asitplus.attestation.AttestationException as AttException

/**
 * Configuration class for Apple App Attestation
 */
data class IOSAttestationConfiguration @JvmOverloads constructor(

    /**
     * List of applications that can be attested
     */
    val applications: List<AppData>,

    /**
     * Optional parameter. If present the iOS version of the attested app must be greater or equal to this parameter
     * Uses [SemVer](https://semver.org/) syntax. Can be overridden vor individual apps.
     *
     * @see AppData.iosVersionOverride
     */
    val iosVersion: OsVersions? = null,

    ) {


    @JvmOverloads
    constructor(singleApp: AppData, iosVersion: OsVersions? = null) : this(listOf(singleApp), iosVersion)

    init {
        if (applications.isEmpty())
            throw AttestationException.Configuration(Platform.IOS, "No apps configured", IllegalArgumentException())
    }

    /**
     * Container class for iOS versions. Necessary, iOS versions used to always be encoded into attestation statements using
     * [SemVer](https://semver.org/) syntax. Newer iPhones, however, use a hex string representation of the build number instead.
     * Since it makes rarely sense to only check for SemVer not for a hex-encoded build number (i.e only accept older iPhones),
     * encapsulating both variants into a dedicated type ensures that either both or neither are set.
     */
    data class OsVersions(
        /**
         * [SemVer](https://semver.org/)-formatted iOS version number.
         * This property is a simple string, because it plays nicely when externalising configuration to files, since
         * it doesn't require a custom deserializer/decoder.
         */
        private val semVer: String,

        /**
         * String representation of an iOS build number. As per [TidBITS.com](https://tidbits.com/2020/07/08/how-to-decode-apple-version-and-build-numbers/):
         * @see BuildNumber
         */
        private val buildNumber: String,

        ) : Comparable<Any> {

        /**
         * Parsed and normalised iOS build number. As per [TidBITS.com](https://tidbits.com/2020/07/08/how-to-decode-apple-version-and-build-numbers/):
         * @see BuildNumber
         */
        val normalisedBuildNumber: BuildNumber = runCatching { BuildNumber(buildNumber) }.getOrElse { ex ->
            throw AttestationException.Configuration(
                Platform.IOS,
                "Illegal iOS build number $buildNumber",
                ex
            )
        }

        /**
         * [SemVer](https://semver.org/)-formatted iOS version number.
         */
        val semVerParsed: SemVer =
            runCatching { SemVer.parse(semVer) }.getOrElse { ex ->
                throw AttestationException.Configuration(
                    Platform.IOS,
                    "Illegal iOS version number $semVer",
                    ex
                )
            }

        override fun toString(): String =
            "iOS Versions (semVer=$semVerParsed, buildNumber: $normalisedBuildNumber)"

        override fun compareTo(other: Any): Int {
            return when (other) {
                is BuildNumber -> normalisedBuildNumber.compareTo(other)
                is SemVer -> semVerParsed.compareTo(other)
                is Pair<*, *> -> {
                    if ((other.first is SemVer || other.first is SemVer?) && (other.second is BuildNumber || other.second is BuildNumber?)) {
                        other.first?.let { return semVerParsed.compareTo(it as SemVer) }
                            ?: other.second?.let { normalisedBuildNumber.compareTo(it as BuildNumber) }
                            ?: throw UnsupportedOperationException("No Parsed iOS Version present.")
                    } else throw UnsupportedOperationException("Cannot compare OsVersions to ${other::class.simpleName}")
                }

                else -> throw UnsupportedOperationException("Cannot compare OsVersions to ${other::class.simpleName}")
            }
        }
    }


    /**
     * Specifies a to-be attested app
     */
    data class AppData @JvmOverloads constructor(
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
         * Optional parameter. If present, overrides the globally configured iOS version for this app.
         */
        val iosVersionOverride: OsVersions? = null,

        ) {

        /**
         * Builder for more Java-friendliness
         * @param teamIdentifier nomen est omen
         * @param bundleIdentifier nomen est omen
         */
        @Suppress("UNUSED")
        class Builder(private val teamIdentifier: String, private val bundleIdentifier: String) {
            private var sandbox = false
            private var iosVersionOverride: OsVersions? = null

            /**
             * @see AppData.sandbox
             */
            fun sandbox(sandbox: Boolean) = apply { this.sandbox = sandbox }

            /**
             * @see AppData.iosVersionOverride
             */
            fun overrideIosVersion(version: OsVersions) = apply { iosVersionOverride = version }

            fun build() = AppData(teamIdentifier, bundleIdentifier, sandbox, iosVersionOverride)
        }
    }

}

typealias ParsedVersions = Pair<SemVer?, BuildNumber?>

/**
 * iOS build number. As per [TidBITS.com](https://tidbits.com/2020/07/08/how-to-decode-apple-version-and-build-numbers/):
 *
 * An Apple build number also has three parts:
 *
 * *  Major version: Within Apple, the major version is called the build train.
 * *  Minor version: For iOS and its descendants, the minor version tracks with the minor release; for macOS, it tracks with patch releases.
 * *  Daily build version: The daily build indicates how many times Apple has built the source code for the release since the previous public release.
 *
 * While this last bit about the daily build number is phrased somewhat fuzzy, it really is a strictly increasing decimal number.
 */
class BuildNumber private constructor(val buildTrain: UInt, val minorVersion: String, val buildVer: UInt) :
    Comparable<BuildNumber> {


    constructor(buildNumber: String) : this(parseBuildNumber(buildNumber))

    constructor(boxed: Triple<UInt, String, UInt>) : this(boxed.first, boxed.second, boxed.third)


    /**
     * Integer representation of the build number. Converts [buildTrain] into a hex number, concatenates it with [minorVersion] radix-36-parsed
     * to a hex number and concatenates it with an end-padded hex-representation of [buildVer].
     * This results in a [UInt] whose MSBs are always set for correct and straight-forward comparison of build numbers.
     * The implementation is inefficient but comprehensible.
     */
    val intRepresentation = (
            buildTrain.toString(16)
                    + minorVersion.toUInt(36).toString(16)
                    //there will never be more than 9999 days between first release of minorVer and patch
                    + buildVer.toString(10).padEnd(4, '0').toUInt(10).toString(16)
            ).padEnd(8, '0').toUInt(16)

    override fun compareTo(other: BuildNumber): Int = intRepresentation.compareTo(other.intRepresentation)

    override fun toString() = "$buildTrain$minorVersion$buildVer (${intRepresentation.toString(16)})".uppercase()

    companion object {
        private fun parseBuildNumber(stringRepresentation: String): Triple<UInt, String, UInt> {
            val buildTrain = stringRepresentation.takeWhile { it.isDigit() }
            val minorVersion = stringRepresentation.substring(buildTrain.length).takeWhile { it.isLetter() }.uppercase()
            val buildVer = stringRepresentation.substring(buildTrain.length + minorVersion.length).toUInt(10)

            return Triple(buildTrain.toUInt(10), minorVersion, buildVer)
        }
    }
}


abstract class AttestationService {


    internal abstract fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray? = null
    ): AttestationResult


    /**
     * Verifies key attestation for both Android and Apple devices.
     *
     * Succeeds if attestation data structures of the client (in [attestationProof]) can be verified and [expectedChallenge] matches
     * the attestation challenge. For Android clients, this function makes sure that [keyToBeAttested] matches the key contained in the attestation certificate.
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
    ): KeyAttestation<T> {
        when (val firstTry = verifyAttestation(
            attestationProof,
            expectedChallenge,
            keyToBeAttested.encoded
        )) {
            is AttestationResult.Android -> {
                return if (CryptoPublicKey.fromJcaPublicKey(keyToBeAttested) == CryptoPublicKey.fromJcaPublicKey(
                        firstTry.attestationCertificate.publicKey
                    )
                )
                    KeyAttestation(keyToBeAttested, firstTry)
                else {
                    ("Android attestation failed: keyToBeAttested (${keyToBeAttested.encoded.encodeBase64()}) does not match " +
                            "key from attestation certificate: ${firstTry.attestationCertificate.publicKey.encoded.encodeBase64()}").let {
                        KeyAttestation(
                            null,
                            AttestationResult.Error(
                                explanation = it,
                                cause = AttException.Content.Android(
                                    it,
                                    AttestationValueException(
                                        it,
                                        cause = null,
                                        reason = AttestationValueException.Reason.APP_UNEXPECTED
                                    )
                                )
                            )
                        )
                    }
                }
            }

            is AttestationResult.Error -> {
                //try different encodings
                val publicKeyEncodings = CryptoPublicKey.fromJcaPublicKey(keyToBeAttested).getOrThrow().let {
                    listOf(
                        it.iosEncoded,
                        (it as CryptoPublicKey.EC).copy(
                            it.publicPoint,
                            preferCompressedRepresentation = !it.preferCompressedRepresentation
                        ).iosEncoded,
                        it.encodeToDer()
                    )
                }

                // not the most efficient way, but doing it like this won't involve any guesswork at all
                publicKeyEncodings.forEach {
                    when (val secondTry =
                        kotlin.runCatching { verifyAttestation(attestationProof, expectedChallenge, it) }
                            .getOrElse { return KeyAttestation(null, firstTry) }) {
                        is AttestationResult.Android -> throw RuntimeException("Logical Error attesting key ${keyToBeAttested.encoded.encodeBase64()} for attestation proof ${attestationProof.joinToString { it.encodeBase64() }} with challenge ${expectedChallenge.encodeBase64()} at ${Clock.System.now()}")
                        is AttestationResult.Error -> {/*try again*/
                        }
                        //if this works, perfect!
                        is AttestationResult.IOS -> return KeyAttestation(keyToBeAttested, secondTry)
                    }
                }
                //if no encoding works, then it should just fail
                return KeyAttestation(null, firstTry)
            }

            is AttestationResult.IOS -> return KeyAttestation(keyToBeAttested, firstTry)
        }
    }

    /** Same as [verifyKeyAttestation], but taking an encoded (either ANSI X9.63 or DER) publix key as a byte array
     * @see verifyKeyAttestation
     */
    fun verifyKeyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        encodedPublicKey: ByteArray
    ): KeyAttestation<PublicKey> =
        verifyKeyAttestation(attestationProof, challenge, encodedPublicKey.parseToPublicKey())

    /**
     * Groups iOS-specific API to reduce toplevel clutter.
     *
     * Exposes iOS-specific functionality in a more expressive, and less confusing manner
     */
    abstract val ios: IOS

    interface IOS {
        /**
         * convenience method specific to iOS, which only verifies App Attestation and no assertion
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
         * First, it verifies the app attestation, afterwards it verifies the assertion, checks whether at most [counter] many signatures
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

    /**
     * Exposes Android-specific API to reduce toplevel clutter
     */
    abstract val android: Android

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
 * Attestation result class. Successful results contain attested data. Typically contained within a
 * [KeyAttestation] object.
 */
sealed class AttestationResult {

    override fun toString() = "AttestationResult::$details)"
    protected abstract val details: String

    /**
     * Successful Android Key Attestation result. [attestationCertificateChain] contains the attested certificate.
     *
     * All attested information in [attestationRecord] is available for further processing, should this be desired.
     * Note: this will fail when using the [NoopAttestationService]!
     */
    @Suppress("MemberVisibilityCanBePrivate")
    abstract class Android(val attestationCertificateChain: List<X509Certificate>) :
        AttestationResult() {

        protected abstract val androidDetails: String
        override val details: String by lazy { "Android::$androidDetails" }
        abstract val attestationRecord: ParsedAttestationRecord

        val attestationCertificate by lazy { attestationCertificateChain.first() }

        internal class NOOP internal constructor(attestationCertificateChain: List<ByteArray>) :
            Android(attestationCertificateChain.mapNotNull { it.parseToCertificate() }) {
            override val androidDetails = "NOOP"
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
            override val androidDetails =
                "Verified(keyMaster security level: ${attestationRecord.keymasterSecurityLevel().name}, " +
                        "attestation security level: ${attestationRecord.attestationSecurityLevel().name}, " +
                        "${attestationRecord.attestedKey().algorithm} public key: ${attestationRecord.attestedKey().encoded.encodeBase64()}" + attestationRecord.softwareEnforced()
                    .attestationApplicationId()
                    .getOrNull()
                    ?.let { app ->
                        ", packageInfos: ${
                            app.packageInfos().joinToString(
                                prefix = "[",
                                postfix = "]"
                            ) { info: AttestationApplicationId.AttestationPackageInfo -> "${info.packageName()}:${info.version()}" }
                        }"
                    }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Android) return false

            if (attestationCertificateChain.map { it.encoded.encodeBase64() } != other.attestationCertificateChain.map { it.encoded.encodeBase64() }) return false
            if (androidDetails != other.androidDetails) return false

            return true
        }

        override fun hashCode(): Int {
            var result = attestationCertificateChain.map { it.encoded.contentHashCode() }.hashCode()
            result = 31 * result + androidDetails.hashCode()
            return result
        }
    }


    /**
     * Successful iOS attestation. If [AttestationService.verifyKeyAttestation] returned this, [clientData] contains the
     * encoded attested public key.
     * The [Warden], returns [IOS.Verified], also setting [IOS.Verified.attestation].
     * The [NoopAttestationService] returns [IOS.NOOP] (which is useful to as it enables skipping any
     * and all attestation checks for unit testing, when used with dependency injection, for example).
     */
    @Suppress("MemberVisibilityCanBePrivate")
    abstract class IOS(val clientData: ByteArray?) : AttestationResult() {

        abstract val iosDetails: String
        override val details: String by lazy { "iOS::$iosDetails" }

        class Verified(
            val attestation: ValidatedAttestation,
            val iosVersion: ParsedVersions,
            val assertedClientData: Pair<ByteArray, Assertion>?
        ) :
            IOS(assertedClientData?.first) {
            override val iosDetails =
                "Verified(${attestation.certificate.publicKey.algorithm} public key: ${attestation.certificate.publicKey.encoded.encodeBase64()}, " +
                        "iOS version: (semVer=${iosVersion.first}, buildNumber=[${iosVersion.second}]), app: ${attestation.receipt.payload.appId}"
        }

        class NOOP(clientData: ByteArray?) : IOS(clientData) {
            override val iosDetails = "NOOP"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is IOS) return false

            if (clientData != null) {
                if (other.clientData == null) return false
                if (!clientData.contentEquals(other.clientData)) return false
            } else if (other.clientData != null) return false
            if (iosDetails != other.iosDetails) return false

            return true
        }

        override fun hashCode(): Int {
            var result = clientData?.contentHashCode() ?: 0
            result = 31 * result + iosDetails.hashCode()
            return result
        }

        /**
         * Represents an attestation verification failure. Always contains an  [explanation] about what went wrong.
         */
    }

    class Error(val explanation: String, val cause: AttException? = null) : AttestationResult() {
        override val details = "Error($explanation" + cause?.let { ", Cause: ${cause::class.qualifiedName}" }
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

    override fun toString() = "Key$details"

    @Suppress("UNUSED")
    inline fun <R> fold(
        onError: (AttestationResult.Error) -> R,
        onSuccess: (T, AttestationResult) -> R
    ): R =
        if (isSuccess) onSuccess(attestedPublicKey!!, details)
        else {
            onError(details as AttestationResult.Error)
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeyAttestation<*>) return false

        if (!attestedPublicKey?.encoded.contentEquals(other.attestedPublicKey?.encoded)) return false
        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        var result = attestedPublicKey?.encoded?.contentHashCode() ?: 0
        result = 31 * result + details.hashCode()
        return result
    }


}

/**
 * NOOP attestation service. Useful during unit tests for disabling attestation integrated into service endpoints.
 * Simply forwards inputs but performs no attestation whatsoever.
 *
 * Do not use in production!
 */

object NoopAttestationService : AttestationService() {

    private val log = LoggerFactory.getLogger(this.javaClass)
    override fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray?
    ): AttestationResult =
        if (attestationProof.size > 2) AttestationResult.Android.NOOP(attestationProof)
        else AttestationResult.IOS.NOOP(clientData)

    override val ios: IOS
        get() = object : IOS {
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
    override val android: Android
        get() = TODO("Not yet implemented")
}

