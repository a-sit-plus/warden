package at.asitplus.attestation


enum class Platform {
    IOS,
    ANDROID
}

/**
 * Provides additional details on why an attestation attempt failed, indicating which [platform] was being attested.
 * Although many reasons exist, why an attestation may fail, these can be put into two categories:
 *  * [Content] e.g. version, app name, challenge, or key mismatch
 *  * [Certificate] e.g. chain rooted in an untrusted certificate, revocation, validity period
 *
 *  If more specific details about why the attestation failed are available, [message] and/or [cause] will be set.
 *  Especially when acting upon Errors propagating from a failed Android attestation, the type of the [cause] and
 *  [error codes contained within](https://a-sit-plus.github.io/android-attestation/-android%20%20-attestation%20-library/at.asitplus.attestation.android.exceptions/index.html)
 *  will provide insights.
 *
 */
sealed class AttestationException(val platform: Platform, message: String? = null, cause: Throwable? = null) :
    Throwable(message, cause) {

    /**
     * Indicates that some value (key to be attests, bundle identifier or package name, team identified or signer certificate, etc.) failed to verify
     * This usually means that either the client's OS or the app was compromised/modified.
     */
    open class Content(platform: Platform, message: String? = null, cause: Throwable? = null) :
        AttestationException(platform, message = message, cause = cause)

    /**
     * Indicates a problem verifying the certificate chain the attestation statement is built upon.
     * This can either be just a borked certificate chain (i.e. just a wrong certificate somewhere in the chain),
     * or the chain not being rooted in a valid trust anchor.
     * Most probably, however, a legitimate app on a trusted OS will simply have fallen victim to the system clock
     * being too far ahead. This heavily depends on the OS a device was originally shipped with,
     * (or just Samsung being Samsung and being unable to correctly encode a timestamp conforming to ASN.1)
     */

    sealed class Certificate(platform: Platform, message: String?, cause: Throwable?) :
        AttestationException(platform, message = message, cause = cause) {

        /**
         * Indicates that temporal certificate chain verification failed
         * (i.e. the client's clock is not synchronised with the back-end)
         */
        class Time(platform: Platform, message: String? = null, cause: Throwable? = null) :
            Certificate(platform, message, cause)

        /**
         * Indicates either a borked certificate chain or one that is not rooted in one of the configured trust anchors
         */
        class Trust(platform: Platform, message: String? = null, cause: Throwable? = null) :
            Certificate(platform, message, cause)
    }

    /**
     * Thrown on instantiation, for illegal configurations (e.g. no apps configured)
     */
    class Configuration(platform: Platform, message: String? = null, cause: Throwable? = null) :
        AttestationException(platform, message = message, cause = cause)

    override fun toString() =
        "AttestationException.${this::class.simpleName}: platform: $platform, message: ${message ?: cause?.message}, cause: $cause"
}