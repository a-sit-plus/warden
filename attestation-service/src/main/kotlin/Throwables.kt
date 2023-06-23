package at.asitplus.attestation


//not very idiomatic, but

enum class Platform {
    IOS,
    ANDROID
}

sealed class AttestationException(val platform: Platform, message: String? = null, cause: Throwable? = null) :
    Throwable(message, cause) {

    open class Content(platform: Platform, message: String? = null, cause: Throwable? = null) :
        AttestationException(platform, message = message, cause = cause)

    class Certificate(platform: Platform, message: String? = null, cause: Throwable? = null) :
        AttestationException(platform, message = message, cause = cause)
}