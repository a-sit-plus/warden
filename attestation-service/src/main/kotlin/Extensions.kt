package at.asitplus.attestation

import kotlinx.datetime.Clock
import kotlinx.datetime.toJavaInstant
import kotlinx.datetime.toKotlinInstant
import org.bouncycastle.util.encoders.Base64
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.time.ZoneId
import java.util.*


//copied from AppAttest Library
private val certificateFactory = CertificateFactory.getInstance("X.509")
fun ByteArray.parseToCertificate(): X509Certificate? = kotlin.runCatching {
    certificateFactory.generateCertificate(this.inputStream()) as X509Certificate
}.getOrNull()

data class AttestationObject(
    val fmt: String,
    val attStmt: AttestationStatement,
    val authData: ByteArray
) {
    data class AttestationStatement(
        val x5c: List<ByteArray>,
        val receipt: ByteArray
    )
}

internal fun String.decodeBase64ToArray() = Base64.decode(this)

internal fun ByteArray.encodeBase64() = Base64.toBase64String(this)

internal fun Clock.toJavaClock(): java.time.Clock =
    object : java.time.Clock() {
        override fun getZone(): ZoneId = systemDefaultZone().zone


        override fun withZone(zone: ZoneId?): java.time.Clock {
            TODO("Not yet implemented")
        }

        override fun instant(): Instant = now().toJavaInstant()

    }

internal fun kotlinx.datetime.Instant.toJavaDate() = Date.from(toJavaInstant())

fun ECPublicKey.toAnsi() = let {
    val xFromBc = it.w.affineX.toByteArray().ensureSize(32)
    val yFromBc = it.w.affineY.toByteArray().ensureSize(32)
    byteArrayOf(0x04) + xFromBc + yFromBc
}

/**
 * Drops or adds zero bytes at the start until the [size] is reached
 */
private fun ByteArray.ensureSize(size: Int): ByteArray = when {
    this.size > size -> this.drop(1).toByteArray().ensureSize(size)
    this.size < size -> (byteArrayOf(0) + this).ensureSize(size)
    else -> this
}

// taken from https://github.com/Kotlin/kotlinx-datetime/pull/249/
fun java.time.Clock.toKotlinClock(): Clock = let {
    object : Clock {
        override fun now() = it.instant().toKotlinInstant()
    }
}