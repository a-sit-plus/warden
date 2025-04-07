package at.asitplus.attestation

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import kotlinx.datetime.Clock
import kotlinx.datetime.toJavaInstant
import kotlinx.datetime.toKotlinInstant
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.util.encoders.Base64
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.ZoneId
import java.util.*


private val ecKeyFactory = KeyFactory.getInstance("EC")
private val rsaKeyFactory = KeyFactory.getInstance("RSA")

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

internal fun PublicKey.transcodeToAllFormats() = toCryptoPublicKey().getOrThrow().let {
    listOf(
        it.iosEncoded,
        (it as CryptoPublicKey.EC).toAnsiX963Encoded(useCompressed = !it.preferCompressedRepresentation),
        it.encodeToDer()
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

fun ByteArray.parseToPublicKey(): PublicKey =
    try {
       CryptoPublicKey.decodeFromDer(this).toJcaPublicKey().getOrThrow()
    } catch (e: Throwable) {
       CryptoPublicKey.fromIosEncoded(this).toJcaPublicKey().getOrThrow()
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