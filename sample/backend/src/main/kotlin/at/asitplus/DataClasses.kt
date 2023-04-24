package at.asitplus

import kotlinx.datetime.Instant
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonClassDiscriminator
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

val b64enc = Base64.getEncoder()
val b64dec = Base64.getDecoder()

object Base64Serializer : KSerializer<ByteArray> {
    override val descriptor = PrimitiveSerialDescriptor("Base64ByteArray", PrimitiveKind.STRING)


    override fun deserialize(decoder: Decoder) = b64dec.decode(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(b64enc.encodeToString(value))

}

object InstantSecondSerializer : KSerializer<Instant> {
    override val descriptor = PrimitiveSerialDescriptor("SecondsSinceEpoch", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder) = Instant.fromEpochSeconds(decoder.decodeLong())

    override fun serialize(encoder: Encoder, value: Instant) = encoder.encodeLong(value.epochSeconds)

}

object CertificateSerializer : KSerializer<Certificate> {
    private val certificateFactory = CertificateFactory.getInstance("X.509")
    override val descriptor = PrimitiveSerialDescriptor("X509Certificate", PrimitiveKind.STRING)
    override fun deserialize(decoder: Decoder) =
        certificateFactory.generateCertificate(ByteArrayInputStream(b64dec.decode(decoder.decodeString())))

    override fun serialize(encoder: Encoder, value: Certificate) =
        encoder.encodeString(b64enc.encodeToString(value.encoded))

}

object EcPublicKeySerializer : KSerializer<ECPublicKey> {
    override val descriptor = PrimitiveSerialDescriptor("EcPublicKey", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder) = KeyFactory.getInstance("EC")
        .generatePublic(X509EncodedKeySpec(b64dec.decode(decoder.decodeString()))) as ECPublicKey


    override fun serialize(encoder: Encoder, value: ECPublicKey) =
        encoder.encodeString(b64enc.encodeToString(value.encoded))
}

@Serializable
data class Challenge(
    @Serializable(with = Base64Serializer::class) val challenge: ByteArray,
    @Serializable(with = InstantSecondSerializer::class) val validUntil: Instant
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Challenge

        if (!challenge.contentEquals(other.challenge)) return false
        return validUntil == other.validUntil
    }

    override fun hashCode(): Int {
        var result = challenge.contentHashCode()
        result = 31 * result + validUntil.hashCode()
        return result
    }
}

@Serializable
data class AttestationRequest(
    @Serializable(with = Base64Serializer::class) val challenge: ByteArray,
    val attestationProof: List<@Serializable(with = Base64Serializer::class) ByteArray>,
    @Serializable(with = EcPublicKeySerializer::class) val publicKey: ECPublicKey
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AttestationRequest

        if (!challenge.contentEquals(other.challenge)) return false
        if (attestationProof != other.attestationProof) return false
        return publicKey.encoded.contentEquals(other.publicKey.encoded)
    }

    override fun hashCode(): Int {
        var result = challenge.contentHashCode()
        result = 31 * result + attestationProof.hashCode()
        result = 31 * result + publicKey.hashCode()
        return result
    }
}

enum class Platform {
    iOS,
    Android
}

@Serializable
@JsonClassDiscriminator("status")
sealed class AttestationResponse {

    @Serializable
    @SerialName("Error")
    class Error(val reason:String) : AttestationResponse()

    @Serializable
    @SerialName("Success")
    class Success(
        val platform: Platform,
        val certificateChain: List<@Serializable(with = CertificateSerializer::class) X509Certificate>
    ) : AttestationResponse()
}
