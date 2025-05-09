package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.io.MultiBase
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlin.time.Duration

private val jsonDebug = kotlinx.serialization.json.Json {
    encodeDefaults = true
    ignoreUnknownKeys = true
}


@Serializable
class WardenDebugAttestationStatement internal constructor(
    val method: Method,
    val androidAttestationConfiguration: AndroidAttestationConfiguration,
    val iosAttestationConfiguration: IOSAttestationConfiguration,
    val genericAttestationProof: List<@Serializable(with = ByteArrayBase64UrlSerializer::class) ByteArray>? = null,
    val keyAttestation: Attestation? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val clientData: ByteArray? = null,
    val verificationTime: Instant,
    val verificationTimeOffset: Duration = Duration.ZERO
) {

    enum class Method {
        LEGACY,
        SUPREME,
        KEY_ATTESTATION_LEGACY,
        KEY_ATTESTATION_LEGACY_RAW,
    }

    /**
     * Creates a new [Warden] instance based on recorded debug data
     */
    fun createWarden(): Warden = Warden(
        androidAttestationConfiguration,
        iosAttestationConfiguration,
        FixedTimeClock(verificationTime),
        verificationTimeOffset
    )


    /**
     * Replay the attestation call that was recorded. I.e., it automatically calls the correct `replay` method
     * baaed on how this debug statement was recorded.
     */
    fun replaySmart() = when (method) {
        Method.LEGACY -> replayGenericAttestation()
        Method.SUPREME -> replayKeyAttestation()
        Method.KEY_ATTESTATION_LEGACY, Method.KEY_ATTESTATION_LEGACY_RAW -> replayKeyAttestationLegacy()
    }

    /**
     * Replays ```verifyAttestation(
     *         attestationProof: List<ByteArray>,
     *         challenge: ByteArray,
     *         clientData: ByteArray?
     *     ): AttestationResult```
     */
    fun replayGenericAttestation() =
        createWarden().verifyAttestation(genericAttestationProof!!, challenge!!, clientData)

    /**
     * Replays ```verifyKeyAttestation(
     *         attestationProof: Attestation,
     *         challenge: ByteArray
     *     ): KeyAttestation<PublicKey>```
     */
    fun replayKeyAttestation() = createWarden().verifyKeyAttestation(keyAttestation!!, challenge!!)

    /**
     * Replays ```verifyKeyAttestation(
     *         attestationProof: List<ByteArray>,
     *         challenge: ByteArray,
     *         encodedPublicKey: ByteArray
     *     ): KeyAttestation<PublicKey>```
     */
    fun replayKeyAttestationLegacy() =
        createWarden().verifyKeyAttestation(genericAttestationProof!!, challenge!!, clientData!!)

    /**
     * Produces a JSON representation of this debug info
     */
    fun serialize() = jsonDebug.encodeToString(this)

    /**
     * serializes and multibase-encodes this debug info
     */
    fun serializeCompact() = MultiBase.encode(MultiBase.Base.BASE64_URL, serialize().encodeToByteArray())

    companion object {
        /**
         * Parses a debug info from JSON
         */
        fun deserialize(string: String) = jsonDebug.decodeFromString<WardenDebugAttestationStatement>(string)

        /**
         * Multibase-decodes and deserializes a debug info string.
         */
        fun deserializeCompact(string: String) = deserialize(MultiBase.decode(string)!!.decodeToString())
    }
}

class FixedTimeClock(private val epochMilliseconds: Long) : Clock {
    constructor(instant: Instant) : this(instant.toEpochMilliseconds())
    constructor(yyyy: UInt, mm: UInt, dd: UInt) : this(
        Instant.parse(
            "$yyyy-${
                mm.toString().let { if (it.length < 2) "0$it" else it }
            }-${
                dd.toString().let { if (it.length < 2) "0$it" else it }
            }T00:00:00.000Z"
        )
    )

    override fun now() = Instant.fromEpochMilliseconds(epochMilliseconds)
}