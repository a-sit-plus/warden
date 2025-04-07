package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
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
    val androidAttestationConfiguration: AndroidAttestationConfiguration,
    val iosAttestationConfiguration: IOSAttestationConfiguration,
    val genericAttestationProof: List<@Serializable(with = ByteArrayBase64UrlSerializer::class) ByteArray>? = null,
    val keyAttestation: Attestation? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val clientData: ByteArray? = null,
    val verificationTime: Instant,
    val verificationTimeOffset: Duration = Duration.ZERO
) {
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

    companion object {
        /**
         * Parses a debug info from JSON
         */
        fun deserialize(string: String) = jsonDebug.decodeFromString<WardenDebugAttestationStatement>(string)
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