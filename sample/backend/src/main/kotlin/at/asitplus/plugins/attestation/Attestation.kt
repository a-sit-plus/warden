@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.plugins.attestation

import at.asitplus.AttestationRequest
import at.asitplus.AttestationResponse
import at.asitplus.Challenge
import at.asitplus.Platform
import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.Warden
import at.asitplus.attestation.IOSAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.pki.KeySigner
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import kotlinx.datetime.Clock
import java.util.concurrent.LinkedBlockingQueue
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes


private object ChallengeService {

    private val cache = LinkedBlockingQueue<Challenge>()

    fun generate(): Challenge =
        Challenge(Random.nextBytes(16), Clock.System.now() + 5.minutes).apply { cache.put(this) }

    fun getAndRemove(challenge: ByteArray): Challenge? {
        cache.removeAll { (_, creationTime) -> (Clock.System.now() - creationTime) > 5.minutes }
        return cache.firstOrNull { (ch, _) -> ch.contentEquals(challenge) }?.also { cache.remove(it) }
    }
}


fun Application.configureAttestation() {
    val log = log

    log.info("Setting up attestation as follows:")

    val attestationService = Warden(
        androidAttestationConfiguration = AndroidAttestationConfiguration(AndroidAttestationConfiguration.AppData(
            packageName = environment.config.property("attestation.android.package-name").getString().also {
                log.info("Android package name: $it")
            },
            signatureDigests = environment.config.property("attestation.android.signature-digests").getList().also {
                log.info("Android signature digests: ${it.joinToString { it }}")
            }.map { it.decodeBase64Bytes() }),
            androidVersion = runCatching {
                environment.config.property("attestation.android.min-version").getString().toInt()
            }.getOrNull().also {
                log.info("Android minimum OS version: ${it ?: "none"}")
            }
        ),
        iosAttestationConfiguration = IOSAttestationConfiguration(
            IOSAttestationConfiguration.AppData(
                teamIdentifier = environment.config.property("attestation.ios.team-identifier").getString().also {
                    log.info("iOS team identifier: $it")
                },
                bundleIdentifier = environment.config.property("attestation.ios.bundle-identifier").getString().also {
                    log.info("iOS bundle identifier: $it")
                }, sandbox = environment.config.property("attestation.ios.sandbox").getString().toBoolean().also {
                    log.info("iOS sandbox: $it")
                }),
            iosVersion = runCatching {
                IOSAttestationConfiguration.OsVersions(
                    environment.config.property("attestation.ios.min-version").getString(),
                    environment.config.property("attestation.ios.min-buildnum").getString()
                )
            }.getOrNull().also {
                log.info("iOS minimum OS version: ${it ?: "none"}")
            }
        ),
        verificationTimeOffset = runCatching {
            environment.config.property("attestation.drift-minutes").getString().toLong()
        }.getOrElse { 0L }.minutes.also {
            log.info("Attestation Time Drift: $it")
        }
    )


    routing {
        route("/binding") {
            get("/start") {
                call.respond<Challenge>(ChallengeService.generate())
            }
            post("/create") {
                call.receive<AttestationRequest>().let { (challenge, proof, pubKey) ->
                    //So, here's the thing with the challenge:
                    //We can either extract it from the attestation proof and check directly.
                    //*OR* we can have the client send it separately, verify it against our challenge cache (i.e. do not
                    //bother the attestation library with this task at all and then simply pass the already verified
                    //challenge along to assure that the challenge sent separately does indeed match the challenge
                    //inside the attestation proof.
                    //
                    //We chose the latter and also recommend doing it this way, because it makes things so much easier
                    //and more robust.

                    val verifiedChallenge = ChallengeService.getAndRemove(challenge)?.challenge
                    if (verifiedChallenge == null) call.respond(
                        HttpStatusCode.BadRequest,
                        AttestationResponse.Error("Challenge invalid")
                    ) else {
                        val (status, message) = attestationService.verifyKeyAttestation(proof, challenge, pubKey)
                            .fold(
                                onError = {
                                    log.error(it.explanation)
                                    HttpStatusCode.BadRequest to AttestationResponse.Error(it.explanation)
                                },
                                onSuccess = { key, result ->
                                    KeySigner.createCertificate(key)?.let {
                                        HttpStatusCode.OK to AttestationResponse.Success(
                                            (if (result is AttestationResult.IOS) Platform.iOS else Platform.Android),
                                            listOf(it, KeySigner.rootCert)
                                        )
                                    } ?: (HttpStatusCode.InternalServerError to
                                            AttestationResponse.Error("internal server error"))
                                }
                            )
                        call.respond(status, message)
                    }

                }
            }
        }
    }
}