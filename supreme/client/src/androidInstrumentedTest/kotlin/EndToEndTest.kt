package at.asitplus.attestation.test

import androidx.test.filters.SmallTest
import at.asitplus.attestation.supreme.*
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign.Signer
import io.kotest.engine.runBlocking
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters


@SmallTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class EndToEndTest {


    val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"
    val ENDPOINT_SHUTDOWN = "http://10.0.2.2:8080/shutdown"


    val alias = "ALIAS"
    lateinit var client: AttestationClient

    @Before
    fun setup() {
        runBlocking {

            PlatformSigningProvider.deleteSigningKey(alias)
            client = AttestationClient(HttpClient())
        }
    }

    lateinit var attestationChallenge: AttestationChallenge

    @Test
    fun getChallenge() {
        runBlocking {

            val resp = client.getChallenge(Url(ENDPOINT_CHALLENGE))
            println(resp)
            resp.isSuccess shouldBe true
            attestationChallenge = resp.getOrThrow()
        }
    }

    lateinit var signer: Signer.Attestable<*>

    @Test
    fun initSigner() {
        runBlocking {

            signer = PlatformSigningProvider.createSigningKey(alias) {
                ec {}
                hardware {
                    attestation {
                        this.challenge = attestationChallenge.nonce
                    }
                }
            }.getOrThrow()
        }
    }

    @Test
    fun postAttestation() {
        runBlocking {
            val csr = signer.createCsr(attestationChallenge).getOrThrow()
            val result = client.attest(csr, attestationChallenge.attestationEndpointUrl)
            result.shouldBeInstanceOf<AttestationResponse.Success>()
        }
    }

    @Test
    fun shutdown() {
        runBlocking {
            HttpClient().get(ENDPOINT_SHUTDOWN)
        }
    }

}