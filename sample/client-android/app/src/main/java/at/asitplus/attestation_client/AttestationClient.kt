package at.asitplus.attestation_client

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import at.asitplus.attestation.AttestationRequest
import at.asitplus.attestation.AttestationResponse
import at.asitplus.attestation.Challenge
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.*
import javax.security.auth.x500.X500Principal


class AttestationClient {
    private val client = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }

        install(DefaultRequest) {
            header(HttpHeaders.ContentType, ContentType.Application.Json)
        }

        install(Logging) {
            logger = Logger.DEFAULT
            level = LogLevel.ALL
        }
    }

    suspend fun startBinding(host: String) = runCatching { client.get("$host/binding/start").body<Challenge>() }

    suspend fun createBinding(host: String, challenge: ByteArray) = runCatching {
        val pubKey =
            (generateKeyPair(host, challenge) as ECPublicKey?) ?: throw SecurityException("could not generate key pair")
        val req = AttestationRequest(challenge, loadCertChain(host).map { it.encoded }, pubKey)
        client.post("$host/binding/create") {
            setBody(req)
        }.body<AttestationResponse>()

    }


    suspend fun accessProtected(host: String, certChain: List<Certificate>?) = runCatching {
        client.get("$host/protected") {
            accept(ContentType.Text.Plain)
            certChain?.also { bearerAuth(createJWT(host, it).serialize()) }
        }
    }


    private fun generateKeyPair(alias: String, challenge: ByteArray): PublicKey? {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY //we want to sign a JWT
        ).setKeySize(256) //256-bit key
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA1, //technically, we don't even need this
            )
            .setCertificateNotBefore(Date()) //valid since now
            .setCertificateSubject(X500Principal("CN=$alias")) //depending on the android version this is ignored anyway
            .setUserAuthenticationRequired(false) //no need to require auth, it's just a demo
            .setAttestationChallenge(challenge) // this is crucial, in order to generate a certificate with attestation extensions


        val keyPairGenerator: KeyPairGenerator = //let's roll
            KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
                initialize(builder.build())
            }
        return keyPairGenerator.generateKeyPair().public //the private key is useless, since it only references an object stored in HW
    }

    private fun loadCertChain(alias: String): List<X509Certificate> =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
            it.getCertificateChain(alias).map { it as X509Certificate }
        }

    fun purge(host: String) = runCatching {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
            it.deleteEntry(host)
        }
    }

    private fun createJWT(alias: String, certChain: List<Certificate>): SignedJWT {

        //load the HW-backed private key
        val privKey = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
            it.getKey(alias, null) as PrivateKey
        }

        // Create the EC signer
        val signer: JWSSigner =
            ECDSASigner(
                ECKey.Builder(Curve.P_256, certChain.first().publicKey as ECPublicKey).privateKey(privKey).build()
            )


        // Prepare JWT with claims set
        val claimsSet = JWTClaimsSet.Builder()
            .subject("Attested Android Client") //irrelevant
            .issueTime(Date())
            .build()

        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(certChain.map { com.nimbusds.jose.util.Base64.encode(it.encoded) }).build(),
            claimsSet
        )

        // Compute the EC signature
        signedJWT.sign(signer)

        // Serialize the JWS to compact form
        return signedJWT

    }

}