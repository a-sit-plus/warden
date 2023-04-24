package at.asitplus.pki

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.FileInputStream
import java.math.BigInteger
import java.security.*
import java.security.KeyStore.PasswordProtection
import java.security.KeyStore.PrivateKeyEntry
import java.security.cert.X509Certificate
import java.util.*
import kotlin.random.Random


object KeySigner {
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    private val rootKey: PrivateKey
    val rootCert: X509Certificate

    init {
        Security.addProvider(BouncyCastleProvider())
        val keyStore = loadKS("root.p12", "changeit")
        (keyStore.getEntry("root", PasswordProtection("changeit".toCharArray())) as PrivateKeyEntry).let {
            rootKey = it.privateKey
            rootCert = (it.certificate as X509Certificate)
        }
    }


    fun createCertificate(publicKey: PublicKey): X509Certificate? = runCatching {

        // Setup start date to yesterday and end date for 1 year validity
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DATE, -1)
        val startDate = calendar.time
        calendar.add(Calendar.YEAR, 5)
        val endDate = calendar.time


        val issuedCertSubject = X500Name("CN=${names.random()}")
        val issuedCertSerialNum = BigInteger(Random.nextBytes(8))

        val p10Builder: PKCS10CertificationRequestBuilder =
            JcaPKCS10CertificationRequestBuilder(issuedCertSubject, publicKey)
        val csrBuilder = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")


        val csrContentSigner = csrBuilder.build(rootKey)
        val csr = p10Builder.build(csrContentSigner)

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        val issuedCertBuilder = X509v3CertificateBuilder(
            X500Name("CN=Attestation Root of Trust"),
            issuedCertSerialNum,
            startDate,
            endDate,
            csr.subject,
            csr.subjectPublicKeyInfo
        )
        val issuedCertExtUtils = JcaX509ExtensionUtils()

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(
            Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert)
        )
        issuedCertBuilder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            issuedCertExtUtils.createSubjectKeyIdentifier(csr.subjectPublicKeyInfo)
        )


        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, KeyUsage(KeyUsage.digitalSignature))
        val issuedCertHolder = issuedCertBuilder.build(csrContentSigner)

        JcaX509CertificateConverter().setProvider("BC").getCertificate(issuedCertHolder)
    }.getOrElse { it.printStackTrace(); null }

    private fun loadKS(name: String, pw: String) = FileInputStream(name).use { fin ->
        KeyStore.getInstance("PKCS12").also { it.load(fin, pw.toCharArray()) }
    }

}

private val names by lazy {
    KeySigner::class.java.classLoader.getResourceAsStream("random_names_fossbytes.csv").reader().readLines()
}
