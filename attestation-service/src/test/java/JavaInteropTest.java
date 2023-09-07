import at.asitplus.attestation.*;
import at.asitplus.attestation.android.AndroidAttestationConfiguration;
import at.asitplus.attestation.android.exceptions.AttestationException;
import io.kotest.core.spec.style.AnnotationSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.suite.api.Suite;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;


public class JavaInteropTest {


    public static void testDefaults() {
        Assertions.assertThrows(AttestationException.class, () -> {
                    new DefaultAttestationService(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData(
                                    "at.asitplus.attestation-example", Collections.emptyList())).build(),
                            new IOSAttestationConfiguration(new IOSAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example")));
                },
                "No signature digests specified");

        Assertions.assertThrows(AttestationException.class, () -> {
                    new DefaultAttestationService(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>()
                            )).build(),
                            new IOSAttestationConfiguration(new IOSAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example")),
                            Duration.ZERO);
                },
                "No signature digests specified");

        Assertions.assertThrows(AttestationException.class, () -> {
                    new DefaultAttestationService(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>(),
                                    10)
                            ).build(),
                            new IOSAttestationConfiguration(new IOSAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example")),
                            Duration.ZERO);
                },
                "No signature digests specified");

        Assertions.assertThrows(AttestationException.class, () -> {
                    new DefaultAttestationService(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>(),
                                    10,
                                    10000)
                            ).build(),
                            new IOSAttestationConfiguration(new IOSAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example",
                                    true)),
                            Duration.ZERO);
                },
                "No signature digests specified");

        Assertions.assertThrows(AttestationException.class, () -> {
                    new DefaultAttestationService(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>()
                            )).build(),
                            new IOSAttestationConfiguration(new IOSAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example",
                                    false),
                                    "14.1"),
                            Duration.ZERO);
                },
                "No signature digests specified");
    }

    public static void testAttestationCallsJavaFriendliness() throws NoSuchAlgorithmException {
        AttestationService service = new DefaultAttestationService(
                new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                        Arrays.asList(new byte[][]{new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8}}))
                ).build(),
                new IOSAttestationConfiguration(new IOSAttestationConfiguration.AppData(
                        "1234567890",
                        "at.asitplus.attestation-example",
                        false),
                        "14.1"),
                Duration.ZERO);

        AttestationResult result = service.verifyAttestation(Collections.emptyList(), new byte[]{}, null);


        if (result instanceof AttestationResult.Android) {
            ((AttestationResult.Android) result).getAttestationCertificate();
            ((AttestationResult.Android) result).getAttestationRecord();
        }

        if (result instanceof AttestationResult.IOS) {
            ((AttestationResult.IOS) result).getClientData();
        }

        if (result instanceof AttestationResult.Error) {
            Throwable cause = ((AttestationResult.Error) result).getCause();
            String explanation = ((AttestationResult.Error) result).getExplanation();
            Assertions.assertEquals("Attestation proof is empty", explanation);
            Assertions.assertNull(cause);
        }

        Assertions.assertTrue(result instanceof AttestationResult.Error);


        KeyAttestation<ECPublicKey> keyAttestationResult = service.verifyKeyAttestation(Collections.emptyList(),
                new byte[]{0, 2, 3, 2, 2}, (ECPublicKey) KeyPairGenerator.getInstance("EC").
                        generateKeyPair().getPublic());


        Assertions.assertFalse(keyAttestationResult.isSuccess());
        Assertions.assertNull(keyAttestationResult.getAttestedPublicKey());


    }

}
