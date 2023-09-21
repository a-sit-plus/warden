package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.data.AttestationData
import at.asitplus.attestation.data.mimeDecoder
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds


val AttestationData.attestationProof: List<ByteArray>
    get() = attestationProofB64.map { mimeDecoder.decode(it) }


val pixel6KeyMint200Good = AttestationData(
    "Pixel 6",
    challengeB64 = "9w11c/H1kgfx+2Lqrqscug==",
    attestationProofB64 = listOf(
        """
                        MIICpzCCAk6gAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIGQ3MWRmYjM1NjNlNWQ5Y2I0NmRkMTJjMWJhMjI2YzM5MB4XDTIzMDQxNDE0MzAyMVoXDTQ4M
                        DEwMTAwMDAwMFowJTEjMCEGA1UEAxMaaHR0cDovLzE5Mi4xNjguMTc4LjMzOjgwODAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqzk1wE4o3jS27/n40sW8ZExFxgXopGSxihSaLCUqGHN
                        sZoAvMTY96sQznDM0p4LoRKu5klGgE+4efkP4d+gyQo4IBWTCCAVUwDgYDVR0PAQH/BAQDAgeAMIIBQQYKKwYBBAHWeQIBEQSCATEwggEtAgIAyAoBAQICAMgKAQEEEPcNdXPx9ZIH8fti6q6
                        rHLoEADBfv4U9CAIGAYeALKLxv4VFTwRNMEsxJTAjBB5hdC5hc2l0cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaehCDEG
                        AgECAgEDogMCAQOjBAICAQClCDEGAgECAgEEqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCAPbnXIAYO13sB0sAVNQnHpk4nr5LE2sIGd4fFQug/51wEB/woBAAQgNidLYFH3o3y3ufJGD1UzB
                        8M0ZzGpxDl7RrvUI0SJSwi/hUEFAgMB+9C/hUIFAgMDFj+/hU4GAgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNHADBEAiAYJTfwNDCSiw/fob8VIBSNnXfaQaoyLxVmbaP/U5e2AgIgAl
                        ngbOcR1syv1RP369hnI8cMh4xe1AFnB+H3Y9OVirQ=
                        """,
        """
                        MIIBwzCCAWqgAwIBAgIRANcd+zVj5dnLRt0SwboibDkwCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMB4XDTIzMDMyNjExNDk0OVoXDTIzM
                        DUwMTExNDk0OVowOTEMMAoGA1UEChMDVEVFMSkwJwYDVQQDEyBkNzFkZmIzNTYzZTVkOWNiNDZkZDEyYzFiYTIyNmMzOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJS3ylJ9AibrkDPP/W
                        4PBHmHU/e+yRiSTr4nLkojZzkBDWayhRI6PhrsN8Cetsp2EG2r2dQ60VnPvtvw9ElYYlGjYzBhMB0GA1UdDgQWBBQRvZZGVqzjrxcT1lU/u8OGt6xJSjAfBgNVHSMEGDAWgBTEfQBQs7lkcRy
                        V+Ok7Vmuti/ra9zAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAgNHADBEAiAjV7E60YcWRMdplr3lyh/M6nSHuADoGWdO10hP2h/81gIgTRHSnjjwPA3FGlyY
                        g8DGschrg3a7j8lEzLg2kRmzg9c=
                        """,
        """
                        MIIB1jCCAVygAwIBAgITKqOs6sgL8zCfdZ1InqRvUR51szAKBggqhkjOPQQDAzApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTIwHhcNMjMwMzI3MjMxMzUyWhcNM
                        jMwNTAxMjMxMzUxWjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGyo5Rgphmke9X1N+/0OBQzlUIsfWudjeXWa
                        FQOUl8VKN9y00pYQlyICzNAC4A9/f92tNhF3RkCn//Xfae9zcDo2MwYTAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUxH0AULO5ZHEclfjpO1ZrrYv62vcwHwY
                        DVR0jBBgwFoAUu/g2rYmubOLlnpTw1bLX0nrkfEEwCgYIKoZIzj0EAwMDaAAwZQIwffCbRJ9FCtNJopq2R2L0cpeoLKZTmu3SD2tcnU1CxBbEnhBA8Jl1giOBPsdB+VrPAjEA74XTlWF8C2Um
                        zwiCRxemo+tlw9EJ752ljAIwlUOWErA40tIGRe18736YdxM/zC8X
                        """,
        """
                        MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNDc1MloXDTM3MDEyMjIyNDc1MlowKTETMBEGA
                        1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuppxbZvJgwNXXe6qQKidXqUt1ooT8M6Q+ysWIwpduM2EalST8v/Cy2JN10aqTfUSTh
                        Jha/oCtG+F9TUUviOch6RahrpjVyBdhopM9MFDlCfkiCkPCPGu2ODMj7O/bKnko2YwZDAdBgNVHQ4EFgQUu/g2rYmubOLlnpTw1bLX0nrkfEEwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8
                        aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAIFxUiFHYfObqrJM0eeXI+kZFT57wBplhq+TEjd+78nIWbKvKGUFlvt7IuXHzZ7Y
                        JdtSDs7lFtCsxXdrWEmLckxRDCRcth3Eb1leFespS35NAOd0Hekg8vy2G31OWAe567l6NdLjqytukcF4KAzHIRxoFivN+tlkEJmg7EQw9D2wPq4KpBtug4oJE53R9bLCT5wSVj63hlzEY3hC0
                        NoSAtp0kdthow86UFVzLqxEjR2B1MPCMlyIfoGyBgkyAWhd2gWN6pVeQ8RZoO5gfPmQuCsn8m9kv/dclFMWLaOawgS4kyAn9iRi2yYjEAI0VVi7u3XDgBVnowtYAn4gma5q4BdXgbWbUTaMVV
                        VZsepXKUpDpKzEfss6Iw0zx2Gql75zRDsgyuDyNUDzutvDMw8mgJmFkWjlkqkVM2diDZydzmgi8br2sJTLdG4lUwvedIaLgjnIDEG1J8/5xcPVQJFgRf3m5XEZB4hjG3We/49p+JRVQSpE1+Q
                        zG0raYpdNsxBUO+41diQo7qC7S8w2J+TMeGdpKGjCIzKjUDAy2+gOmZdZacanFN/03SydbKVHV0b/NYRWMa4VaZbomKON38IH2ep8pdj++nmSIXeWpQE8LnMEdnUFjvDzp0f0ELSXVW2+5xbl
                        +fcqWgmOupmU4+bxNJLtknLo49Bg5w9jNn7T7rkF
                        """,
        """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDV
                        QQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tq
                        w1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRx
                        B/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvs
                        BslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er
                        5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/b
                        kwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAM
                        BAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6Wszodm
                        MkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3
                        UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoB
                        IuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJgu
                        Bw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWU
                        DqG8At2JHA==
                        """
    ),
    isoDate = "2023-04-14T14:30:21Z",
    pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqs5NcBOKN40tu/5+NLFvGRMRcYF6KRksYoUmiwlKhhzbGaALzE2PerEM5wzNKeC6ESruZJRoBPuHn5D+HfoMkA=="
)
val nokiaX10KeyMasterGood = AttestationData(
    "Nokia X10",
    challengeB64 = "HcAotmy6ZBX8cnh5mvMc2w==",
    attestationProofB64 = listOf(
        """
                        MIICozCCAkigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDg4NGY4MTlkYzAxMjJkYjFmNGFiZDI4YzllNzBmM2QwMCAXDTcwMDEwMTAwMDAwMFoYDzIxMDYwMjA3MDY
                        yODE1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC9z3T/NtNDTc94eKdG3MKz4pIg+frP6j1zf3h4pE3fEZ0IrrXM+LagKuDV4HJ
                        oy4hHDSDrZD0youOREwxKKj6SjggFXMIIBUzAOBgNVHQ8BAf8EBAMCB4AwggE/BgorBgEEAdZ5AgERBIIBLzCCASsCAQMKAQECAQQKAQEEEB3AKLZsumQV/HJ4eZrzHNsEADBfv4U9CAIGAYd/5
                        YkQv4VFTwRNMEsxJTAjBB5hdC5hc2l0cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaehCDEGAgECAgEDogMCAQOjBAICAQCl
                        CDEGAgEEAgECqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDU9Nwdz6RJ5XFKxYBLU0JAfUxps3hHRVc6cnRct9Wb9gEB/woBAAQgJ+BQyXYw7V5iEtU6QFzXeCnCpi75mTof21kND/tR7YC/hUE
                        FAgMB+9C/hUIFAgMDFj+/hU4GAgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNJADBGAiEAmSuuN2StHrBfO3J9tR45vcq/22Gn5cXKXt+DR45MBroCIQCuabv+4ia9Y7w8ooHzql2OVYiDat
                        qR9k5YUPABdVwd1g==
                        """,
        """
                        MIIB8zCCAXqgAwIBAgIRALdlXIz6RNuRvfQY1AsxwIwwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODAeFw0yMDA5MjgyMDE
                        4NDhaFw0zMDA5MjYyMDE4NDhaMDkxDDAKBgNVBAwMA1RFRTEpMCcGA1UEBRMgODg0ZjgxOWRjMDEyMmRiMWY0YWJkMjhjOWU3MGYzZDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmhTTiVh
                        Hty0CEC/ZOmZukvtlo0oVljIk/X66yucR13UfkzVzErNuM7Dznj0yGlSylkSTeJOYRUD82AYMQPwJFo2MwYTAdBgNVHQ4EFgQUPY4E/H/RzXhd1rVjbMikMLz6CLMwHwYDVR0jBBgwFoAUwlMBr
                        j5jAa/ypZzVX4CUjgAyTjwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDZwAwZAIwCsSg1hhIw9M3OFndg+2OzsCCCtyckDEYeQZLSc1w+LNAqsxkC6p/yhmg
                        G+jyIDB7AjAyg7gzKF6ymsSQ+C55zoCS+InIaIK8ruz9RE4J7lC6SIvMCMXhmyoelkZ7aWARKaI=
                        """,
        """
                        MIIDkzCCAXugAwIBAgIQFk/xbbOK0z0ZBF99wwx/zDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIwMDkyODIwMTc0OVoXDTMwMDkyNjIwMTc0OVowOTEMMAoGA1U
                        EDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODB2MBAGByqGSM49AgEGBSuBBAAiA2IABJHz0uU3kbaMjfVN38GXDgIBLl4Gp7P59n6+zmqoswoBrbrsCi
                        FOWUU+B918FnEVcW86joLS+Ysn7msakvrHanJMJ4vDwD7/p+F6nkQ9J95FEkuq71oGTzCrs6SlCHu5XqNjMGEwHQYDVR0OBBYEFMJTAa4+YwGv8qWc1V+AlI4AMk48MB8GA1UdIwQYMBaAFDZh4
                        QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQAnO5KNrbenSYxIOfzxH47CNi3Qz2O5+FoPW7svNjggg/hZotSwbddp
                        SVa+fdQYYYZdHMPNjQKXYaDxPPC2i/8KBhscq+TW1k9YKP+qNGMZ2CKzRIT0pByL0M5LQNbH6VxAvzGlaCvTOIsDmlLyjzmT9QMtjWkmLKduISOa72hGMM4kCcIRKcgsq/s00whsOJ6IT27lp85
                        AATuL9NvNE+kC1TZ96zEsR8Oplur4euBmFoGzmtSFsZa9TNyc68RuJ+n/bY7iI77wXUz7ER6uj/sfnrjYJFclLjIjm8Mqp69IZ1nbJsKTgg0e5X4xeecNPLSMp/hGqDOvNnSVbpri6Djm0ZWILk
                        65BeRxANDUhICg/iuXnbSLIgPAIxsmniTV41nnIQ2nwDxVtfStsPzSWeEKkMTeta+Lu8jKKVDcRTt2zoGx+JOQWaEWpOTUM/xZwnJamdHsKBWsskQhFMxLIPJbMeYAeCCswDTE+LQv31wDTxSrF
                        Vw/fcfVY6PSRZWoy+6Q/zF3JATwQnYxNUchZG4suuy/ONPbOhD0VdzjkSyza6fomTw2F1G3c4jSQIiNV3OIxsxh4ja1ssJqMPuQzRcGGXxX8yQHrg+t+Dxn32jFVhl5bxTeKuI6mWBYM+/qEBTB
                        EXLNSmVdxrntFaPmiQcguBSFR1oHZyi/xS/jbYFZEQ==
                        """,
        """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTI
                        wMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlR
                        fdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC
                        4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS
                        +tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVt
                        CLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8
                        WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDA
                        gIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXE
                        ydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZ
                        qZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1
                        R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/A
                        wqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2JHA==
                        """
    ),
    isoDate = "2023-04-15T00:00:00Z",
    pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL3PdP8200NNz3h4p0bcwrPikiD5+s/qPXN/eHikTd8RnQiutcz4tqAq4NXgcmjLiEcNIOtkPTKi45ETDEoqPpA=="
)

val androidGood = listOf(
    nokiaX10KeyMasterGood,
    pixel6KeyMint200Good,
)

//TODO eternal leaves
//TODO samsung

val ios16 = AttestationData(
    "iPhone 11",
    challengeB64 = "aRkq0BvWmx4QIm/1CfYNoQ==",
    attestationProofB64 = listOf(
        """
                o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAvEwggLtMIICc6ADAgECAgYB
                h3rs7tEwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENB
                IDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjMwNDEy
                MTQwMjQwWhcNMjMxMjI1MTUyNjQwWjCBkTFJMEcGA1UEAwxAOTRhOWJhMjAxNzQ1NzU2MDAy
                MWRhYTRlYjAyZDcxNWVkNzZiZmJjOWVjZjNiMzU4YjcxYzdkZDhjNGNkZDdkNzEaMBgGA1UE
                CwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNh
                bGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASS1Yzn9H6qomUnxfQ78v5XZ2oR
                w/QBrvTZNxpw43vO0Xr0GiEGdJe2gB7OxU5bZd/WmI0TOEOL2l/4N6GSn56Co4H3MIH0MAwG
                A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMIGDBgkqhkiG92NkCAUEdjB0pAMCAQq/iTAD
                AgEBv4kxAwIBAL+JMgMCAQG/iTMDAgEBv4k0KwQpOUNZSEpORzY0NC5hdC5hc2l0cGx1cy5h
                dHRlc3RhdGlvbi1jbGllbnSlBgQEc2tzIL+JNgMCAQW/iTcDAgEAv4k5AwIBAL+JOgMCAQAw
                GQYJKoZIhvdjZAgHBAwwCr+KeAYEBDE2LjIwMwYJKoZIhvdjZAgCBCYwJKEiBCA8hv/PE/js
                u97Ds4YnGstWW82Rhk8kQju10q+ScYd5IDAKBggqhkjOPQQDAgNoADBlAjEAoSR6nDJfxYRg
                +42xZa9ddIOSdupGrzdY+0331SE8FtASesvwm06vsBoqBdYeYM4VAjBAASbn6hSEtEpeOCNN
                Tj2o77Xhb075z5ZTeOdM18tuxlN9WpoKFlMyJgJdipl4CDVZAkcwggJDMIIByKADAgECAhAJ
                usXhvEAa2dRTlbw4GghUMAoGCCqGSM49BAMDMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRl
                c3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
                bmlhMB4XDTIwMDMxODE4Mzk1NVoXDTMwMDMxMzAwMDAwMFowTzEjMCEGA1UEAwwaQXBwbGUg
                QXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNh
                bGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASuWzegd015sjWPQOfR8iYm8cJf7xeA
                LeqzgmpZh0/40q0VJXiaomYEGRJItjy5ZwaemNNjvV43D7+gjjKegHOphed0bqNZovZvKdsy
                r0VeIRZY1WevniZ+smFNwhpmzpmjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgw
                FoAUrJEQUzO9vmhB/6cMqeX66uXliqEwHQYDVR0OBBYEFD7jXRwEGanJtDH4hHTW4eFXcuOb
                MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNpADBmAjEAu76IjXONBQLPvP1mbQlXUDW8
                1ocsP4QwSSYp7dH5FOh5mRya6LWu+NOoVDP3tg0GAjEAqzjt0MyB7QCkUsO6RPmTY2VT/swp
                fy60359evlpKyraZXEuCDfkEOG94B7tYlDm3Z3JlY2VpcHRZDm0wgAYJKoZIhvcNAQcCoIAw
                gAIBATEPMA0GCWCGSAFlAwQCAQUAMIAGCSqGSIb3DQEHAaCAJIAEggPoMYIEJjAxAgECAgEB
                BCk5Q1lISk5HNjQ0LmF0LmFzaXRwbHVzLmF0dGVzdGF0aW9uLWNsaWVudDCCAvsCAQMCAQEE
                ggLxMIIC7TCCAnOgAwIBAgIGAYd67O7RMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxl
                IEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApD
                YWxpZm9ybmlhMB4XDTIzMDQxMjE0MDI0MFoXDTIzMTIyNTE1MjY0MFowgZExSTBHBgNVBAMM
                QDk0YTliYTIwMTc0NTc1NjAwMjFkYWE0ZWIwMmQ3MTVlZDc2YmZiYzllY2YzYjM1OGI3MWM3
                ZGQ4YzRjZGQ3ZDcxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBs
                ZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
                ktWM5/R+qqJlJ8X0O/L+V2dqEcP0Aa702TcacON7ztF69BohBnSXtoAezsVOW2Xf1piNEzhD
                i9pf+Dehkp+egqOB9zCB9DAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DCBgwYJKoZI
                hvdjZAgFBHYwdKQDAgEKv4kwAwIBAb+JMQMCAQC/iTIDAgEBv4kzAwIBAb+JNCsEKTlDWUhK
                Tkc2NDQuYXQuYXNpdHBsdXMuYXR0ZXN0YXRpb24tY2xpZW50pQYEBHNrcyC/iTYDAgEFv4k3
                AwIBAL+JOQMCAQC/iToDAgEAMBkGCSqGSIb3Y2QIBwQMMAq/ingGBAQxNi4yMDMGCSqGSIb3
                Y2QIAgQmMCShIgQgPIb/zxP47Lvew7OGJxrLVlvNkYZPJEI7tdKvknGHeSAwCgYIKoZIzj0E
                AwIDaAAwZQIxAKEkepwyX8WEYPuNsWWvXXSDknbqRq83WPtN99UhPBbQEnrL8JtOr7AaKgXW
                HmDOFQIwQAEm5+oUhLRKXjgjTU49qO+14W9O+c+WU3jnTNfLbsZTfVqaChZTMiYCXYqZeAg1
                MCgCAQQCAQEEINI6ZKJMwFowZ3a3fOFii20AmI4tW4c76DCPYcgQxUk9MGACAQUCAQEEWGov
                TG9FMndPQnJUNCtwYmwveUI4NVk2d2lzT3hYcm5keXVJRHNrdFZYem1DWDU2TE50WkppMHJL
                OHByaVN3ZGdwZlEreHZhZXJxKzNiVFhIK1E0bTR3PT0wDgIBBgIBAQQGQVRURVNUMBICAQcC
                AQEECnByb2R1Y3Rpb24wIARCAgEMAgEBBBgyMDIzLTA0LTEzVDE0OjAyOjQwLjc1NVowIAIB
                FQIBAQQYMjAyMy0wNy0xMlQxNDowMjo0MC43NTVaAAAAAAAAoIAwggOuMIIDVKADAgECAhAJ
                ObS86QzDoYFlNjcvZnFBMAoGCCqGSM49BAMCMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0
                aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlv
                biBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTIyMDQx
                OTEzMzMwM1oXDTIzMDUxOTEzMzMwMlowWjE2MDQGA1UEAwwtQXBwbGljYXRpb24gQXR0ZXN0
                YXRpb24gRnJhdWQgUmVjZWlwdCBTaWduaW5nMRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYD
                VQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDnU+aqbHMRF1lumF6zywITsbwcI
                1ZAUoOduzz3uOZmpTGv7AVUQVVVkbNqOI+AmARQC0H4TuVQf2LTWV9guk3ijggHYMIIB1DAM
                BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFNkX/ktnkDhLkvTbztVXgBQLjz3JMEMGCCsGAQUF
                BwEBBDcwNTAzBggrBgEFBQcwAYYnaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hYWlj
                YTVnMTAxMIIBHAYDVR0gBIIBEzCCAQ8wggELBgkqhkiG92NkBQEwgf0wgcMGCCsGAQUFBwIC
                MIG2DIGzUmVsaWFuY2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNzdW1l
                cyBhY2NlcHRhbmNlIG9mIHRoZSB0aGVuIGFwcGxpY2FibGUgc3RhbmRhcmQgdGVybXMgYW5k
                IGNvbmRpdGlvbnMgb2YgdXNlLCBjZXJ0aWZpY2F0ZSBwb2xpY3kgYW5kIGNlcnRpZmljYXRp
                b24gcHJhY3RpY2Ugc3RhdGVtZW50cy4wNQYIKwYBBQUHAgEWKWh0dHA6Ly93d3cuYXBwbGUu
                Y29tL2NlcnRpZmljYXRlYXV0aG9yaXR5MB0GA1UdDgQWBBT7Z9MNv3O3kqYmXUiNLMEdleJz
                +DAOBgNVHQ8BAf8EBAMCB4AwDwYJKoZIhvdjZAwPBAIFADAKBggqhkjOPQQDAgNIADBFAiEA
                lJCgZzdz5y94KTZ2I7jdUdfImgnquwDjnG5FCwVYC9ACIEc0GivRPMBUqAo6qsw8wUV8AFRT
                GOozjX1t1fYLK4cuMIIC+TCCAn+gAwIBAgIQVvuD1Cv/jcM3mSO1Wq5uvTAKBggqhkjOPQQD
                AzBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRp
                ZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAe
                Fw0xOTAzMjIxNzUzMzNaFw0zNDAzMjIwMDAwMDBaMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxp
                Y2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNh
                dGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYH
                KoZIzj0CAQYIKoZIzj0DAQcDQgAEks5jvX2GsasoCjsc4a/7BJSAkaz2Md+myyg1b0RL4SHl
                V90SjY26gnyVvkn6vjPKrs0EGfEvQyX69L6zy4N+uqOB9zCB9DAPBgNVHRMBAf8EBTADAQH/
                MB8GA1UdIwQYMBaAFLuw3qFYM4iapIqZ3r6966/ayySrMEYGCCsGAQUFBwEBBDowODA2Bggr
                BgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJvb3RjYWczMDcG
                A1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3Js
                MB0GA1UdDgQWBBTZF/5LZ5A4S5L0287VV4AUC489yTAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZI
                hvdjZAYCAwQCBQAwCgYIKoZIzj0EAwMDaAAwZQIxAI1vpp+h4OTsW05zipJ/PXhTmI/02h9Y
                HsN1Sv44qEwqgxoaqg2mZG3huZPo0VVM7QIwZzsstOHoNwd3y9XsdqgaOlU7PzVqyMXmkrDh
                Yb6ASWnkXyupbOERAqrMYdk4t3NKMIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0E
                AwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0
                aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMw
                HhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290
                IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYD
                VQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjp
                Lz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBP
                EVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYE
                FLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG
                MAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvO
                wgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vL
                UagM6BgD56KyKAAAMYH+MIH7AgEBMIGQMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9u
                IEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBB
                dXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTAhAJObS86QzDoYFl
                NjcvZnFBMA0GCWCGSAFlAwQCAQUAMAoGCCqGSM49BAMCBEgwRgIhAPDinR30x2gXYUR4p34q
                meC7mI6yUioYABvq62DrGOM2AiEA+ZytzwX1s8saNFxJZ50Z7jk6t++FVbQdLg6+OdWKYnsA
                AAAAAABoYXV0aERhdGFYpKERrYsSTaM3YpZTFuU5cr8aE+F5QNvbtpvG4bfWKUbTQAAAAABh
                cHBhdHRlc3QAAAAAAAAAACCUqbogF0V1YAIdqk6wLXFe12v7yezzs1i3HH3YxM3X16UBAgMm
                IAEhWCCS1Yzn9H6qomUnxfQ78v5XZ2oRw/QBrvTZNxpw43vO0SJYIHr0GiEGdJe2gB7OxU5b
                Zd/WmI0TOEOL2l/4N6GSn56C
                """"",
        """
                omlzaWduYXR1cmVYRzBFAiEA53GCmQ2236JBDsxIKIdauZuT/eR7P4zeICwUvyJxTtkCIDn6
                rivY7ZQeB4JnwU3GrqENn39G/fPQ6flk1Pk0jzdPcWF1dGhlbnRpY2F0b3JEYXRhWCWhEa2L
                Ek2jN2KWUxblOXK/GhPheUDb27abxuG31ilG00AAAAAB
                """""
    ),
    isoDate = "2023-04-12T14:02:40Z",
    pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEoHa3s8Au2QoovqslpA2X6kczRLSNnSzEvaIgFO03iRylBevYIh0jktyMtCnOhOeqcb4fyO/83QCRMMXGgvK9A=="
)
val iosGood = listOf(
    ios16,
)

const val ANDROID_PACKAGE_NAME = "at.asitplus.attestation_client"

val ANDROID_SIGNATURE_DIGESTS = listOf(
    "NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=".decodeBase64ToArray(),
    /*this one's an invalid digest and must not affect the tests*/
    "LvfTC77F/uSecSfJDeLdxQ3gZrVLHX8+NNBp7AiUO0E=".decodeBase64ToArray()!!
)

val DEFAULT_IOS_ATTESTATION_CFG = IOSAttestationConfiguration(
    applications = listOf(
        IOSAttestationConfiguration.AppData(
            "9CYHJNG644",
            bundleIdentifier = "at.asitplus.attestation-client",
            sandbox = false
        )
    )
)

fun attestationService(
    androidPackageName: String = ANDROID_PACKAGE_NAME,
    androidAppSignatureDigest: List<ByteArray> = ANDROID_SIGNATURE_DIGESTS,
    androidVersion: Int? = 10000,
    androidAppVersion: Int? = 1,
    androidPatchLevel: PatchLevel? = PatchLevel(2021, 8),
    requireStrongBox: Boolean = false,
    unlockedBootloaderAllowed: Boolean = false,
    requireRollbackResistance: Boolean = false,
    iosTeamIdentifier: String = "9CYHJNG644",
    iosBundleIdentifier: String = "at.asitplus.attestation-client",
    iosVersion: String? = "14",
    iosSandbox: Boolean = false,
    timeSource: Clock,
    offset: Duration = 0.seconds,
    eternalLeaves: Boolean = false,
    androidSW: Boolean = false,
    androidN: Boolean=false,
) =
    DefaultAttestationService(
        AndroidAttestationConfiguration(
            applications = listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = androidPackageName,
                    signatureDigests = androidAppSignatureDigest,
                    appVersion = androidAppVersion
                )
            ),
            androidVersion = androidVersion,
            patchLevel = androidPatchLevel,
            requireStrongBox = requireStrongBox,
            allowBootloaderUnlock = unlockedBootloaderAllowed,
            requireRollbackResistance = requireRollbackResistance,
            ignoreLeafValidity = eternalLeaves,
            enableSoftwareAttestation = androidSW,
            enableNougatAttestation = androidN,
        ),
        IOSAttestationConfiguration(
            applications = listOf(
                IOSAttestationConfiguration.AppData(
                    iosTeamIdentifier,
                    iosBundleIdentifier,
                    sandbox = iosSandbox
                )
            ),
            iosVersion = iosVersion
        ),
        timeSource,
        offset
    )


internal class FixedTimeClock(private val epochMilliseconds: Long) : Clock {
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

private object TestTimeSource : Clock {
    const val timePeriod = 2021

    private val clock: Clock = TestClock


    fun offset(duration: Duration) {
        fixedClock = FixedTimeClock((fixedClock.now() + duration))
    }

    override fun now() = clock.now()


    private var fixedClock =
        FixedTimeClock(Instant.parse("$timePeriod-10-11T00:00:00.000Z"))

    private object TestClock : Clock {

        override fun now() =
            fixedClock.now()

    }
}
