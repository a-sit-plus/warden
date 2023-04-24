# Dead-Simple Key Attestation Demo Service

This dead-simple key attestation demo service showcases [our Attestation Library](https://github.com/a-sit-plus/attestation-service) in action.
Apps for [Android](../client-android) and [iOS](../client-ios) demonstrate the respective client parts.
For in-depth documentation regarding the Attestation library, please refer to the [official documentation](../../README.md).

## Overview

This service is based on [ktor](https://ktor.io) and establishes trust in mobile clients based on
[our Attestation Library](https://github.com/a-sit-plus/attestaton-service). This concrete incarnation utilises the attestation library's unified
interface to provide key attestation on both Android and iOS.

The process to attest a mobile client works a follows:

1. A client connects to obtain a challenge. This challenge is valid for five minutes.
2. Within those five minutes, the client may post an attestation request to this service, based on this challenge,
   a platform-specfic attestation proof, and a public key to be attested and certified.
3. On success, the service issues a certificate for the previously posted public key and responds with
   a certificate chain starting with this so-called binding certificate. The chain terminates at the
   service's signing certificate, which also serves as root of trust.
4. The client may now access a protected resource using JWT authentication. If the JWT is correctly signed
   using a valid binding certificate, access is granted.
5. ???
6. PROFIT!

This process corresponds 1:1 to service endpoints. In addition, a hello-world endpoint is present, which totals
to the endpoints described below:

### `/`
returns *Hello World* to verify it's up and running


### `/binding/start`
Creates and returns a challenge to start a binding process:

#### Example Request
```http request
GET /binding/start HTTP/1.1
Host: 192.168.178.33:8080
Accept: application/json
Accept-Charset: UTF-8
User-Agent: Ktor client
Content-Type: application/json
```

#### Example Response
```http request
HTTP/1.1 200 OK
Content-Length: 64
Content-Type: application/json; charset=UTF-8

{"challenge":"XJCMLMmZcc77q5kt9Asjpw==","validUntil":1681457601}
```

### `/binding/create`
Expects an attestation proof containing, the challenge obtained from `/binding/start` and the public key to be attested.
  <br>
  On success, it returns a certificate chain, whose leaf is issued for the public key, terminating in this service's
  signing certificate

#### Example Request
```http request
POST /binding/create HTTP/1.1
Host: 192.168.178.33:8080
Content-Length: 4772
User-Agent: Ktor client
Accept: application/json
Accept-Charset: UTF-8
Content-Type: application/json

{"challenge":"XJCMLMmZcc77q5kt9Asjpw==","attestationProof":["MII…","MI…",…],"publicKey":"MFkwEwYHKoZIzj0CA…"}
```

#### Example Response
```http request
HTTP/1.1 200 OK
Content-Length: 1236
Content-Type: application/json; charset=UTF-8

{"status":"Success","platform":"Android","certificateChain":["MII…","MI…"]}
```


### `/protected`
Can only be accessed by clients which successfully authenticated using a JWT signed by the binding certificate.
The JWT header must contain a certificate chain (`x5c`) starting at the binding certificate and terminating at this
service's signing certificate (as obtained by `/binding/create`). Apart from that, only cryptographic and temporal
verifications are performed on the JWT (i.e. the subject can be freely defined and custom claims are ignored altogether).
<br>
The JWT is passed in the `Authorization` header using the `Bearer` schema (i.e. `Authorization: Bearer ey…`)


#### Example Request
```http request
GET /protected HTTP/1.1
Host: 192.168.178.33:8080
Accept: text/plain,application/json
Authorization: Bearer eyJ4NWMiOlsiTUlJQnZqQ0NBV1dnQXdJQkFnSUlKMTRWVXNyOGFwVXdDZ1lJS29aSXpqMEVBd0l3SkRFaU1DQUdBMVVFQXd3WlFYUjBaWE4wWVhScGIyNGdVbTl2ZENCdlppQlVjblZ6ZERBZUZ3MHlNekEwTVRNd056TTNNREZhRncweU9EQTBNVE13TnpNM01ERmFNQmd4RmpBVUJnTlZCQU1NRFV4MWFYcGhJR1JoSUUxaGRHRXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUktINEdSd2lnaEJBQjRsanFDTXB0YUtIYytsS3RPaDVDYXhLL3JxbTNFcFgvL2MwS2pRYWFQTGRodkU5OThkbUp0WHB4YUZlYTRTM2I1dUE0MVpiWkpvNEdNTUlHSk1Bd0dBMVVkRXdFQi93UUNNQUF3VFFZRFZSMGpCRVl3UklBVVBOemxEMWQvTXZUWEU1cUowc0VRLy9XK0pRdWhLS1FtTUNReElqQWdCZ05WQkFNTUdVRjBkR1Z6ZEdGMGFXOXVJRkp2YjNRZ2IyWWdWSEoxYzNTQ0FnVTVNQjBHQTFVZERnUVdCQlFkN29VQnpnRnNHSVdTbjBCN1A5T3M1UDZjWnpBTEJnTlZIUThFQkFNQ0I0QXdDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdYZ2JkbnNJUU5ZSXo1ZkJiNG8yRDZseElEOEMrQ29Ob3JjbkRDaEpSK3BNQ0lFeEFiVy9sajJLVURKSk5IQzNWMlVMcEIvNXlaZXJkeE92UWh6RnlrTGVDIiwiTUlJQm16Q0NBVUdnQXdJQkFnSUNCVGt3Q2dZSUtvWkl6ajBFQXdJd0pERWlNQ0FHQTFVRUF3d1pRWFIwWlhOMFlYUnBiMjRnVW05dmRDQnZaaUJVY25WemREQWVGdzB5TXpBek16RXlNakF3TURCYUZ3MHlOREF6TXpFeU1UVTVOVGxhTUNReElqQWdCZ05WQkFNTUdVRjBkR1Z6ZEdGMGFXOXVJRkp2YjNRZ2IyWWdWSEoxYzNRd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRdGxHRmdFelVJN2Nqc0N6Szl2MlJ1MWVHMHZVWGY1MTdoSktid0NMajUzN0JLckR1T0dKbW51TStBbXdzNHpWN3ZxRDM1M2MzMkpJb2RNeWJCTlpSeW8yTXdZVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTRHQTFVZER3RUIvd1FFQXdJQkJqQWZCZ05WSFNNRUdEQVdnQlE4M09VUFYzOHk5TmNUbW9uU3dSRC85YjRsQ3pBZEJnTlZIUTRFRmdRVVBOemxEMWQvTXZUWEU1cUowc0VRLy9XK0pRc3dDZ1lJS29aSXpqMEVBd0lEU0FBd1JRSWhBTTdkN2dsYU9XYnU5U3ZwT1BaVUhielM4TWRRUmhSMk55RkU5aVYwSzlTWkFpQWJ4YmVSRjNqUW9WczlzU20rZStTY0pWalNkblgzUlZlRHRHWEpXMFFGc2c9PSJdLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJBdHRlc3RlZCBBbmRyb2lkIENsaWVudCIsImlhdCI6MTY4MTQ1NzgyMn0.lAv01a_mjCUVIN3cmEEsgwM0khrKbjgoTaLTfs4Zfg-UXzllILRHpb8YIV5gzO_xe-GpmJCOI77MQw_cvwiGTQ
Accept-Charset: UTF-8
User-Agent: Ktor client
Content-Type: application/json
```

#### Example Response
```http request
HTTP/1.1 200 OK
Content-Length: 59
Content-Type: text/plain; charset=UTF-8

Welcome, Luiza da Mata!
This message is for your eyes only.
```

## Development
Minimum JDK Version required: 11.

To produce a runnable jar, run `/.gradlew buildFatJar`

## Source Code Layout

### [plugins.attestation.Attestation.kt](src/main/kotlin/at/asitplus/plugins/attestation/Attestation.kt)
Configures teh attestation library.
Defines, exposes and handles all endpoints related to creating a binding based on key attestation.

### [pki.KeySigner](src/main/kotlin/at/asitplus/pki/KeySigner.kt)
Holds this services signing certificate and issues binding certificates

### [Security.kt](src/main/kotlin/at/asitplus/Security.kt)
Handles custom JWT authentication

### [Routing.kt](src/main/kotlin/at/asitplus/Routing.kt)
Defines service-specific endpoints. In this case, it only `/protected` and enables the custom JWT authentication for it.

### [DataClasses.kt](src/main/kotlin/at/asitplus/DataClasses.kt)
Defines all JSON data classes used for the binding process. This is a single, discrete file for convenient copy-pasting
to Android projects.

### [Serialization.kt](src/main/kotlin/at/asitplus/Serialization.kt)
Configures JSON serialization for ktor. Discrete file to separate ktor-specifics from data classes.

### [Application.kt](src/main/kotlin/at/asitplus/Application.kt)
Wires everything together

### [application.yaml](src/main/resources/application.yaml)
Main configuration file. Does **NOT** contain all configuration parameters of the attestation library, since
[plugins.attestation.Attestation.kt](src/main/kotlin/at/asitplus/plugins/attestation/Attestation.kt)
only reads a select few of them.
