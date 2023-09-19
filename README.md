# Server-Side Mobile Client Attestation Library

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0) 
[![Kotlin](https://img.shields.io/badge/kotlin-1.9.10-blue.svg?logo=kotlin)](http://kotlinlang.org)
![Java](https://img.shields.io/badge/java-11-blue.svg?logo=OPENJDK)
![Build artifacts](https://github.com/a-sit-plus/attestation-service/actions/workflows/gradle.yml/badge.svg)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus/attestation-service)](https://mvnrepository.com/artifact/at.asitplus/attestation-service/)

Server-side library providing a unified interface for key attestation compatible with Android and iOS (yes, even iOS!).
It also provides App attestation on both platforms (see [our 2019 Paper](https://graz.elsevierpure.com/en/publications/fides-unleashing-the-full-potential-of-remote-attestation) 
on how to remotely establish trust in Android applications for more Android-specifics on this matter).

Under the hood, this library depends on the [Android Key Attestation Library](https://github.com/a-sit-plus/android-attestation) and
[Vincent Haupert's](https://github.com/veehaitch)  excellent [DeviceCheck/AppAttest Library](https://github.com/veehaitch/devicecheck-appattest).

Full API docs are available [here](https://a-sit-plus.github.io/attestation-service/).

## Demonstration / Usage Example
This library is intended for integration into back-end services which need to remotely establish trust in mobile clients
(both Android and iOS). Usually, this means that a mobile client initially request a binding certificate from the back-end
based on a public/private key pair stored inside cryptographic hardware.
This binding is only granted if device and app integrity can be verified, and if the key can be proven to be stored in hardware.
<br>
Once a binding has been obtained, mobile clients can subsequently authenticate to the back-end (e.g. to access some protected
resource). However, far more flexible scenarios can be implemented. Hence, Figure&nbsp;1 depicts an abstract version of
establishing trust in mobile clients.

See the provided [sample service](https://github.com/a-sit-plus/attestation-service/tree/main/sample/backend) and its accompanying mobile clients for an MWE that integrates this library.
(The sample also contains the Android and iOS clients.)

![flow.png](flow.png)
<div style="text-align: center;">Figure 1: Abstract example usage: remotely establishing trust in mobile clients</div>

## Background
Apple and Google pursue different strategies wrt. establishing trust in mobile clients.
On Android, things are kept rather simpler from an architectural point of view, while iOS attestation depends on infrastructure operated by Apple.

### Android
During a device's manufacturing process, manufacturers provision signing keys and matching certificates into every device's
cryptographic hardware.
The device manufacturers' certificates are signed by Google, resulting in a certificate chain from a certificate signed
by the [attestation root key published by Google](https://developer.android.com/training/articles/security-key-attestation#root_certificate).
down to every individual Android device that ships with Google play services.
Apps can then generate cryptographic keys, which are again securely stored in cryptographic hardware on the device
and have this hardware module issue certificates for those keys.
These certificates are signed by the previously mentioned device manufacturer signing key provisioned during the manufacturing process.
In the end, this leads to a chain of trust from the Google root certificate to the cryptographic material created
on the device.
<br>
The cryptographic material referenced by the leaf certificate of the aforementioned chain can be used by the app as desired (e.g. to perform
signatures, etc.).

To establish trust in an Android device and a client app, quite some properties of such a leaf certificate need to be evaluated
in a particular manner.
From a high-level point of view, it really is simple: Validate the certificate chain just like any certificate chain, and evaluate
a well-documented extension of the leaf certificate to establish trust in an Android client app (Figure&nbsp;2 illustrates this high-level concept in more detail).
This is one core feature of this library -- make establishing trust in client apps just as simple and straight-forward.
The other one is providing a unified API to provide a inified API to achieve the same for iOS clients.

![android.png](android.png)
<div style="text-align: center;">Figure 2: High-level structure of an Android key attestation result</div>

### iOS
iOS's attestation, is a rather different beast compared to Android.
Apple relies on their own heuristics employed as part of a service operated by the company to assess whether a device
and an app can be trusted or not.
While some of the same basic principles apply here as well (i.e. keys generated in hardware come with chain of trust rooted in
the manufacturer's certificate), the semantics are quite different.
Android primarily attests the properties of a cryptographic key.
Apple's [App Attest](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity), on the
other hand, attests the integrity of apps.
The cryptographic material is in this case a mere vehicle to realise the idea of attesting app integrity.
Therefore, the involved key material cannot be used for arbitrary cryptographic operations, but is only employed to sign
attestations (and related assertions; see below).

This begs the question: How to enable key attestation on iOS?
After all, many applications exist, which require some proof that a key used for critical operations resides in hardware.
<br>
Here, the ability to obtain a so-called *assertion* comes to the rescue: iOS allows generating an *assertion* for some
data by signing it using the same key backing a previously obtained attestation.
By that logic, computing an assertion over the public key of a freshly generated public/private key pair proves that an
authentic, uncompromised app on a non-jailbroken device was used to generate this key pair as intended by the app developer.

This library abstracts away all the nitty-gritty details of this verification process and provides a unified API
which works with both Android and iOS.

## Usage
Written in Kotlin, plays nicely with Java (cf. `@JvmOverloads`), published at maven central.

### Gradle
Add the dependency:
```kotlin
 dependencies {
     implementation("at.asitplus:attestation-service:$version")
 }
```
### Configuration
Every parameter is configurable and multiple instance of an attestation service can be created and used in parallel.

Android and iOS attestation require different configuration parameters. Hence, distinct configuration classes exist.
The following snippet lists all configuration values:

```kotlin
val service = DefaultAttestationService(
    androidAttestationConfiguration = AndroidAttestationConfiguration(
       applications= listOf(   //REQUIRED: add applications to be attested
           AndroidAttestationConfiguration.AppData(
               packageName = "at.asitplus.attestation_client",
               signatureDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray()),
               appVersion = 5
           ),
           AndroidAttestationConfiguration.AppData( //we have a dedicated app for latest android version
               packageName = "at.asitplus.attestation_client-tiramisu",
               signatureDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7=".encodeToByteArray()),
               appVersion = 2, //with a different versioning scheme
               androidVersionOverride = 13000, //so we need to override this
               patchLevelOverride = PatchLevel(2023, 6) //also override patch level
           )
       ),
       androidVersion = 11000,                 //OPTIONAL, null by default
       patchLevel = PatchLevel(2022, 12),      //OPTIONAL, null by default
       requireStrongBox = false,               //OPTIONAL, defaults to false
       allowBootloaderUnlock = false,          //OPTIONAL, defaults to false
       requireRollbackResistance = false,      //OPTIONAL, defaults to false
       ignoreLeafValidity = false,             //OPTIONAL, defaults to false
       hardwareAttestationTrustAnchors = linkedSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS), //OPTIONAL, defaults shown here
       softwareAttestationTrustAnchors = linkedSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS), //OPTIONAL, defaults shown here
       verificationSecondsOffset = -300,       //OPTIONAL, defaults to 0
       disableHardwareAttestation = false,     //OPTIONAL, defaults to false. Set to true to disable HW attestation
       enableNougatAttestation = false,        //OPTIONAL, defaults to false. Set to true to enable hybrid attestation
       enableSoftwareAttestation = false       //OPTIONAL, defaults to false. Set to true to enable SW attestation
   ),
   iosAttestationConfiguration = IOSAttestationConfiguration(
      applications = listOf(
      IOSAttestationConfiguration.AppData(
        teamIdentifier = "9CYHJNG644",
        bundleIdentifier = "at.asitplus.attestation-client",
        iosVersionOverride = "16.0",     //OPTIONAL, null by default
        sandbox = false                  //OPTIONAL, defaults to false
        )
     )
   ),
   iosVersion = 14,                                                 //OPTIONAL, null by default
   clock = FixedTimeClock(Instant.parse("2023-04-13T00:00:00Z")),   //OPTIONAL, system clock by default,
   verificationTimeOffset = Duration.ZERO                           //OPTIONAL, defaults to zero
)
```

The (nullable) properties like patch level, iOS version or Android app version essentially allow for excluding outdated devices.
Custom android challenge verification has been omitted by design, considering iOS constraints and inconsistencies resulting from such a customisation.
More details on the configuration can be found in the API documentation

#### A Note on Android Attestation
This library allows for using combining different flavours of Android attestation, ranging from full hardware attestation
to (rather useless in practice) software-only attestation (see [Android Attestation](https://github.com/a-sit-plus/android-attestation) for details).
Hardware attestation is enabled by default, while hybrid and software-only attestation need to be explicitly enabled
through `enableNougatAttestation` and `enableSoftwareAttestation`, respectively. Doing so, will chain the corresponding
`AndroidAttestationChecker`s initially from strictest (hardware) to most useless (software-only).
Naturally, hardware attestation can also be disabled by setting `disableHardwareAttestation = true` although there is probably
no real use case for such a configuration.
Note that not all flavours use different the same root of trust by default.

### Example Usage
While still not complete, the test suite in this repository should provide a nice overview. [FeatureDemonstration](https://github.com/a-sit-plus/attestation-service/blob/main/attestation-service/src/test/kotlin/FeatureDemonstration.kt),
in particular, was designed to demonstrate this library's API.
<br>
See the provided [sample service](https://github.com/a-sit-plus/attestation-service/tree/main/sample/backend) and its mobile clients for an MWE that integrates this library.
The sample also contains Android and iOS clients.

#### Obtaining a Key Attestation Result
* The general workflow this library caters to assumes a back-end service, sending an attestation challenge to the mobile app. This challenge needs to be kept for future reference
* The app is assumed to generate a key pair with attestation (passing the received challenge to the platform's respective crypto APIs)
* The app responds with a platform-dependent attestation proof, the public key just created, and the challenge.
  * On Android, this proof is simply the certificate chain associated with the newly created key pair, which obtainable through the Android KeyStore API.
    * The certificate chain needs to be encoded into a list of byte arrays.
    * The first (index `0`) certificate is assumed to be the leaf, while tha last is assumed to be a certificate signed by the Google hardware attestation root key.
  * On iOS, the list of byte arrays must contain exactly two entries:
    * Index `0` contains an attestation object
    * Index `1` contains an assertion over the to-be-attested public key (either ANSI X9.63 encoded or DER encoded)
* On the back-end, a single call to `verifyKeyAttestation()`  is sufficient to remotely verify
   whether the key is indeed stored in HW (and whether the app can be trusted). This call requires the challenge from step 1.

Various advanced, platform-specific variants of this `verifyKeyAttestation()` call exist, to cater towards features specific to Android and iOS
(do see [FeatureDemonstration](https://github.com/a-sit-plus/attestation-service/blob/main/attestation-service/src/test/kotlin/FeatureDemonstration.kt) for details).
However, only `verifyKeyAttestation()` works for both Android and iOS and returns a [KeyAttestation](https://github.com/a-sit-plus/attestation-service/blob/main/attestation-service/src/main/kotlin/AttestationService.kt#L293) object:

```kotlin
 fun <T : PublicKey> verifyKeyAttestation(
        attestationProof: List<ByteArray>,
        expectedChallenge: ByteArray,
        keyToBeAttested: T
    ): KeyAttestation<T>
```
The returned `KeyAttestation` object contains the attested key on success, or an error on failure.

#### Semantics
The call succeeds if attestation data structures of the client (in `attestationProof`) can be verified and `expectedChallenge` matches
the attestation challenge and if `keyToBeAttested` matches the key contained in the proof.

As mentioned, the contents of **attestationProof** are platform-specific!
On Android, this is simply the certificate chain from the attestation certificate
(i.e. the certificate corresponding to the key to be attested) up to one of the
[Google hardware attestation root certificates](https://developer.android.com/training/articles/security-key-attestation#root_certificate).
on iOS this must contain the [AppAttest attestation statement](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643)
at index `0` and an [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
at index `1`, which, is verified for integrity and to match `keyToBeAttested`.
The signature counter in the attestation must be `0` and the signature counter in the assertion must be `1`.

Passing a public key created in the same app on an iDevice's secure hardware as `clientData` to create an assertion effectively
emulates Android's key attestation: Attesting such a secondary key through an assertion proves that
it was also created within the same app, on the same device, resulting in an attested key, which can then be used
for general-purpose crypto.
<br>
**Limitation: supports only EC key on iOS (either ANSI X9.63 encoded or DER encoded).**
The key can be passed in either encoding to the secure enclave when creating an assertion.

<br>

---
<p align="center">
This project has received funding from the European Union’s Horizon 2020 research and innovation
programme under grant agreement No 959072.
</p>
<p align="center">
<img src="eu.svg" alt="EU flag">
</p>