## 0.1
Initial Release

## 0.2
Reworked API and workflow to enable emulation of key attestation on iOS

### 0.3
Explicit `verifyKeyAttestation` function for both mobile platforms

### 0.3.1
- More Java-friendly API
- More detailed toplevel exception messages on certificate verification error (Android)
- Kotlin 1.8.0

### 0.3.2
- fixed iOS leeway calculation

### 0.3.3
- update upstream google code

## 0.4
- ability to ignore timely validity of leaf cert for Android key attestation

### 0.4.1
- bugfix: NOOP attestation service actually being a NOOP

## 0.5.0
- Group OS-specific interfaces
- Align exception types between iOS and Android
 
### 0.5.1
-  depend on android-attestation 0.8.3 (MR Jar)

### 0.5.2
- Kotlin 1.8.21
- Gradle 8.1.1
- depend on android-attestation 0.8.4 to support custom Android trust anchors and testing against software-created
  attestations.

### 0.5.3 (broken!)
- android-attestation updated
- use A-SIT Plus gradle conventions plugin
- Kotlin 1.9
- BC 1.75

### 0.5.4 (broken!)
- fix dependency on wrong android-attestation version

### 0.5.5 (java-interop impaired)
- android-attestation (0.9.2)

### 0.5.6
- android-attestation 0.9.3
- better java interop

## 1.0.0
This release introduces breaking changes as it allows multiple apps to be attested and introduces multi-stage
attestation on Android, please re-read the readme!

- Kotlin 1.9.10!
- Bouncy Castle 1.76
- Android-Attestation 1.0.0

### 1.1.0
- remove `verifyAttestation`
- introduce `verifyKeyAttestation` taking an encoded public key as a byte array

### 1.2.0
- introduce builder for `AppData`
- Introduce `ByteArray.parseToPublicKey` which takes ANSI X9.63 and DER-encoded byte arrays
  (only P-256 is supported for ANSI)
- Update android-attestation to 1.1.0

### 1.3.0
- Documentation updates
- Update to android-attestation 1.2.0
- Refactor exceptions

### 1.4.0
- Discriminate between temporal certificate validation errors and trust-related ones

#### 1.4.1
- make all config classes `data` classes
- update to android attestation 1.2.1

#### 1.4.2
- fix temporal iOS receipt validation error not being propagated as such 

#### 1.4.3
- update android-attestation

#### 1.4.4
- update android-attestation
- update gradle conventions

#### 1.4.5
- make `fold` function of `KeyAttestation` inline

### 1.5.0
- better iOS-specific exception handling and enumerable error cases
- Kotlin 1.9.22
- Various dependency updates including BC

### 1.6.0
**Breaking changes ahead!**

- Parsing of iOS Build numbers in addition to OS Versions
  - Requires changes to configuration format
  - Introduces changes to IOS Attestation result
- Update to latest android-attestation
  - Changes types of ParsedAttestationRecord's properties
  - Exposes Guava as API dependency