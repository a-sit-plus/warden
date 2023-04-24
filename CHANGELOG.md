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