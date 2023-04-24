//
//  KeychainService.swift
//  attestation client
//
//  Created by Christian Kollmann on 13.04.23.
//

import Foundation
import CryptoKit
import DeviceCheck

public class KeychainService {

    public func loadPrivateKey() -> SecureEnclave.P256.Signing.PrivateKey? {
        let query = [kSecClass: kSecClassGenericPassword,
 kSecUseDataProtectionKeychain: true,
                 kSecAttrLabel: "alias",
                kSecReturnData: true] as [String: Any]
        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data,
                  let privateKey = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data) else {
                print("loadPrivateKey: Creation failed")
                return nil
            }
            return privateKey
        default:
            print("loadPrivateKey: Creation failed")
            return nil
        }
    }

    public func generateKeyPairWithAttestation(challenge: Data) async throws -> KeyPairAttestation? {
        clear()
        guard let (privateKey, publicKey, attestationKeyId) = try await generateKeyPair(),
              let attestationKeyId = attestationKeyId else {
            print("Error: Can't generate key pair with attestation")
            return nil
        }
        guard let attestationStatement = await attestKey(with: challenge, also: publicKey.derRepresentation, key: attestationKeyId) else {
            print("Error: Can't create attestation statement")
            return nil
        }
        return KeyPairAttestation(privateKey: privateKey, publicKey: publicKey, attestationStatement: attestationStatement)
    }

    public struct KeyPairAttestation {
        let privateKey: SecureEnclave.P256.Signing.PrivateKey
        let publicKey: P256.Signing.PublicKey
        let attestationStatement: [Data]
    }

    private func generateKeyPair() async throws -> (SecureEnclave.P256.Signing.PrivateKey, P256.Signing.PublicKey, String?)? {
        clear()
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage] // Add ".userPresence" for Biometric Authentication
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, &error) else {
            throw RuntimeError("Can't create access flags")
        }
        
        guard let privateKey = try? SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: true, accessControl: access) else {
            throw RuntimeError("Can't create private key")
        }

        // SecureEnclave keys from CryptoKit shall be stored as "passwords"
        // (their data representation is an encrypted blob)
        let query = [kSecClass: kSecClassGenericPassword,
            kSecAttrAccessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
 kSecUseDataProtectionKeychain: true,
                 kSecAttrLabel: "alias",
                 kSecValueData: privateKey.dataRepresentation] as [String: Any]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw RuntimeError("Can't store private key")
        }
        
        if DCAppAttestService.shared.isSupported {
            guard let keyId = try? await DCAppAttestService.shared.generateKey() else {
                throw RuntimeError("Can't generate key for attestation")
            }
            return (privateKey, privateKey.publicKey, keyId)
        }

        return (privateKey, privateKey.publicKey, nil)
    }
    
    private func attestKey(with challenge: Data, also clientData: Data, key: String) async -> [Data]? {
        if DCAppAttestService.shared.isSupported {
            do {
                let attestation = try await DCAppAttestService.shared.attestKey(key, clientDataHash: Data(SHA256.hash(data: challenge)))
                let assertion = try await DCAppAttestService.shared.generateAssertion(key, clientDataHash: Data(SHA256.hash(data: clientData)))
                return [attestation, assertion]
            } catch let error {
                print("attestKey failed")
                print(error)
            }
        }
        print("attestKey not supported")
        return nil
    }
    
    public func storeBinding(certificateChain: [Data]) throws {
        if (certificateChain.isEmpty) {
            throw RuntimeError("Empty chain")
        }
        clearCertificate(for: "binding")
        try storeCertificate(data: certificateChain[0], alias: "binding")
        if (certificateChain.count > 1) {
            clearCertificate(for: "binding-ca")
            try storeCertificate(data: certificateChain[1], alias: "binding-ca")
        }
    }
    
    private func storeCertificate(data: Data, alias: String) throws {
        let certificate = SecCertificateCreateWithData(nil, data as CFData)!
        let query: [NSString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: alias,
            kSecValueRef: certificate,
            kSecAttrAccessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw RuntimeError("Can't store binding")
        }
    }
    
    public func loadBinding() -> [Data]? {
        if let binding = loadCertificate(alias: "binding") {
            if let bindingca = loadCertificate(alias: "binding-ca") {
                return [binding, bindingca]
            }
            return [binding]
        }
        return nil
    }
    
    private func loadCertificate(alias: String) -> Data? {
        let query: [NSString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: alias,
            kSecReturnData: true,
        ]
        var ref : CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &ref)
        guard status == errSecSuccess,
              let cert = ref else {
            print("loadCertificate failed")
            return nil
        }
        return (cert as! Data)
    }
    
    public func loadBindingPemSafe() -> String {
        guard let chain = loadBinding() else {
            return "No Binding"
        }
        return chain.compactMap { "-----BEGIN CERTIFICATE-----\n" + $0.toBase64() + "\n-----END CERTIFICATE-----\n" }.joined()
    }

    public func clear() {
        clearKeychain(for: "alias")
        clearKeychain(for: "binding")
        clearKeychain(for: "attestation")
    }
    
    private func clearKeychain(for alias: String) {
        clearCertificate(for: alias)
        clearGenericPassword(for: alias)
    }
    
    private func clearCertificate(for alias: String) {
        let query: [NSString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: alias,
        ]
        _ = SecItemDelete(query as CFDictionary)
    }
    
    func clearGenericPassword(for alias: String) {
        let deleteQuery : [NSString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: alias,
        ]
        _ = SecItemDelete(deleteQuery as CFDictionary)
    }
}

struct RuntimeError: LocalizedError {
    let description: String

    init(_ description: String) {
        self.description = description
    }

    var errorDescription: String? {
        description
    }
}
