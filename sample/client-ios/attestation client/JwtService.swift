//
//  HttpClient.swift
//  attestation client
//
//  Created by Christian Kollmann on 13.04.23.
//

import Foundation
import CryptoKit

public class JwtService {
    
    private let keychainService: KeychainService

    public init(_ keychainService : KeychainService) {
        self.keychainService = keychainService
    }

    public func createSignedJwt(with header: JwsHeader, and claims: JwsClaims) -> String? {
        do {
            print("Creating JWT ...")
            let encodedHeader = try JSONEncoder().encode(header).toBase64Url()
            let encodedPayload = try JSONEncoder().encode(claims).toBase64Url()
            let signInput = encodedHeader + "." + encodedPayload
            let privateKey = keychainService.loadPrivateKey()
            let signature = try privateKey?.signature(for: SHA256.hash(data: signInput.data(using: .utf8)!))
            let encodedSignature = signature!.rawRepresentation.toBase64Url()
            return signInput + "." + encodedSignature
        } catch let error {
            print("Error: JWT creation failed")
            print(error)
            return nil
        }
    }

}

public struct JwsHeader: Codable {
    let alg: String
    let x5c: [String]
}

public struct JwsClaims: Codable {
    let sub: String
    let iat: Int64
}
