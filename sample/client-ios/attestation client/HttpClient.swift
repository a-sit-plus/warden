//
//  HttpClient.swift
//  attestation client
//
//  Created by Christian Kollmann on 13.04.23.
//

import Foundation
import CryptoKit

public class HttpClient {
    
    private let keychainService: KeychainService
    private let jwtService: JwtService

    public init(_ keychainService: KeychainService, _ jwtService: JwtService) {
        self.keychainService = keychainService
        self.jwtService = jwtService
    }
    
    public func createBinding(baseUrl: String) async {
        guard let url = URL(string: "\(baseUrl)/binding/start") else {
            print("Error: Can't build URL")
            return
        }
        do {
            print("Calling /binding/start at \(baseUrl) ...")
            let (data, _) = try await URLSession.shared.data(from: url)
            //print(data.base64EncodedString())
            let result = try JSONDecoder().decode(Challenge.self, from: data)
            print("Result from /binding/start: \(result)")
            await createKeypair(baseUrl: baseUrl, challenge: result.challenge)
        } catch let error {
            print("Error: createBinding failed")
            print(error)
        }
    }
    
    private func createKeypair(baseUrl: String, challenge: Data) async {
        do {
            print("Creating keypair ...")
            guard let url = URL(string: "\(baseUrl)/binding/create") else {
                print("Error: Can't build URL")
                return
            }
            guard let keyPairWithAttestation = try await keychainService.generateKeyPairWithAttestation(challenge: challenge) else {
                print("Error: Can't create key pair with attestation")
                return
            }
            let requestBody = AttestationRequest(challenge: challenge,
                                                 attestationProof: keyPairWithAttestation.attestationStatement,
                                                 publicKey: keyPairWithAttestation.publicKey.derRepresentation)
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = try JSONEncoder().encode(requestBody)
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            print("Calling /binding/create ... ")
            //print(request.httpBody!.base64EncodedString())
            let (data, _) = try await URLSession.shared.data(for: request)
            //print(data.base64EncodedString())
            let result = try JSONDecoder().decode(AttestationResponse.self, from: data)
            print("Storing binding ...")
            try keychainService.storeBinding(certificateChain: result.certificateChain)
            print("Success!")
        } catch let error {
            print("Error: createKeypair failed")
            print(error)
        }
    }
    
    public func accessResource(baseUrl: String) async {
        print("Accessing resource at \(baseUrl)...")
        guard let bindingChain = keychainService.loadBinding() else {
            print("Error: Can't load binding")
            return
        }
        guard let url = URL(string: "\(baseUrl)/protected") else {
            print("Error: Can't build URL")
            return
        }
        let x5c = bindingChain.compactMap { $0.toBase64() }
        let header = JwsHeader(alg: "ES256", x5c: x5c)
        let claims = JwsClaims(sub: "Attested iOS Client", iat: Int64(Date.now.timeIntervalSince1970))
        guard let jwt = jwtService.createSignedJwt(with: header, and: claims) else {
            print("Error: Can't build JWT")
            return
        }
        do {
            print("Calling /protected ...")
            var request = URLRequest(url: url)
            request.addValue("Bearer \(jwt)", forHTTPHeaderField: "Authorization")
            let (data, _) = try await URLSession.shared.data(for: request)
            print(String(data: data, encoding: .utf8)!)
        } catch let error {
            print("Error: accessResource failed")
            print(error)
        }
    }

    struct Challenge: Codable {
        let challenge: Data
        let validUntil: Int64
    }
            
    struct AttestationRequest: Codable {
        let challenge: Data
        let attestationProof: [Data]
        let publicKey: Data
    }
            
    struct AttestationResponse: Codable {
        let status: String
        let platform: String
        let certificateChain: [Data]
    }

}
