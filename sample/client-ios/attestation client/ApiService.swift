//
//  HttpClient.swift
//  attestation client
//
//  Created by Christian Kollmann on 13.04.23.
//

public class ApiService {
    
    private let keychainService: KeychainService
    private let jwtService: JwtService
    private let httpClient: HttpClient

    init() {
        self.keychainService = KeychainService()
        self.jwtService = JwtService(keychainService)
        self.httpClient = HttpClient(keychainService, jwtService)
    }
    
    public func createBinding(baseUrl: String) async {
        await httpClient.createBinding(baseUrl: baseUrl)
    }

    public func accessResource(baseUrl: String) async {
        await httpClient.accessResource(baseUrl: baseUrl)
    }

    public func exportBindingCertChain() -> String {
        return keychainService.loadBindingPemSafe()
    }

}
