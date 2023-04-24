//
//  HttpClient.swift
//  attestation client
//
//  Created by Christian Kollmann on 13.04.23.
//

import Foundation

extension String {

    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
    
    func fromBase64Url() -> String? {
        let base64 = self.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }
    
    func toBase64Url() -> String {
        return Data(self.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

}

extension Data {
    
    func toBase64() -> String {
        return self.base64EncodedString()
    }
    
    func toBase64Url() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
