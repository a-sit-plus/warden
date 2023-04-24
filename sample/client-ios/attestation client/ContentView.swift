//
//  ContentView.swift
//  attestation client
//
//  Created by Christian Kollmann on 13.04.23.
//

import SwiftUI
import MessageUI

struct ContentView: View {
    @State private var url: String = UserDefaults.standard.string(forKey: "url") ?? "http://192.168.1.1:8080"
    @State private var log: String = ""
           private var pipe = Pipe()
    @State private var pipeSetup = false
    @State private var result: Result<MFMailComposeResult, Error>? = nil
    @State private var isShowingMailView = false
           private var apiService = ApiService()

    var body: some View {
        VStack {
            HStack {
                Image(systemName: "lock.shield")
                Text("Attestation Demo")
                    .font(.system(.title))
            }
            HStack {
                Text("Host:")
                TextField("IP address and port", text: $url)
            }.padding()
            Button("Create Binding") {
                openConsolePipe()
                UserDefaults.standard.set(url, forKey: "url")
                Task {
                    await apiService.createBinding(baseUrl: url)
                }
            }.padding()
            Button("Access Protected Resource") {
                openConsolePipe()
                UserDefaults.standard.set(url, forKey: "url")
                Task {
                    await apiService.accessResource(baseUrl: url)
                }
            }.padding()
            Button("Export Binding Cert Chain") {
                openConsolePipe()
                self.isShowingMailView.toggle()
            }.padding()
                .disabled(!MFMailComposeViewController.canSendMail())
                .sheet(isPresented: $isShowingMailView) {
                    MailView(result: self.$result, message: apiService.exportBindingCertChain())
                }
            ScrollView {
                Text(log)
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity)
            }.frame(maxWidth: .infinity)
        }.padding()
    }
    
    // https://stackoverflow.com/questions/53978091/using-pipe-in-swift-app-to-redirect-stdout-into-a-textview-only-runs-in-simul
    private func openConsolePipe() {
        if (self.pipeSetup) {
            return
        }
        setvbuf(stdout, nil, _IONBF, 0)
        dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
        self.pipeSetup = true
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            let str = String(data: data, encoding: .ascii) ?? "<Non-ascii data of size\(data.count)>\n"
            DispatchQueue.main.async {
                self.log += str
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
