//
//  Issuence.swift
//  OID4VC
//
//  Created by Aziz Karabashov on 04/04/25.
//
import SwiftUI

struct IssuenceView: View {
    
    @ObservedObject var viewModel: OID4VCViewModel
    
    var body: some View {
        VStack(spacing: 16) {
            issuenceFlowContent
        }.padding()
    }
    
    @ViewBuilder
    private var authCodeFlowContent: some View {
        switch viewModel.tokenResponse {
        case.initial:
            if case .ready(data: let url) = viewModel.authorizationCodeURL {
                Link("Get authorization code", destination: URL(string: url)!)
                
                TextField("Enter auth code", text: $viewModel.authCode)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding(.horizontal)
                
                Button("Submit Auth Code") {
                    viewModel.submitCode()
                }
                .padding()
                .buttonStyle(.bordered)
            } else {
                Button("Start Authorization Flow") {
                    Task {
                        await viewModel.startAuthorizationFlow()
                    }
                }
                .padding()
                .buttonStyle(.borderedProminent)
            }
        case .loading:
            ProgressView("Waiting for token response...")
        case .error(let message):
            Text("Authorization Failed: \(message)")
                .foregroundColor(.red)
            Button("Restart Issuence") {
                viewModel.restartIssuance()
            }
            .buttonStyle(.borderedProminent)
        case .ready(let tokenResponse):
            if case .initial = viewModel.credential {
                VStack(spacing: 10) {
                    Text("Token Response Received")
                        .font(.headline)
                        .foregroundColor(.green)
                    
                    MultilineText(text: tokenResponse.accessToken)
                    
                    Button("Start Credential Issuance") {
                        Task {
                            await viewModel.startCredentialIssuanceFlow(token: tokenResponse.accessToken)
                        }
                    }
                    .padding()
                    .buttonStyle(.borderedProminent)
                }
            }
        }
    }
    
    @ViewBuilder
    private var issuenceFlowContent: some View {
        switch viewModel.credential {
        case .initial:
            authCodeFlowContent
        case .loading:
            ProgressView("Requesting Credential...")
                .padding()
        case .error(let message):
            VStack {
                Text("Credential Issuance Failed")
                    .font(.headline)
                    .foregroundColor(.red)
                Text(message)
                    .multilineTextAlignment(.center)
                    .padding()
                Button("Restart Issuence") {
                    viewModel.restartIssuance()
                }
                .buttonStyle(.borderedProminent)
            }
        case .ready(let credentialData):
            VStack {
                Text("Credential Issued Successfully!")
                    .font(.headline)
                    .foregroundColor(.green)
                
                MultilineText(text: credentialData)
                
                Button("Restart Issuence") {
                    viewModel.restartIssuance()
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }
}

#Preview {
    IssuenceView(viewModel: OID4VCViewModel())
}
