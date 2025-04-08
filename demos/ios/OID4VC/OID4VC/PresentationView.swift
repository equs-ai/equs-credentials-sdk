//
//  PresentationView.swift
//  OID4VC
//
//  Created by Aziz Karabashov on 04/04/25.
//
import SwiftUI

struct PresentationView: View {
    
    @ObservedObject var viewModel: OID4VCViewModel
    
    var body: some View {
        VStack(spacing: 16) {
            switch viewModel.presentation {
            case .initial:
                Link("Get request URI", destination: URL(string: Constants.vpRequestUri)!)
                
                TextField("Enter request URI", text: $viewModel.requestUri)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding(.horizontal)
                
                Button("Start Presentation") {
                    Task {
                        await viewModel.startPresentationFlow()
                    }
                }
                .padding()
                .buttonStyle(.borderedProminent)
            case .loading:
                ProgressView("Presentation...")
                    .padding()
            case .error(let message):
                VStack {
                    Text("Presentation Failed")
                        .font(.headline)
                        .foregroundColor(.red)
                    Text(message)
                        .multilineTextAlignment(.center)
                        .padding()
                    Button("Restart Presentation") {
                        viewModel.restartPresentation()
                    }
                    .buttonStyle(.borderedProminent)
                }
            case .ready(_):
                VStack {
                    Text("Presentation Finished Successfully!")
                        .font(.headline)
                        .foregroundColor(.green)
                    
                    Button("Restart Presentation") {
                        viewModel.restartPresentation()
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
    }
}

#Preview {
    PresentationView(viewModel: OID4VCViewModel())
}
