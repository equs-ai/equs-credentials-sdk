//
//  ContentView.swift
//  OID4VC
//
//  Created by Aziz Karabashov on 04/04/25.
//
import SwiftUI

enum NavigationDestinations: String, CaseIterable, Hashable {
    case Issuence
    case Presention
}

struct ContentView: View {
    private let screens = NavigationDestinations.allCases
    @StateObject private var viewModel = OID4VCViewModel()
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Image(systemName: "wallet.bifold")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 64, height: 64)
                    .foregroundStyle(.tint)
                
                Text("OID4VC Demo")
                    .font(.title)
                    .bold()
                
                content
            }
            .padding()
            .navigationDestination(for: NavigationDestinations.self) { screen in
                switch screen {
                case .Issuence:
                    IssuenceView(viewModel: viewModel)
                case .Presention:
                    PresentationView(viewModel: viewModel)
                }
            }
        }
    }
    
    @ViewBuilder
    private var content: some View {
        switch viewModel.initialization {
        case .initial:
            Button("Start") {
                Task {
                    await viewModel.setup()
                }
            }
            .padding()
            .buttonStyle(.borderedProminent)
        case .loading:
            ProgressView()
                .progressViewStyle(CircularProgressViewStyle())
        case .ready(_):
            List(screens, id: \.self) { screen in
                NavigationLink(value: screen) {
                    Text(screen.rawValue)
                }
            }
            .listStyle(InsetGroupedListStyle())
        case .error(let message):
            VStack(spacing: 8) {
                Text("Error: \(message)")
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                Button("Retry") {
                    Task {
                        await viewModel.setup()
                    }
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
        }
    }
}

#Preview {
    ContentView()
}
