//
//  MultilineText.swift
//  OID4VC
//
//  Created by Aziz Karabashov on 07/04/25.
//
import SwiftUI

struct MultilineText: View {
    
    let text: String
    
    var body: some View {
        ScrollView {
            Text(text)
                .textSelection(.enabled)
                .padding()
        }
        .frame(maxWidth: .infinity, maxHeight: 300)
        .border(Color.gray.opacity(0.5), width: 1)
        .padding()
    }
}
