//
//  ContentView.swift
//  SSLPinningDemo
//
//  Created by Sujeet kumar on 04/09/26.
//

import SwiftUI

struct ContentView: View {
    @State private var responseRecieved = "Response will available here once clicked the below button"
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("\(responseRecieved)")
                .padding(EdgeInsets(top: 20, leading: 20, bottom: 20, trailing: 20))
            Button("Fetch data from URL(No Pinning)") {
                let networkService = NetworkService()
                networkService.fetchData(id: "1") { result in
                    switch result {
                    case .success(let data):
                        DispatchQueue.main.async {
                            responseRecieved = String(data: data, encoding: .utf8) ?? "decode error"
                        }
                    case .failure(let error):
                        DispatchQueue.main.async {
                            responseRecieved = "Error: \(error )"
                        }
                    }
                }
            }
            .frame(width: 200, height: 100)
            .background(Color.blue)
            .foregroundColor(Color.green)
            .cornerRadius(10)
            
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
