//
//  NetworkService.swift
//  SSLPinningDemo
//
//  Created by Sujeet kumar on 04/09/26.
//

import Foundation

public class NetworkService {
    private lazy var session: URLSession = {
        let delegate = PinningURLSessionDelegate()
        return URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
    }()
    
    func fetchData(id: String, complitionHandler: @escaping (Result<Data, Error>) -> Void ) {
        
        guard let url = URL(string: "https://\(PinningConfig.host)/todos/\(id)") else {
            complitionHandler(.failure(APIError.urlError))
            return
        }

        let urlRequest = URLRequest(url: url)
        session.dataTask(with: urlRequest) { data, response, error in
            guard let httpUrlResponse = response as? HTTPURLResponse else  {
                complitionHandler(.failure(APIError.otherError("Invalid response")))
                return
            }
            let statusCode =  httpUrlResponse.statusCode
            if (200...299).contains(statusCode) {
                complitionHandler(.success(data ?? Data()))
            } else {
                complitionHandler(.failure(APIError.otherError("")))
            }
            
        }.resume()
        
    }
    
    func fetchDataWithoutSSL(id: String, complitionHandler: @escaping (Result<Data, Error>) -> Void ) {
        
        guard let url = URL(string: "https://jsonplaceholder.typicode.com/todos/\(id)") else {
            complitionHandler(.failure(APIError.urlError))
            return
        }

        let urlRequest = URLRequest(url: url)
        session.dataTask(with: urlRequest) { data, response, error in
            guard let httpUrlResponse = response as? HTTPURLResponse else  {
                complitionHandler(.failure(APIError.otherError("Invalid response")))
                return
            }
            let statusCode =  httpUrlResponse.statusCode
            if (200...299).contains(statusCode) {
                complitionHandler(.success(data ?? Data()))
            } else {
                complitionHandler(.failure(APIError.otherError("")))
            }
            
        }.resume()
        
    }
}

enum APIError: Error {
    case urlError
    case ServerError(Int)
    case ClientError(Int)
    case otherError(String)
}
