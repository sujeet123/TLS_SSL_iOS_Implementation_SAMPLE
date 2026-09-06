//
//  SSLPinningDemo.swift
//  SSLPinningDemo
//
//  Created by Sujeet kumar on 05/09/26.
//

//
//  SSLPinningDemo.swift
//
//  A self-contained, runnable demo of SSL Pinning on iOS using
//  URLSessionDelegate — showing BOTH strategies:
//    1) Certificate Pinning  (pin the exact leaf cert)
//    2) Public Key Pinning   (pin the SPKI hash of the public key)
//
//  Demo target: https://jsonplaceholder.typicode.com  (public test API)
//  Swap PinningConfig.host / pins for your own server later.
//
//  HOW TO GET THE PIN VALUES FOR YOUR OWN SERVER (do this once, offline):
//
//  --- For Certificate Pinning (SHA-256 of the whole DER certificate) ---
//  openssl s_client -connect jsonplaceholder.typicode.com:443 -servername jsonplaceholder.typicode.com </dev/null 2>/dev/null \
//    | openssl x509 -outform der > leaf.der
//  openssl dgst -sha256 leaf.der
//
//  --- For Public Key Pinning (SHA-256 of the SubjectPublicKeyInfo) ---
//  openssl s_client -connect jsonplaceholder.typicode.com:443 -servername jsonplaceholder.typicode.com </dev/null 2>/dev/null \
//    | openssl x509 -pubkey -noout \
//    | openssl pkey -pubin -outform der \
//    | openssl dgst -sha256
//
//  Run those two commands against YOUR server, drop the resulting hex/base64
//  hash into PinningConfig below, and this same code protects your API.
//

import Foundation
import CryptoKit
import Security

// MARK: - Configuration

enum PinningStrategy {
    case certificate   // pin the whole leaf certificate
    case publicKey      // pin only the SPKI (public key) hash
}

enum PinningConfig {
    /// The host this pinning applies to. Only connections to this exact host are checked.
    static let host = "jsonplaceholder.typicode.com"

    /// Which strategy this demo uses. Flip this to compare behavior.
    static let strategy: PinningStrategy = .certificate

    /// SHA-256 hash of the full DER-encoded leaf certificate, base64-encoded.
    /// Placeholder value — replace with output of the "Certificate Pinning" openssl
    /// command above run against your real server.
    //static let certificateSHA256Base64 = "REPLACE_WITH_YOUR_CERT_SHA256_BASE64"
    static let certificateSHA256Base64 = "XFEG81xf0W9SQljEY124tVuom/JizMpy4dwLe+VYAjE="
    /// SHA-256 hash of the certificate's SubjectPublicKeyInfo (SPKI), base64-encoded.
    /// Placeholder value — replace with output of the "Public Key Pinning" openssl
    /// command above run against your real server.
    ///
    /// Tip: keep TWO pins in production (current key + a backup/rotation key)
    /// so you can rotate certs without bricking old app versions.
    static let publicKeySHA256Base64Pins: Set<String> = [
        "fj/LGYZh+mUuNimcCT6b6V6MLFW1SIzcsM4hgwSwVB4="
    ]
}

// MARK: - Pinning Delegate

final class PinningURLSessionDelegate: NSObject, URLSessionDelegate {

    enum PinningError: Error {
        case notAServerTrustChallenge
        case hostMismatch
        case certificateExtractionFailed
        case noPinMatched
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // 1. Only handle server trust challenges; let everything else use default handling.
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // 2. Only pin for the specific host we care about (in a real app you might
        //    pin multiple hosts with different pin sets in a lookup table).
        guard challenge.protectionSpace.host == PinningConfig.host else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // 3. Let the system do its normal chain-of-trust validation FIRST.
        //    Pinning is an ADDITIONAL check, not a replacement for CA validation.
        var error: CFError?
        let isSystemTrustValid = SecTrustEvaluateWithError(serverTrust, &error)
        guard isSystemTrustValid else {
            print("System trust evaluation failed: \(String(describing: error))")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 4. Pull the leaf certificate out of the trust object.
        guard let serverCertificate = extractLeafCertificate(from: serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 5. Compare against our pin(s) using the selected strategy.
        let matched: Bool
        switch PinningConfig.strategy {
        case .certificate:
            matched = validateCertificatePin(certificate: serverCertificate)
        case .publicKey:
            matched = validatePublicKeyPin(certificate: serverCertificate)
        }

        if matched {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            print("SSL Pinning failed — rejecting connection to \(challenge.protectionSpace.host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: Certificate extraction

    private func extractLeafCertificate(from trust: SecTrust) -> SecCertificate? {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else {
            return nil
        }
        return leaf
    }

    // MARK: Strategy 1 — Certificate Pinning

    private func validateCertificatePin(certificate: SecCertificate) -> Bool {
        let certificateData = SecCertificateCopyData(certificate) as Data
        let hash = SHA256.hash(data: certificateData)
        let hashBase64 = Data(hash).base64EncodedString()

        return hashBase64 == PinningConfig.certificateSHA256Base64
    }

    // MARK: Strategy 2 — Public Key Pinning

    private func validatePublicKeyPin(certificate: SecCertificate) -> Bool {
        guard let publicKeyData = extractSubjectPublicKeyInfo(from: certificate) else {
            return false
        }
        let hash = SHA256.hash(data: publicKeyData)
        let hashBase64 = Data(hash).base64EncodedString()

        return PinningConfig.publicKeySHA256Base64Pins.contains(hashBase64)
    }

    /// Extracts the DER-encoded SubjectPublicKeyInfo (algorithm identifier + raw key bits)
    /// so the hash matches what `openssl pkey -pubin -outform der` produces.
    private func extractSubjectPublicKeyInfo(from certificate: SecCertificate) -> Data? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let rawKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }

        guard let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
              let keyType = attributes[kSecAttrKeyType] as? String,
              let keySizeInBits = attributes[kSecAttrKeySizeInBits] as? Int else {
            return nil
        }

        // SecKeyCopyExternalRepresentation gives raw key bytes, not full SPKI.
        // Wrap them in the correct ASN.1 SPKI header so the hash matches OpenSSL's output.
        let asn1Header = subjectPublicKeyInfoHeader(keyType: keyType, keySizeInBits: keySizeInBits)
        guard let header = asn1Header else { return nil }

        return header + rawKeyData
    }

    /// Minimal ASN.1 headers for the common key types or sizes used by TLS server certs.
    /// Add more entries here if your server uses a different key type/size.
    private func subjectPublicKeyInfoHeader(keyType: String, keySizeInBits: Int) -> Data? {
        let rsa2048Header: [UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        ]
        let rsa4096Header: [UInt8] = [
            0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
        ]
        let ecdsaP256Header: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
            0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00
        ]

        switch (keyType as CFString, keySizeInBits) {
        case (kSecAttrKeyTypeRSA, 2048):
            return Data(rsa2048Header)
        case (kSecAttrKeyTypeRSA, 4096):
            return Data(rsa4096Header)
        case (kSecAttrKeyTypeECSECPrimeRandom, 256):
            return Data(ecdsaP256Header)
        default:
            print("Unsupported key type/size for header lookup: \(keyType), \(keySizeInBits) bits")
            return nil
        }
    }
}

// MARK: - Example usage

final class PinnedAPIClient {
    private lazy var session: URLSession = {
        let delegate = PinningURLSessionDelegate()
        return URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
    }()

    func fetchTodo(id: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        guard let url = URL(string: "https://\(PinningConfig.host)/todos/\(id)") else { return }

        let task = session.dataTask(with: url) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data else {
                completion(.failure(URLError(.badServerResponse)))
                return
            }
            completion(.success(data))
        }
        task.resume()
    }
}

// MARK: - Try it (e.g. call this from a button action or app launch for testing)

func demoRunPinnedRequest() {
    let client = PinnedAPIClient()
    client.fetchTodo(id: 1) { result in
        switch result {
        case .success(let data):
            let json = String(data: data, encoding: .utf8) ?? "<binary>"
            print("Pinned request succeeded:\n\(json)")
        case .failure(let error):
            print("Pinned request failed: \(error)")
        }
    }
}

