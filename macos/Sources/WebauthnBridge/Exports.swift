import Foundation
import AuthenticationServices

// MARK: - C-callable FFI exports

/// Callback type: receives a JSON C-string (or null on failure) and a context pointer.
/// The Rust side owns the C-string and must free it with `webauthn_free_string`.
public typealias WebauthnCallback = @Sendable @convention(c) (
    UnsafePointer<CChar>?,   // json result (null = error)
    UnsafePointer<CChar>?,   // error message (null = success)
    UInt64                    // context
) -> Void

@_cdecl("webauthn_register")
public func webauthnRegister(
    domain: UnsafePointer<CChar>,
    challengePtr: UnsafePointer<UInt8>,
    challengeLen: UInt,
    username: UnsafePointer<CChar>,
    userIdPtr: UnsafePointer<UInt8>,
    userIdLen: UInt,
    context: UInt64,
    callback: WebauthnCallback
) {
    let domainStr = String(cString: domain)
    let challengeData = Data(bytes: challengePtr, count: Int(challengeLen))
    let usernameStr = String(cString: username)
    let userIdData = Data(bytes: userIdPtr, count: Int(userIdLen))

    Task { @MainActor in
        let handler = PasskeyHandler()
        do {
            let auth = try await handler.register(
                domain: domainStr,
                challenge: challengeData,
                username: usernameStr,
                userID: userIdData
            )

            let json = try registrationJSON(from: auth)
            callbackWithJSON(json, context: context, callback: callback)
        } catch {
            callbackWithError(error, context: context, callback: callback)
        }
    }
}

@_cdecl("webauthn_authenticate")
public func webauthnAuthenticate(
    domain: UnsafePointer<CChar>,
    challengePtr: UnsafePointer<UInt8>,
    challengeLen: UInt,
    allowCredentialsJson: UnsafePointer<CChar>?,
    context: UInt64,
    callback: WebauthnCallback
) {
    let domainStr = String(cString: domain)
    let challengeData = Data(bytes: challengePtr, count: Int(challengeLen))

    var allowedCredentials: [Data] = []
    if let jsonPtr = allowCredentialsJson {
        let jsonStr = String(cString: jsonPtr)
        if let jsonData = jsonStr.data(using: .utf8),
           let arr = try? JSONSerialization.jsonObject(with: jsonData) as? [String] {
            allowedCredentials = arr.compactMap { base64URLDecode($0) }
        }
    }

    Task { @MainActor in
        let handler = PasskeyHandler()
        do {
            let auth = try await handler.authenticate(
                domain: domainStr,
                challenge: challengeData,
                allowCredentials: allowedCredentials
            )

            let json = try assertionJSON(from: auth)
            callbackWithJSON(json, context: context, callback: callback)
        } catch {
            callbackWithError(error, context: context, callback: callback)
        }
    }
}

@_cdecl("webauthn_free_string")
public func webauthnFreeString(ptr: UnsafeMutablePointer<CChar>?) {
    free(ptr)
}

// MARK: - Response serialization

private enum BridgeError: LocalizedError {
    case unexpectedCredentialType

    var errorDescription: String? {
        switch self {
        case .unexpectedCredentialType: return "Unexpected credential type in authorization response"
        }
    }
}

private func registrationJSON(from auth: ASAuthorization) throws -> [String: Any] {
    guard let reg = auth.credential as? ASAuthorizationPublicKeyCredentialRegistration else {
        throw BridgeError.unexpectedCredentialType
    }
    return [
        "id": reg.credentialID.base64URLEncodedString(),
        "rawId": reg.credentialID.base64URLEncodedString(),
        "type": "public-key",
        "response": [
            "attestationObject": (reg.rawAttestationObject ?? Data()).base64URLEncodedString(),
            "clientDataJSON": reg.rawClientDataJSON.base64URLEncodedString()
        ]
    ]
}

private func assertionJSON(from auth: ASAuthorization) throws -> [String: Any] {
    guard let assertion = auth.credential as? ASAuthorizationPublicKeyCredentialAssertion else {
        throw BridgeError.unexpectedCredentialType
    }
    return [
        "id": assertion.credentialID.base64URLEncodedString(),
        "rawId": assertion.credentialID.base64URLEncodedString(),
        "type": "public-key",
        "response": [
            "authenticatorData": assertion.rawAuthenticatorData.base64URLEncodedString(),
            "clientDataJSON": assertion.rawClientDataJSON.base64URLEncodedString(),
            "signature": assertion.signature.base64URLEncodedString(),
            "userHandle": assertion.userID.base64URLEncodedString()
        ]
    ]
}

// MARK: - Helpers

private func callbackWithJSON(_ json: [String: Any], context: UInt64, callback: WebauthnCallback) {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: json),
          let jsonStr = String(data: jsonData, encoding: .utf8) else {
        callbackWithError(
            NSError(
                domain: "WebauthnBridge", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Failed to serialize JSON"]
            ),
            context: context,
            callback: callback
        )
        return
    }
    jsonStr.withCString { cStr in
        callback(strdup(cStr), nil, context)
    }
}

private func callbackWithError(_ error: Error, context: UInt64, callback: WebauthnCallback) {
    error.localizedDescription.withCString { cStr in
        callback(nil, strdup(cStr), context)
    }
}

extension Data {
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private func base64URLDecode(_ str: String) -> Data? {
    var base64 = str
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 {
        base64.append("=")
    }
    return Data(base64Encoded: base64)
}
