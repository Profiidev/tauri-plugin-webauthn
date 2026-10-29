import AuthenticationServices
import Foundation

// MARK: - Active handler storage

/// Module-level storage for the active handler, accessed on the main actor.
@MainActor
private var activePasskeyHandler: PasskeyHandler?

// MARK: - C-callable FFI exports

/// Callback type: receives a JSON C-string (or null on failure) and a context pointer.
/// The Rust side owns the C-string and must free it with `webauthn_free_string`.
/// On failure the error string is itself JSON: `{"code": ..., "message": ...}`,
/// with `code` omitted when there is no machine-readable code.
public typealias WebauthnCallback = @Sendable @convention(c) (
    UnsafePointer<CChar>?, // json result (null = error)
    UnsafePointer<CChar>?, // error JSON (null = success)
    UInt64 // context
) -> Void

/// `optionsJson` is the browser-shaped `PublicKeyCredentialCreationOptions`
/// JSON (with `extensions.prf` and a top-level `timeout` in ms). It is copied
/// before this function returns, so the caller may free it afterwards.
@_cdecl("webauthn_register")
public func webauthnRegister(
    optionsJson: UnsafePointer<CChar>,
    context: UInt64,
    callback: WebauthnCallback
) {
    let params: RegistrationParameters
    do {
        let options = try decodeOptions(RegistrationOptions.self, from: optionsJson, kind: "registration")
        params = try RegistrationParameters(options)
    } catch {
        callbackWithError(error, context: context, callback: callback)
        return
    }

    Task { @MainActor in
        let handler = PasskeyHandler()
        activePasskeyHandler = handler
        defer { clearActiveHandler(handler) }
        do {
            let auth = try await handler.register(params)
            let json = try registrationJSON(from: auth)
            callbackWithJSON(json, context: context, callback: callback)
        } catch {
            callbackWithError(error, context: context, callback: callback)
        }
    }
}

/// `optionsJson` is the browser-shaped `PublicKeyCredentialRequestOptions`
/// JSON (with `extensions.prf.eval` and a top-level `timeout` in ms). It is
/// copied before this function returns, so the caller may free it afterwards.
@_cdecl("webauthn_authenticate")
public func webauthnAuthenticate(
    optionsJson: UnsafePointer<CChar>,
    context: UInt64,
    callback: WebauthnCallback
) {
    let params: AuthenticationParameters
    do {
        let options = try decodeOptions(AuthenticationOptions.self, from: optionsJson, kind: "authentication")
        params = try AuthenticationParameters(options)
    } catch {
        callbackWithError(error, context: context, callback: callback)
        return
    }

    Task { @MainActor in
        let handler = PasskeyHandler()
        activePasskeyHandler = handler
        defer { clearActiveHandler(handler) }
        do {
            let auth = try await handler.authenticate(params)
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

@_cdecl("webauthn_cancel")
public func webauthnCancel() {
    DispatchQueue.main.async {
        activePasskeyHandler?.cancel()
        activePasskeyHandler = nil
    }
}

// MARK: - Helpers

/// Only clear the slot if a newer ceremony has not replaced this handler.
@MainActor
private func clearActiveHandler(_ handler: PasskeyHandler) {
    if activePasskeyHandler === handler {
        activePasskeyHandler = nil
    }
}

private func decodeOptions<T: Decodable>(
    _: T.Type, from pointer: UnsafePointer<CChar>, kind: String
) throws -> T {
    let data = Data(String(cString: pointer).utf8)
    do {
        return try JSONDecoder().decode(T.self, from: data)
    } catch {
        throw PasskeyHandlerError.invalidOptions("Failed to parse \(kind) options JSON: \(error)")
    }
}

/// The error string handed to Rust: `{"code": ..., "message": ...}`, `code`
/// omitted when nil. Rust maps known codes via `crate::error::error_from_code`.
func errorJSON(code: String?, message: String) -> String {
    var object = ["message": message]
    if let code {
        object["code"] = code
    }
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
          let string = String(data: data, encoding: .utf8)
    else {
        return message
    }
    return string
}

func errorJSON(for error: Error) -> String {
    errorJSON(code: PluginErrorCode.from(error), message: error.localizedDescription)
}

private func callbackWithJSON(_ json: [String: Any], context: UInt64, callback: WebauthnCallback) {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: json),
          let jsonStr = String(data: jsonData, encoding: .utf8)
    else {
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
    errorJSON(for: error).withCString { cStr in
        callback(nil, strdup(cStr), context)
    }
}
