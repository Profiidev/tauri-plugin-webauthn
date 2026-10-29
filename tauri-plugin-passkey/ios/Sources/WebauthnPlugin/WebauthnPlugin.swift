import AuthenticationServices
import Foundation
import Tauri
import UIKit

// MARK: - Plugin

class WebauthnPlugin: Plugin {
    @MainActor private var activeHandler: PasskeyHandler?

    @objc func cancel(_ invoke: Invoke) {
        Task { @MainActor in
            self.activeHandler?.cancel()
            self.activeHandler = nil
        }
        invoke.resolve()
    }

    @objc func register(_ invoke: Invoke) {
        // The Rust side sends serde_json::to_string(&options) via run_mobile_plugin
        // which double-serializes: the JSON string is itself JSON-encoded
        guard let jsonString = try? invoke.parseArgs(String.self),
              let jsonData = jsonString.data(using: .utf8),
              let options = try? JSONDecoder().decode(RegistrationOptions.self, from: jsonData)
        else {
            invoke.reject("Failed to parse registration options JSON")
            return
        }

        let params: RegistrationParameters
        do {
            params = try RegistrationParameters(options)
        } catch {
            reject(invoke, error)
            return
        }

        Task { @MainActor in
            let handler = PasskeyHandler()
            self.activeHandler = handler
            defer { self.clearActiveHandler(handler) }
            do {
                let auth = try await handler.register(params)
                let json = try registrationJSON(from: auth)
                invoke.resolve(json)
            } catch {
                self.reject(invoke, error)
            }
        }
    }

    @objc func authenticate(_ invoke: Invoke) {
        guard let jsonString = try? invoke.parseArgs(String.self),
              let jsonData = jsonString.data(using: .utf8),
              let options = try? JSONDecoder().decode(AuthenticationOptions.self, from: jsonData)
        else {
            invoke.reject("Failed to parse authentication options JSON")
            return
        }

        let params: AuthenticationParameters
        do {
            params = try AuthenticationParameters(options)
        } catch {
            reject(invoke, error)
            return
        }

        Task { @MainActor in
            let handler = PasskeyHandler()
            self.activeHandler = handler
            defer { self.clearActiveHandler(handler) }
            do {
                let auth = try await handler.authenticate(params)
                let json = try assertionJSON(from: auth)
                invoke.resolve(json)
            } catch {
                self.reject(invoke, error)
            }
        }
    }

    /// Only clear the slot if a newer ceremony has not replaced this handler.
    @MainActor private func clearActiveHandler(_ handler: PasskeyHandler) {
        if activeHandler === handler {
            activeHandler = nil
        }
    }

    private func reject(_ invoke: Invoke, _ error: Error) {
        invoke.reject(error.localizedDescription, code: PluginErrorCode.from(error))
    }
}

// MARK: - Plugin Registration

@_cdecl("init_plugin_passkey")
func initPlugin() -> Plugin {
    WebauthnPlugin()
}
