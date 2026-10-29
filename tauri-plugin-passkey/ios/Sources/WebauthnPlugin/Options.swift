// Ceremony option decoding and mapping shared by the iOS plugin and the macOS
// bridge. The two SwiftPM packages cannot share a target (the iOS one depends
// on the Tauri package), so this file is duplicated in
// macos/Sources/WebauthnBridge/Options.swift. Keep the copies byte-identical
// apart from the `#available` platform check and its error message.

import AuthenticationServices
import Foundation

// MARK: - Decodable argument wrappers

/// Browser-shaped `PublicKeyCredentialCreationOptions` as the Rust side
/// serialises them, plus a top-level `timeout` in milliseconds.
struct RegistrationOptions: Decodable {
    let rp: RelyingParty // swiftlint:disable:this identifier_name
    let user: User
    let challenge: String
    let extensions: Extensions?
    let excludeCredentials: [CredentialDescriptor]?
    let authenticatorSelection: AuthenticatorSelection?
    let attestation: String?
    let pubKeyCredParams: [CredentialParameter]
    let timeout: Int?

    struct RelyingParty: Decodable {
        let id: String
    }

    struct User: Decodable {
        let id: String
        let name: String
        let displayName: String?
    }

    struct CredentialDescriptor: Decodable {
        let id: String
    }

    struct AuthenticatorSelection: Decodable {
        let authenticatorAttachment: String?
        let userVerification: String?
    }

    struct CredentialParameter: Decodable {
        let alg: Int
    }

    /// The Rust side sends the browser `prf` extension verbatim.
    struct Extensions: Decodable {
        let prf: PrfInput?
    }
}

/// Browser-shaped `PublicKeyCredentialRequestOptions` as the Rust side
/// serialises them, plus a top-level `timeout` in milliseconds.
struct AuthenticationOptions: Decodable {
    let rpId: String
    let challenge: String
    let allowCredentials: [CredentialDescriptor]?
    let extensions: Extensions?
    let userVerification: String?
    let timeout: Int?

    struct CredentialDescriptor: Decodable {
        let id: String
    }

    /// The Rust side sends the browser `prf` extension verbatim.
    struct Extensions: Decodable {
        let prf: PrfInput?
    }
}

struct PrfInput: Decodable {
    let eval: Eval?

    struct Eval: Decodable {
        let first: String // base64url-encoded salt
        let second: String? // optional second salt
    }
}

// MARK: - Decoded ceremony parameters

/// Registration inputs with base64url fields decoded. Option strings stay raw
/// and are mapped through `CeremonyOptions` when the requests are built.
struct RegistrationParameters: Sendable {
    let domain: String
    let challenge: Data
    let username: String
    let displayName: String
    let userID: Data
    let excludeCredentials: [Data]
    let prfEnabled: Bool
    let attachment: String?
    let userVerification: String?
    let attestation: String?
    let algorithms: [Int]
    let timeoutMilliseconds: Int

    init(_ options: RegistrationOptions) throws {
        guard let challenge = base64URLDecode(options.challenge),
              let userID = base64URLDecode(options.user.id)
        else {
            throw PasskeyHandlerError.invalidOptions("Failed to decode base64url fields in registration options")
        }
        domain = options.rp.id
        self.challenge = challenge
        username = options.user.name
        displayName = options.user.displayName ?? options.user.name
        self.userID = userID
        excludeCredentials = (options.excludeCredentials ?? []).compactMap { base64URLDecode($0.id) }
        prfEnabled = options.extensions?.prf != nil
        attachment = options.authenticatorSelection?.authenticatorAttachment
        userVerification = options.authenticatorSelection?.userVerification
        attestation = options.attestation
        algorithms = options.pubKeyCredParams.map(\.alg)
        timeoutMilliseconds = CeremonyOptions.timeoutMilliseconds(options.timeout)
    }
}

/// Authentication inputs with base64url fields decoded.
struct AuthenticationParameters: Sendable {
    let domain: String
    let challenge: Data
    let allowCredentials: [Data]
    let prfSalt1: Data?
    let prfSalt2: Data?
    let userVerification: String?
    let timeoutMilliseconds: Int

    init(_ options: AuthenticationOptions) throws {
        guard let challenge = base64URLDecode(options.challenge) else {
            throw PasskeyHandlerError.invalidOptions("Failed to decode challenge in authentication options")
        }
        // ASAuthorization applies the WebAuthn PRF derivation to these salts itself.
        var salt1: Data?
        var salt2: Data?
        if let eval = options.extensions?.prf?.eval {
            salt1 = base64URLDecode(eval.first)
            salt2 = eval.second.flatMap { base64URLDecode($0) }
            if salt1 == nil || (eval.second != nil && salt2 == nil) {
                throw PasskeyHandlerError.invalidOptions("Failed to decode PRF salts in authentication options")
            }
        }
        domain = options.rpId
        self.challenge = challenge
        allowCredentials = (options.allowCredentials ?? []).compactMap { base64URLDecode($0.id) }
        prfSalt1 = salt1
        prfSalt2 = salt2
        userVerification = options.userVerification
        timeoutMilliseconds = CeremonyOptions.timeoutMilliseconds(options.timeout)
    }
}

// MARK: - Option mapping

/// Pure mappings from WebAuthn option strings to ASAuthorization values.
enum CeremonyOptions {
    /// Used when the options carry no usable `timeout`.
    static let defaultTimeoutMilliseconds = 60000

    static func timeoutMilliseconds(_ value: Int?) -> Int {
        guard let value, value > 0 else {
            return defaultTimeoutMilliseconds
        }
        return value
    }

    static func userVerification(_ value: String?) -> ASAuthorizationPublicKeyCredentialUserVerificationPreference? {
        switch value {
        case "required": return .required
        case "preferred": return .preferred
        case "discouraged": return .discouraged
        default: return nil
        }
    }

    static func attestation(_ value: String?) -> ASAuthorizationPublicKeyCredentialAttestationKind? {
        switch value {
        case "none": return ASAuthorizationPublicKeyCredentialAttestationKind.none
        case "indirect": return .indirect
        case "direct": return .direct
        case "enterprise": return .enterprise
        default: return nil
        }
    }

    /// Platform passkeys are offered unless the RP asked for a roaming authenticator.
    static func includesPlatform(attachment: String?) -> Bool {
        attachment != "cross-platform"
    }

    /// Security keys are offered unless the RP asked for a platform authenticator.
    static func includesSecurityKey(attachment: String?) -> Bool {
        attachment != "platform"
    }

    /// Apple authenticators (platform passkeys and security keys) create ES256
    /// keys only. Fail before showing any UI when the RP's non-empty
    /// `pubKeyCredParams` excludes ES256 (-7); an empty list means no preference.
    static func requireES256(_ algs: [Int]) throws {
        guard algs.isEmpty || algs.contains(-7) else {
            throw PasskeyHandlerError.unsupportedAlgorithm
        }
    }

    /// ASAuthorization security-key registration supports ES256 only. An empty
    /// list (no preference) means ES256; a list without ES256 (-7) yields no
    /// parameters, meaning a security key cannot satisfy the RP.
    static func securityKeyAlgorithms(_ algs: [Int]) -> [ASAuthorizationPublicKeyCredentialParameters] {
        guard algs.isEmpty || algs.contains(-7) else {
            return []
        }
        return [ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)]
    }

    /// Fail before showing any UI when PRF salts were supplied but this OS
    /// cannot evaluate them.
    static func requirePrfSupport(_ requested: Bool) throws {
        guard requested else {
            return
        }
        if #available(iOS 18.0, *) {
            return
        }
        throw PasskeyHandlerError.prfUnavailable
    }
}

// MARK: - Errors

struct TimeoutError: LocalizedError {
    var errorDescription: String? {
        "The passkey request timed out"
    }
}

enum PasskeyHandlerError: LocalizedError {
    case unexpectedCredentialType
    case missingAttestationObject
    case invalidOptions(String)
    case prfUnavailable
    case noAuthenticatorMatches
    case unsupportedAlgorithm

    var errorDescription: String? {
        switch self {
        case .unexpectedCredentialType: return "Unexpected credential type in authorization response"
        case .missingAttestationObject: return "Registration returned no attestation object"
        case let .invalidOptions(message): return message
        case .prfUnavailable: return "PRF requires iOS 18 or later"
        case .noAuthenticatorMatches: return "No available authenticator satisfies the requested options"
        case .unsupportedAlgorithm:
            return "pubKeyCredParams does not include ES256 (-7), the only algorithm Apple authenticators support"
        }
    }
}

/// Machine-readable rejection codes understood by the Rust side
/// (`crate::error::error_from_code`). `nil` means no specific code.
enum PluginErrorCode {
    static func from(_ error: Error) -> String? {
        if error is CancellationError {
            return "cancelled"
        }
        if error is TimeoutError {
            return "timeout"
        }
        if let handlerError = error as? PasskeyHandlerError {
            switch handlerError {
            case .prfUnavailable, .noAuthenticatorMatches, .unsupportedAlgorithm: return "unsupported"
            default: return nil
            }
        }
        let nsError = error as NSError
        if nsError.domain == ASAuthorizationError.errorDomain,
           nsError.code == ASAuthorizationError.canceled.rawValue
        {
            return "cancelled"
        }
        return nil
    }
}

// MARK: - Data Helpers

extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

func base64URLDecode(_ str: String) -> Data? {
    var base64 = str
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 {
        base64.append("=")
    }
    return Data(base64Encoded: base64)
}
