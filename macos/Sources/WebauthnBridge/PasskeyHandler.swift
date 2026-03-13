import Foundation
import AuthenticationServices
import AppKit

@MainActor
public final class PasskeyHandler: NSObject {
    private var registrationContinuation: CheckedContinuation<ASAuthorization, Error>?
    private var assertionContinuation: CheckedContinuation<ASAuthorization, Error>?
    private let window: NSWindow?

    public init(windowPtr: UnsafeMutableRawPointer?) {
        if let ptr = windowPtr {
            self.window = Unmanaged<NSWindow>.fromOpaque(ptr).takeUnretainedValue()
        } else {
            self.window = nil
        }
    }

    public func register(domain: String, challenge: Data, username: String, userID: Data) async throws -> ASAuthorization {
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let platformRequest = platformProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: username,
            userID: userID
        )

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let securityKeyRequest = securityKeyProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            displayName: username,
            name: username,
            userID: userID
        )
        securityKeyRequest.credentialParameters = [
            ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)
        ]

        let controller = ASAuthorizationController(authorizationRequests: [platformRequest, securityKeyRequest])
        controller.delegate = self
        controller.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.registrationContinuation = continuation
            controller.performRequests()
        }
    }

    public func authenticate(domain: String, challenge: Data, allowCredentials: [Data]) async throws -> ASAuthorization {
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let platformRequest = platformProvider.createCredentialAssertionRequest(challenge: challenge)

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let securityKeyRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: challenge)

        if !allowCredentials.isEmpty {
            platformRequest.allowedCredentials = allowCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
            }
            securityKeyRequest.allowedCredentials = allowCredentials.map {
                ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: $0,
                    transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                )
            }
        }

        let controller = ASAuthorizationController(authorizationRequests: [platformRequest, securityKeyRequest])
        controller.delegate = self
        controller.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.assertionContinuation = continuation
            controller.performRequests()
        }
    }
}

extension PasskeyHandler: ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return window ?? NSApplication.shared.windows.first ?? NSWindow()
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization auth: ASAuthorization) {
        if auth.credential is ASAuthorizationPlatformPublicKeyCredentialRegistration
            || auth.credential is ASAuthorizationSecurityKeyPublicKeyCredentialRegistration {
            registrationContinuation?.resume(returning: auth)
            registrationContinuation = nil
        } else if auth.credential is ASAuthorizationPlatformPublicKeyCredentialAssertion
            || auth.credential is ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
            assertionContinuation?.resume(returning: auth)
            assertionContinuation = nil
        }
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        registrationContinuation?.resume(throwing: error)
        registrationContinuation = nil
        assertionContinuation?.resume(throwing: error)
        assertionContinuation = nil
    }
}
