import AuthenticationServices
import Foundation
import UIKit

@MainActor
final class PasskeyHandler: NSObject {
    private var continuation: CheckedContinuation<ASAuthorization, Error>?
    private var activeController: ASAuthorizationController?
    private var timeoutTask: Task<Void, Never>?

    func register(_ params: RegistrationParameters) async throws -> ASAuthorization {
        let userVerification = CeremonyOptions.userVerification(params.userVerification)
        let attestation = CeremonyOptions.attestation(params.attestation)
        var requests: [ASAuthorizationRequest] = []

        if CeremonyOptions.includesPlatform(attachment: params.attachment) {
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: params.domain)
            let request = provider.createCredentialRegistrationRequest(
                challenge: params.challenge,
                name: params.username,
                userID: params.userID
            )
            if let userVerification {
                request.userVerificationPreference = userVerification
            }
            if let attestation {
                request.attestationPreference = attestation
            }
            if params.prfEnabled, #available(iOS 18.0, *) {
                request.prf = .checkForSupport
            }
            if !params.excludeCredentials.isEmpty {
                request.excludedCredentials = params.excludeCredentials.map {
                    ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
                }
            }
            requests.append(request)
        }

        let algorithms = CeremonyOptions.securityKeyAlgorithms(params.algorithms)
        if CeremonyOptions.includesSecurityKey(attachment: params.attachment), !algorithms.isEmpty {
            let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: params.domain)
            let request = provider.createCredentialRegistrationRequest(
                challenge: params.challenge,
                displayName: params.displayName,
                name: params.username,
                userID: params.userID
            )
            request.credentialParameters = algorithms
            if let userVerification {
                request.userVerificationPreference = userVerification
            }
            if let attestation {
                request.attestationPreference = attestation
            }
            if !params.excludeCredentials.isEmpty {
                request.excludedCredentials = params.excludeCredentials.map {
                    ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                        credentialID: $0,
                        transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                    )
                }
            }
            requests.append(request)
        }

        guard !requests.isEmpty else {
            throw PasskeyHandlerError.noAuthenticatorMatches
        }
        return try await perform(requests, timeoutMilliseconds: params.timeoutMilliseconds)
    }

    func authenticate(_ params: AuthenticationParameters) async throws -> ASAuthorization {
        try CeremonyOptions.requirePrfSupport(params.prfSalt1 != nil)
        let userVerification = CeremonyOptions.userVerification(params.userVerification)

        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: params.domain)
        let platformRequest = platformProvider.createCredentialAssertionRequest(challenge: params.challenge)

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: params.domain)
        let securityKeyRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: params.challenge)

        if let userVerification {
            platformRequest.userVerificationPreference = userVerification
            securityKeyRequest.userVerificationPreference = userVerification
        }

        if !params.allowCredentials.isEmpty {
            platformRequest.allowedCredentials = params.allowCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
            }
            securityKeyRequest.allowedCredentials = params.allowCredentials.map {
                ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: $0,
                    transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                )
            }
        }

        // PRF is only supported on platform authenticators (passkeys), not security keys
        if let salt1 = params.prfSalt1, #available(iOS 18.0, *) {
            let inputValues: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues
            if let salt2 = params.prfSalt2 {
                inputValues = .saltInput1(salt1, saltInput2: salt2)
            } else {
                inputValues = .saltInput1(salt1)
            }
            platformRequest.prf = .inputValues(inputValues)
        }

        return try await perform(
            [platformRequest, securityKeyRequest],
            timeoutMilliseconds: params.timeoutMilliseconds
        )
    }

    func cancel() {
        finish(.failure(CancellationError()), dismissSheet: true)
    }

    private func perform(
        _ requests: [ASAuthorizationRequest], timeoutMilliseconds: Int
    ) async throws -> ASAuthorization {
        let controller = ASAuthorizationController(authorizationRequests: requests)
        controller.delegate = self
        controller.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            self.activeController = controller
            self.startTimeout(milliseconds: timeoutMilliseconds)
            controller.performRequests()
        }
    }

    /// Dismiss the sheet and fail with `TimeoutError` if the user has not
    /// finished within the RP's timeout.
    private func startTimeout(milliseconds: Int) {
        timeoutTask?.cancel()
        let nanoseconds = UInt64(max(milliseconds, 0)) * 1_000_000
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled else {
                return
            }
            self?.finish(.failure(TimeoutError()), dismissSheet: true)
        }
    }

    /// Resume the pending ceremony exactly once. When `dismissSheet` is set the
    /// controller is cancelled too; its own didCompleteWithError(.canceled)
    /// then finds no continuation and is a no-op.
    private func finish(_ result: Result<ASAuthorization, Error>, dismissSheet: Bool) {
        timeoutTask?.cancel()
        timeoutTask = nil
        let pending = continuation
        continuation = nil
        let controller = activeController
        activeController = nil
        if dismissSheet {
            controller?.cancel()
        }
        pending?.resume(with: result)
    }
}

// MARK: - ASAuthorizationControllerDelegate

extension PasskeyHandler: ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
        return scene?.windows.first(where: { $0.isKeyWindow })
            ?? scene?.windows.first
            ?? UIWindow()
    }

    func authorizationController(
        controller _: ASAuthorizationController, didCompleteWithAuthorization auth: ASAuthorization
    ) {
        finish(.success(auth), dismissSheet: false)
    }

    func authorizationController(controller _: ASAuthorizationController, didCompleteWithError error: Error) {
        finish(.failure(error), dismissSheet: false)
    }
}

// MARK: - Response Serialization

func registrationJSON(from auth: ASAuthorization) throws -> [String: Any] {
    guard let reg = auth.credential as? ASAuthorizationPublicKeyCredentialRegistration else {
        throw PasskeyHandlerError.unexpectedCredentialType
    }
    guard let attestationObject = reg.rawAttestationObject else {
        throw PasskeyHandlerError.missingAttestationObject
    }
    var json: [String: Any] = [
        "id": reg.credentialID.base64URLEncodedString(),
        "rawId": reg.credentialID.base64URLEncodedString(),
        "type": "public-key",
        "response": [
            "attestationObject": attestationObject.base64URLEncodedString(),
            "clientDataJSON": reg.rawClientDataJSON.base64URLEncodedString(),
        ],
    ]

    // Extract PRF registration result (iOS 18+)
    if #available(iOS 18.0, *),
       let platformReg = reg as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
       let prfResult = platformReg.prf
    {
        json["prf"] = ["enabled": prfResult.isSupported]
    }

    return json
}

func assertionJSON(from auth: ASAuthorization) throws -> [String: Any] {
    guard let assertion = auth.credential as? ASAuthorizationPublicKeyCredentialAssertion else {
        throw PasskeyHandlerError.unexpectedCredentialType
    }
    var response: [String: Any] = [
        "authenticatorData": assertion.rawAuthenticatorData.base64URLEncodedString(),
        "clientDataJSON": assertion.rawClientDataJSON.base64URLEncodedString(),
        "signature": assertion.signature.base64URLEncodedString(),
    ]
    if !assertion.userID.isEmpty {
        response["userHandle"] = assertion.userID.base64URLEncodedString()
    }
    var json: [String: Any] = [
        "id": assertion.credentialID.base64URLEncodedString(),
        "rawId": assertion.credentialID.base64URLEncodedString(),
        "type": "public-key",
        "response": response,
    ]

    // Extract PRF assertion result (iOS 18+)
    if #available(iOS 18.0, *),
       let platformAssertion = assertion as? ASAuthorizationPlatformPublicKeyCredentialAssertion,
       let prfResult = platformAssertion.prf
    {
        let firstData = prfResult.first.withUnsafeBytes { Data($0) }
        var prfDict: [String: Any] = [
            "first": firstData.base64URLEncodedString(),
        ]
        if let second = prfResult.second {
            let secondData = second.withUnsafeBytes { Data($0) }
            prfDict["second"] = secondData.base64URLEncodedString()
        }
        json["prf"] = prfDict
    }

    return json
}
