import AuthenticationServices
@testable import tauri_plugin_passkey
import XCTest

final class Base64URLTests: XCTestCase {
    func testEncodeAppliesUrlSafeSubstitutionsAndStripsPadding() {
        // Standard base64 of these two bytes is "+/8=", exercising all three
        // transforms: '+' -> '-', '/' -> '_', and '=' padding removed.
        XCTAssertEqual(Data([0xFB, 0xFF]).base64URLEncodedString(), "-_8")
    }

    func testDecodeRestoresPaddingAndReversesSubstitutions() {
        XCTAssertEqual(base64URLDecode("-_8"), Data([0xFB, 0xFF]))
    }

    func testRoundTrip() {
        let samples: [[UInt8]] = [
            [],
            [0x00],
            [0x00, 0x01, 0x02],
            [0xDE, 0xAD, 0xBE, 0xEF],
            Array(0 ... 255).map { UInt8($0) },
        ]
        for bytes in samples {
            let data = Data(bytes)
            let encoded = data.base64URLEncodedString()
            XCTAssertFalse(encoded.contains("+"))
            XCTAssertFalse(encoded.contains("/"))
            XCTAssertFalse(encoded.contains("="))
            XCTAssertEqual(base64URLDecode(encoded), data)
        }
    }

    func testDecodeReturnsNilForInvalidInput() {
        XCTAssertNil(base64URLDecode("not valid base64 @@@"))
    }
}

final class RegistrationOptionsDecodingTests: XCTestCase {
    private func decode(_ json: String) throws -> RegistrationOptions {
        try JSONDecoder().decode(RegistrationOptions.self, from: Data(json.utf8))
    }

    func testDecodesFieldsAndPrfExtension() throws {
        let json = """
        {"rp":{"id":"example.com"},"user":{"id":"AQID","name":"alice","displayName":"Alice"},
         "challenge":"Y2hhbA","pubKeyCredParams":[{"type":"public-key","alg":-7}],"extensions":{"prf":{}}}
        """
        let opts = try decode(json)
        XCTAssertEqual(opts.rp.id, "example.com")
        XCTAssertEqual(opts.user.name, "alice")
        XCTAssertEqual(opts.user.displayName, "Alice")
        XCTAssertEqual(opts.challenge, "Y2hhbA")
        XCTAssertNotNil(opts.extensions?.prf)
    }

    func testDecodesRegistrationPrfRequest() throws {
        let json = """
        {"rp":{"id":"example.com"},"user":{"id":"dQ","name":"alice"},"challenge":"Y2g","pubKeyCredParams":[],"extensions":{"prf":{}}}
        """
        let options = try JSONDecoder().decode(RegistrationOptions.self, from: Data(json.utf8))
        XCTAssertNotNil(options.extensions?.prf)
    }

    func testDisplayNameIsOptional() throws {
        // The plugin falls back to `name` when displayName is absent; here we
        // pin that the field decodes to nil rather than failing.
        let json = """
        {"rp":{"id":"example.com"},"user":{"id":"AQID","name":"alice"},"challenge":"Y2hhbA","pubKeyCredParams":[]}
        """
        let opts = try decode(json)
        XCTAssertNil(opts.user.displayName)
        XCTAssertNil(opts.extensions)
    }

    func testMissingRequiredFieldThrows() {
        // No `rp` -> decoding must fail (the plugin then rejects the invoke).
        let json = """
        {"user":{"id":"AQID","name":"alice"},"challenge":"Y2hhbA"}
        """
        XCTAssertThrowsError(try decode(json))
    }
}

final class AuthenticationOptionsDecodingTests: XCTestCase {
    private func decode(_ json: String) throws -> AuthenticationOptions {
        try JSONDecoder().decode(AuthenticationOptions.self, from: Data(json.utf8))
    }

    func testDecodesBrowserPrfSalts() throws {
        let json = """
        {"rpId":"example.com","challenge":"Y2g","extensions":{"prf":{"eval":{"first":"c2FsdDE","second":"c2FsdDI"}}}}
        """
        let options = try JSONDecoder().decode(AuthenticationOptions.self, from: Data(json.utf8))
        XCTAssertEqual(options.extensions?.prf?.eval?.first, "c2FsdDE")
        XCTAssertEqual(options.extensions?.prf?.eval?.second, "c2FsdDI")
    }

    func testSecondSaltIsOptional() throws {
        let json = """
        {"rpId":"example.com","challenge":"Y2hhbA",
         "extensions":{"prf":{"eval":{"first":"c2FsdDE"}}}}
        """
        let opts = try decode(json)
        XCTAssertEqual(opts.extensions?.prf?.eval?.first, "c2FsdDE")
        XCTAssertNil(opts.extensions?.prf?.eval?.second)
    }

    func testMissingRpIdThrows() {
        let json = """
        {"challenge":"Y2hhbA"}
        """
        XCTAssertThrowsError(try decode(json))
    }
}

final class PasskeyHandlerErrorTests: XCTestCase {
    func testErrorDescriptions() {
        XCTAssertEqual(
            PasskeyHandlerError.unexpectedCredentialType.errorDescription,
            "Unexpected credential type in authorization response"
        )
        XCTAssertEqual(
            PasskeyHandlerError.missingAttestationObject.errorDescription,
            "Registration returned no attestation object"
        )
    }
}

final class RegistrationOptionsNewFieldsDecodingTests: XCTestCase {
    private func decode(_ json: String) throws -> RegistrationOptions {
        try JSONDecoder().decode(RegistrationOptions.self, from: Data(json.utf8))
    }

    func testOptionalCeremonyFieldsDefaultToNil() throws {
        let opts = try decode("""
        {"rp":{"id":"example.com"},"user":{"id":"AQID","name":"alice"},"challenge":"Y2hhbA","pubKeyCredParams":[]}
        """)
        XCTAssertNil(opts.authenticatorSelection)
        XCTAssertNil(opts.attestation)
        XCTAssertNil(opts.timeout)
        XCTAssertEqual(opts.pubKeyCredParams.count, 0)
    }

    func testDecodesCeremonyFields() throws {
        let opts = try decode("""
        {"rp":{"id":"example.com","name":"Example"},"user":{"id":"AQID","name":"alice"},"challenge":"Y2hhbA",
         "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
         "authenticatorSelection":{"authenticatorAttachment":"cross-platform","userVerification":"required",
                                   "requireResidentKey":false},
         "attestation":"direct","timeout":30000}
        """)
        XCTAssertEqual(opts.authenticatorSelection?.authenticatorAttachment, "cross-platform")
        XCTAssertEqual(opts.authenticatorSelection?.userVerification, "required")
        XCTAssertEqual(opts.attestation, "direct")
        XCTAssertEqual(opts.timeout, 30000)
        XCTAssertEqual(opts.pubKeyCredParams.map(\.alg), [-7, -257])
    }

    func testNullTimeoutDecodesToNil() throws {
        let opts = try decode("""
        {"rp":{"id":"example.com"},"user":{"id":"AQID","name":"alice"},"challenge":"Y2hhbA","pubKeyCredParams":[],
         "timeout":null,"attestation":null,"authenticatorSelection":null}
        """)
        XCTAssertNil(opts.timeout)
        XCTAssertNil(opts.attestation)
        XCTAssertNil(opts.authenticatorSelection)
    }
}

final class AuthenticationOptionsNewFieldsDecodingTests: XCTestCase {
    private func decode(_ json: String) throws -> AuthenticationOptions {
        try JSONDecoder().decode(AuthenticationOptions.self, from: Data(json.utf8))
    }

    func testOptionalCeremonyFieldsDefaultToNil() throws {
        let opts = try decode(#"{"rpId":"example.com","challenge":"Y2hhbA"}"#)
        XCTAssertNil(opts.userVerification)
        XCTAssertNil(opts.timeout)
    }

    func testDecodesCeremonyFields() throws {
        let opts = try decode(#"{"rpId":"example.com","challenge":"Y2hhbA","userVerification":"discouraged","timeout":5000}"#)
        XCTAssertEqual(opts.userVerification, "discouraged")
        XCTAssertEqual(opts.timeout, 5000)
    }
}

final class CeremonyParametersTests: XCTestCase {
    func testRegistrationParametersDecodeAndMapFields() throws {
        let opts = try JSONDecoder().decode(RegistrationOptions.self, from: Data("""
        {"rp":{"id":"example.com"},"user":{"id":"AQID","name":"alice"},"challenge":"Y2hhbA",
         "pubKeyCredParams":[{"type":"public-key","alg":-7}],"excludeCredentials":[{"type":"public-key","id":"BAU"}],
         "authenticatorSelection":{"authenticatorAttachment":"platform","userVerification":"preferred"},
         "attestation":"none","extensions":{"prf":{}}}
        """.utf8))
        let params = try RegistrationParameters(opts)
        XCTAssertEqual(params.domain, "example.com")
        XCTAssertEqual(params.challenge, Data("chal".utf8))
        XCTAssertEqual(params.userID, Data([1, 2, 3]))
        XCTAssertEqual(params.displayName, "alice")
        XCTAssertEqual(params.excludeCredentials, [Data([4, 5])])
        XCTAssertTrue(params.prfEnabled)
        XCTAssertEqual(params.attachment, "platform")
        XCTAssertEqual(params.userVerification, "preferred")
        XCTAssertEqual(params.attestation, "none")
        XCTAssertEqual(params.algorithms, [-7])
        XCTAssertEqual(params.timeoutMilliseconds, CeremonyOptions.defaultTimeoutMilliseconds)
    }

    func testRegistrationParametersRejectInvalidChallenge() throws {
        let opts = try JSONDecoder().decode(RegistrationOptions.self, from: Data("""
        {"rp":{"id":"example.com"},"user":{"id":"AQID","name":"alice"},"challenge":"@@@","pubKeyCredParams":[]}
        """.utf8))
        XCTAssertThrowsError(try RegistrationParameters(opts))
    }

    func testAuthenticationParametersDecodeSaltsAndTimeout() throws {
        let opts = try JSONDecoder().decode(AuthenticationOptions.self, from: Data("""
        {"rpId":"example.com","challenge":"Y2hhbA","allowCredentials":[{"type":"public-key","id":"BAU"}],
         "userVerification":"required","timeout":1234,
         "extensions":{"prf":{"eval":{"first":"c2FsdDE","second":"c2FsdDI"}}}}
        """.utf8))
        let params = try AuthenticationParameters(opts)
        XCTAssertEqual(params.domain, "example.com")
        XCTAssertEqual(params.allowCredentials, [Data([4, 5])])
        XCTAssertEqual(params.prfSalt1, Data("salt1".utf8))
        XCTAssertEqual(params.prfSalt2, Data("salt2".utf8))
        XCTAssertEqual(params.userVerification, "required")
        XCTAssertEqual(params.timeoutMilliseconds, 1234)
    }

    func testAuthenticationParametersRejectInvalidPrfSalt() throws {
        let opts = try JSONDecoder().decode(AuthenticationOptions.self, from: Data("""
        {"rpId":"example.com","challenge":"Y2hhbA","extensions":{"prf":{"eval":{"first":"@@@"}}}}
        """.utf8))
        XCTAssertThrowsError(try AuthenticationParameters(opts))
    }
}

final class CeremonyOptionsTests: XCTestCase {
    func testUserVerificationMapping() {
        XCTAssertEqual(CeremonyOptions.userVerification("required"), .required)
        XCTAssertEqual(CeremonyOptions.userVerification("preferred"), .preferred)
        XCTAssertEqual(CeremonyOptions.userVerification("discouraged"), .discouraged)
        XCTAssertNil(CeremonyOptions.userVerification("bogus"))
        XCTAssertNil(CeremonyOptions.userVerification(nil))
    }

    func testAttestationMapping() {
        XCTAssertEqual(CeremonyOptions.attestation("none"), ASAuthorizationPublicKeyCredentialAttestationKind.none)
        XCTAssertEqual(CeremonyOptions.attestation("indirect"), .indirect)
        XCTAssertEqual(CeremonyOptions.attestation("direct"), .direct)
        XCTAssertEqual(CeremonyOptions.attestation("enterprise"), .enterprise)
        XCTAssertNil(CeremonyOptions.attestation("bogus"))
        XCTAssertNil(CeremonyOptions.attestation(nil))
    }

    func testIncludesPlatform() {
        XCTAssertTrue(CeremonyOptions.includesPlatform(attachment: nil))
        XCTAssertTrue(CeremonyOptions.includesPlatform(attachment: "platform"))
        XCTAssertFalse(CeremonyOptions.includesPlatform(attachment: "cross-platform"))
    }

    func testIncludesSecurityKey() {
        XCTAssertTrue(CeremonyOptions.includesSecurityKey(attachment: nil))
        XCTAssertTrue(CeremonyOptions.includesSecurityKey(attachment: "cross-platform"))
        XCTAssertFalse(CeremonyOptions.includesSecurityKey(attachment: "platform"))
    }

    func testSecurityKeyAlgorithms() {
        XCTAssertEqual(CeremonyOptions.securityKeyAlgorithms([]).map(\.algorithm), [.ES256])
        XCTAssertEqual(CeremonyOptions.securityKeyAlgorithms([-7]).map(\.algorithm), [.ES256])
        XCTAssertEqual(CeremonyOptions.securityKeyAlgorithms([-257, -7, -8]).map(\.algorithm), [.ES256])
        // The RP allows nothing ASAuthorization can produce for a security key.
        XCTAssertEqual(CeremonyOptions.securityKeyAlgorithms([-257, -8]).count, 0)
    }

    func testRequireES256PassesWhenES256IsAllowed() {
        XCTAssertNoThrow(try CeremonyOptions.requireES256([]))
        XCTAssertNoThrow(try CeremonyOptions.requireES256([-7]))
        XCTAssertNoThrow(try CeremonyOptions.requireES256([-257, -7, -8]))
    }

    func testRequireES256ThrowsWhenES256IsAbsent() {
        // Gates passkeys and security keys alike: neither can produce anything but ES256.
        XCTAssertThrowsError(try CeremonyOptions.requireES256([-257, -8])) { error in
            guard case PasskeyHandlerError.unsupportedAlgorithm = error else {
                return XCTFail("expected unsupportedAlgorithm, got \(error)")
            }
            XCTAssertEqual(PluginErrorCode.from(error), "unsupported")
        }
    }

    func testTimeoutDefaultsWhenAbsentOrNonPositive() {
        XCTAssertEqual(CeremonyOptions.defaultTimeoutMilliseconds, 60000)
        XCTAssertEqual(CeremonyOptions.timeoutMilliseconds(nil), 60000)
        XCTAssertEqual(CeremonyOptions.timeoutMilliseconds(0), 60000)
        XCTAssertEqual(CeremonyOptions.timeoutMilliseconds(-5), 60000)
        XCTAssertEqual(CeremonyOptions.timeoutMilliseconds(15000), 15000)
    }

    func testPrfSupportCheckPassesWhenNotRequested() {
        XCTAssertNoThrow(try CeremonyOptions.requirePrfSupport(false))
    }

    func testPrfSupportCheckPassesOnCurrentOS() {
        // The test runtime is newer than the PRF floor, so a request must pass.
        XCTAssertNoThrow(try CeremonyOptions.requirePrfSupport(true))
    }
}

final class PluginErrorCodeTests: XCTestCase {
    func testAuthorizationCanceledIsCancelled() {
        let error = NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.canceled.rawValue)
        XCTAssertEqual(PluginErrorCode.from(error), "cancelled")
        XCTAssertEqual(PluginErrorCode.from(ASAuthorizationError(.canceled)), "cancelled")
    }

    func testCancellationErrorIsCancelled() {
        XCTAssertEqual(PluginErrorCode.from(CancellationError()), "cancelled")
    }

    func testTimeoutErrorIsTimeout() {
        XCTAssertEqual(PluginErrorCode.from(TimeoutError()), "timeout")
    }

    func testUnsupportedHandlerErrors() {
        XCTAssertEqual(PluginErrorCode.from(PasskeyHandlerError.prfUnavailable), "unsupported")
        XCTAssertEqual(PluginErrorCode.from(PasskeyHandlerError.noAuthenticatorMatches), "unsupported")
        XCTAssertEqual(PluginErrorCode.from(PasskeyHandlerError.unsupportedAlgorithm), "unsupported")
    }

    func testOtherErrorsHaveNoCode() {
        XCTAssertNil(PluginErrorCode.from(PasskeyHandlerError.unexpectedCredentialType))
        let failed = NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.failed.rawValue)
        XCTAssertNil(PluginErrorCode.from(failed))
        XCTAssertNil(PluginErrorCode.from(NSError(domain: "other", code: 1)))
    }

    func testUnsupportedErrorMessages() {
        XCTAssertEqual(PasskeyHandlerError.prfUnavailable.errorDescription, "PRF requires iOS 18 or later")
        XCTAssertNotNil(PasskeyHandlerError.noAuthenticatorMatches.errorDescription)
        XCTAssertEqual(
            PasskeyHandlerError.unsupportedAlgorithm.errorDescription,
            "pubKeyCredParams does not include ES256 (-7), the only algorithm Apple authenticators support"
        )
        XCTAssertNotNil(TimeoutError().errorDescription)
    }
}
