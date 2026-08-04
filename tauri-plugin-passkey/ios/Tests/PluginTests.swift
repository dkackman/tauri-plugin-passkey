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
         "challenge":"Y2hhbA","extensions":{"prf":{}}}
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
        {"rp":{"id":"example.com"},"user":{"id":"dQ","name":"alice"},"challenge":"Y2g","extensions":{"prf":{}}}
        """
        let options = try JSONDecoder().decode(RegistrationOptions.self, from: Data(json.utf8))
        XCTAssertNotNil(options.extensions?.prf)
    }

    func testDisplayNameIsOptional() throws {
        // The plugin falls back to `name` when displayName is absent; here we
        // pin that the field decodes to nil rather than failing.
        let json = """
        {"rp":{"id":"example.com"},"user":{"id":"AQID","name":"alice"},"challenge":"Y2hhbA"}
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
