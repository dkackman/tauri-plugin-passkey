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
         "challenge":"Y2hhbA","extensions":{"hmacCreateSecret":true}}
        """
        let opts = try decode(json)
        XCTAssertEqual(opts.rp.id, "example.com")
        XCTAssertEqual(opts.user.name, "alice")
        XCTAssertEqual(opts.user.displayName, "Alice")
        XCTAssertEqual(opts.challenge, "Y2hhbA")
        XCTAssertEqual(opts.extensions?.hmacCreateSecret, true)
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

    func testDecodesBothPrfSalts() throws {
        let json = """
        {"rpId":"example.com","challenge":"Y2hhbA",
         "extensions":{"hmacGetSecret":{"output1":"c2FsdDE","output2":"c2FsdDI"}}}
        """
        let opts = try decode(json)
        XCTAssertEqual(opts.rpId, "example.com")
        XCTAssertEqual(opts.extensions?.hmacGetSecret?.output1, "c2FsdDE")
        XCTAssertEqual(opts.extensions?.hmacGetSecret?.output2, "c2FsdDI")
    }

    func testSecondSaltIsOptional() throws {
        let json = """
        {"rpId":"example.com","challenge":"Y2hhbA",
         "extensions":{"hmacGetSecret":{"output1":"c2FsdDE"}}}
        """
        let opts = try decode(json)
        XCTAssertEqual(opts.extensions?.hmacGetSecret?.output1, "c2FsdDE")
        XCTAssertNil(opts.extensions?.hmacGetSecret?.output2)
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
