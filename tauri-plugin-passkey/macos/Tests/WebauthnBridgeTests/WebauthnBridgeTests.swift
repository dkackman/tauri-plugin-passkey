@testable import WebauthnBridge
import XCTest

final class Base64URLTests: XCTestCase {
    func testEncodeAppliesUrlSafeSubstitutionsAndStripsPadding() {
        // Standard base64 of these two bytes is "+/8=", exercising all three
        // transforms: '+' -> '-', '/' -> '_', and '=' padding removed.
        XCTAssertEqual(Data([0xFB, 0xFF]).base64URLEncodedString(), "-_8")
    }

    func testEncodeOfEmptyDataIsEmptyString() {
        XCTAssertEqual(Data().base64URLEncodedString(), "")
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
            XCTAssertFalse(encoded.contains("+"), "encoded output must be URL-safe")
            XCTAssertFalse(encoded.contains("/"), "encoded output must be URL-safe")
            XCTAssertFalse(encoded.contains("="), "encoded output must be unpadded")
            XCTAssertEqual(base64URLDecode(encoded), data, "round trip must be lossless")
        }
    }

    func testDecodeReturnsNilForInvalidInput() {
        XCTAssertNil(base64URLDecode("not valid base64 @@@"))
    }
}

final class BridgeErrorTests: XCTestCase {
    func testErrorDescriptions() {
        XCTAssertEqual(
            BridgeError.unexpectedCredentialType.errorDescription,
            "Unexpected credential type in authorization response"
        )
        XCTAssertEqual(
            BridgeError.missingAttestationObject.errorDescription,
            "Registration returned no attestation object"
        )
    }
}
