import AuthenticationServices
import Foundation
import Tauri
import UIKit

// MARK: - Decodable argument wrappers

struct RegistrationOptions: Decodable {
    let rp: RelyingParty
    let user: User
    let challenge: String
    let extensions: RegistrationExtensions?
    let excludeCredentials: [CredentialDescriptor]?

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

    /// webauthn-rs-proto serializes RequestRegistrationExtensions with
    /// #[serde(rename_all = "camelCase")], so the wire key is `hmacCreateSecret`.
    struct RegistrationExtensions: Decodable {
        let hmacCreateSecret: Bool?
    }
}

struct AuthenticationOptions: Decodable {
    let rpId: String
    let challenge: String
    let allowCredentials: [CredentialDescriptor]?
    let extensions: AuthenticationExtensions?

    struct CredentialDescriptor: Decodable {
        let id: String
    }

    /// See RegistrationExtensions: the wire key is `hmacGetSecret`.
    struct AuthenticationExtensions: Decodable {
        let hmacGetSecret: HmacGetSecretInput?
    }

    struct HmacGetSecretInput: Decodable {
        let output1: String // base64url-encoded salt
        let output2: String? // optional second salt
    }
}

// MARK: - Plugin

class WebauthnPlugin: Plugin {
    @MainActor private var activeHandler: PasskeyHandler?

    @objc func cancel(_ invoke: Invoke) {
        guard #available(iOS 15.0, *) else {
            invoke.resolve()
            return
        }
        Task { @MainActor in
            self.activeHandler?.cancel()
            self.activeHandler = nil
        }
        invoke.resolve()
    }

    @objc func register(_ invoke: Invoke) {
        guard #available(iOS 15.0, *) else {
            invoke.reject("WebAuthn requires iOS 15.0 or later")
            return
        }

        // The Rust side sends serde_json::to_string(&options) via run_mobile_plugin
        // which double-serializes: the JSON string is itself JSON-encoded
        guard let jsonString = try? invoke.parseArgs(String.self),
              let jsonData = jsonString.data(using: .utf8),
              let options = try? JSONDecoder().decode(RegistrationOptions.self, from: jsonData)
        else {
            invoke.reject("Failed to parse registration options JSON")
            return
        }

        guard let challengeData = base64URLDecode(options.challenge),
              let userIDData = base64URLDecode(options.user.id)
        else {
            invoke.reject("Failed to decode base64url fields in registration options")
            return
        }

        let prfEnabled = options.extensions?.hmacCreateSecret ?? false
        let excluded = (options.excludeCredentials ?? []).compactMap { base64URLDecode($0.id) }

        Task { @MainActor in
            let handler = PasskeyHandler()
            self.activeHandler = handler
            defer { self.activeHandler = nil }
            do {
                let auth = try await handler.register(
                    domain: options.rp.id,
                    challenge: challengeData,
                    username: options.user.name,
                    displayName: options.user.displayName ?? options.user.name,
                    userID: userIDData,
                    excludeCredentials: excluded,
                    prfEnabled: prfEnabled
                )
                let json = try registrationJSON(from: auth)
                invoke.resolve(json)
            } catch {
                invoke.reject(error.localizedDescription)
            }
        }
    }

    @objc func authenticate(_ invoke: Invoke) {
        guard #available(iOS 15.0, *) else {
            invoke.reject("WebAuthn requires iOS 15.0 or later")
            return
        }

        guard let jsonString = try? invoke.parseArgs(String.self),
              let jsonData = jsonString.data(using: .utf8),
              let options = try? JSONDecoder().decode(AuthenticationOptions.self, from: jsonData)
        else {
            invoke.reject("Failed to parse authentication options JSON")
            return
        }

        guard let challengeData = base64URLDecode(options.challenge) else {
            invoke.reject("Failed to decode challenge in authentication options")
            return
        }

        let credentials = options.allowCredentials ?? []
        let allowedCredentialData = credentials.compactMap { base64URLDecode($0.id) }

        // Extract PRF salts from extensions
        let prfSalt1 = options.extensions?.hmacGetSecret.flatMap { base64URLDecode($0.output1) }
        let prfSalt2 = options.extensions?.hmacGetSecret?.output2.flatMap { base64URLDecode($0) }

        Task { @MainActor in
            let handler = PasskeyHandler()
            self.activeHandler = handler
            defer { self.activeHandler = nil }
            do {
                let auth = try await handler.authenticate(
                    domain: options.rpId,
                    challenge: challengeData,
                    allowCredentials: allowedCredentialData,
                    prfSalt1: prfSalt1,
                    prfSalt2: prfSalt2
                )
                let json = try assertionJSON(from: auth)
                invoke.resolve(json)
            } catch {
                invoke.reject(error.localizedDescription)
            }
        }
    }
}

// MARK: - Plugin Registration

@_cdecl("init_plugin_passkey")
func initPlugin() -> Plugin {
    WebauthnPlugin()
}
