# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately rather than opening a public issue.

Email **dkackman@gmail.com** with a description of the issue, the affected platform(s),
and, if possible, steps to reproduce. You should receive a response within a few days.

Please do not disclose the issue publicly until it has been addressed.

## Scope

This plugin bridges each platform's native WebAuthn/FIDO2/passkey APIs (macOS
ASAuthorization, iOS ASAuthorization, Android Credential Manager, Windows Hello/CTAP2,
and a Linux CTAP2 authenticator client) into a single Tauri command surface. Reports
about the plugin's own code — origin/RP ID validation, IPC boundary issues, PIN or PRF
secret handling, incorrect error propagation, cancellation races, or anything else in
the Rust core, the Swift/Kotlin bridges, or the JS bindings — are in scope.

Reports about the underlying platform authenticator implementations themselves (Apple's
ASAuthorization framework, Android's Credential Manager, Windows Hello, a hardware
security key's CTAP2 firmware, etc.) are out of scope; please report those to the
platform or hardware vendor.
