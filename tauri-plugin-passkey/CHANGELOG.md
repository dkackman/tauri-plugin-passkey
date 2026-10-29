# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0-alpha.1] - 2026-10-29

First release of `tauri-plugin-passkey`, an independent fork of
[`tauri-plugin-webauthn`](https://github.com/Profiidev/tauri-plugin-webauthn) 0.2.0 by
[ProfiiDev](https://github.com/Profiidev) (see [Upstream history](#upstream-history) and
`NOTICE`). Versioning restarts under the new crate and npm names. The entries below are
relative to `tauri-plugin-webauthn` 0.2.0.

### ⚠️ Breaking changes

- Renamed: crate `tauri-plugin-passkey`, npm package `tauri-plugin-passkey-api`, plugin
  id `passkey` (commands `plugin:passkey|…`, permissions `passkey:*`, config under
  `plugins.passkey`).
- JS types renamed `Webauthn*` → `Passkey*`.
- Errors reach the webview as tagged `{ kind, message }` objects. Kinds: `io`,
  `platform`, `serialization`, `validation`, `authenticator`, `unsupported`,
  `cancelled`, `busy` (non-exhaustive).
- The public Rust API is `init`, `Error` and `Result`; `WebauthnExt` is crate-private.
- PRF follows the browser contract on every platform: `extensions.prf` in,
  `clientExtensionResults.prf` out. `hmacCreateSecret` / `hmacGetSecret`,
  `prf.evalByCredential` and `prf.eval` at registration are rejected with `unsupported`.
- Minimum OS versions are now macOS 14 and iOS 17.4.
- License is Apache-2.0 (upstream is MIT; its notice is retained in `NOTICE`).

### 🚀 Features

- macOS support for passkeys and security keys via ASAuthorization (Swift bridge).
- PRF support on Linux, macOS 15+, iOS 18+ and Android.
- `timeout` option, enforced natively on every platform.
- `cancel()` works on iOS, macOS, Android and Linux.
- Optional `plugins.passkey.allowedOrigins` origin pinning, plus rpId/origin validation.
- Only one ceremony runs at a time; a concurrent request fails with `busy`.
- `PasskeyError` type and `isPasskeyError` guard in the JS API.
- Apple platforms honour `userVerification`, `authenticatorAttachment`, `attestation`
  and `excludeCredentials` at registration.

### 🐛 Bug Fixes

- Android: PRF results and origin verification hardened; each invoke settles exactly
  once.
- Linux (CTAP2): credential handling hardened.
- Malformed input from the webview is rejected with `validation` instead of panicking.
- PRF secrets are never logged.
- Optional request fields default correctly instead of failing deserialization.
- Windows: OpenSSL is built vendored, so the crate compiles without a system OpenSSL.
- iOS/macOS: the authorization controller is retained for the whole ceremony.

### 📚 Documentation

- New consumer README with a per-platform capability matrix, error-kind reference, PRF
  contract and per-platform setup (Android asset links, Apple associated domains).

### ⚙️ Miscellaneous

- Test suites for the JS API, Rust, Swift (macOS and iOS) and Android.
- CI on every supported platform; tag-driven publishing to crates.io and npm with
  trusted publishing.
- Dependency floors: tauri 2.11.1, tokio 1.54.1, openssl 0.10.80,
  webauthn-authenticator-rs 0.5.5.

## Upstream history

Releases of [`tauri-plugin-webauthn`](https://github.com/Profiidev/tauri-plugin-webauthn)
by [ProfiiDev](https://github.com/Profiidev), from which this project was forked. They were
published under that name, not as `tauri-plugin-passkey`.

### tauri-plugin-webauthn 0.2.0 - 2025-05-16

- Windows native WebAuthn API backend.
- Desktop CTAP2 moved to the `authenticator` crate behind an authenticator trait.
- Timeout option; PIN-entry cancellation.
- Fixed main-thread blocking, missing command permissions and incorrect `cfg` gates.

### tauri-plugin-webauthn 0.1.1 - 2025-05-13

- Android support via Credential Manager.

### tauri-plugin-webauthn 0.1.0 - 2025-05-12

- Initial release: desktop FIDO2 (CTAP2) registration and authentication, PIN handling,
  Windows security keys, and the JS API.
