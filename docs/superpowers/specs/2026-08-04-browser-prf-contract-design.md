# Browser PRF as the internal contract

**Date:** 2026-08-04
**Branch:** `browser-prf-compat`
**Status:** approved, ready for planning

## Goal

Present one contract to consumer apps — the web shape — and have it mean the same
thing on every platform. Today the plugin accepts browser WebAuthn JSON at its JS
boundary but immediately translates PRF into the CTAP2 `hmac-secret` spelling, and
each backend then interprets that spelling differently. The result is a plugin that
looks browser-compatible and silently is not.

## The bug this fixes

Browser PRF derives the CTAP2 `hmac-secret` salt from the caller's salt:

```
ctap_salt = SHA-256("WebAuthn PRF" || 0x00 || prf_salt)
```

Three of the four backends already get this right, because they hand the salt to a
native API that applies the prefix itself:

- **macOS / iOS** — `ASAuthorizationPublicKeyCredentialPRFAssertionInput.saltInput1/2`
- **Android** — Credential Manager consumes browser JSON directly, so
  `WebauthnPlugin.kt` translates `hmacGetSecret` *back* into `prf` before the call

**CTAP2 is the outlier.** `ctap2/platform.rs` passes the caller's bytes through as a
raw `hmac-secret` salt. For the same input, Linux returns a different secret than
macOS — with no error. It also requires salts to be exactly 32 bytes, so a
spec-compliant caller with a 16- or 64-byte salt fails outright on Linux.

Windows has no PRF support at all and silently drops the extension.

## Design

### 1. One rule at the trait boundary

At the `Authenticator` trait boundary, PRF means **browser PRF**: salts are the
caller's raw `prf.eval.{first,second}` bytes, of any length. Each backend adapts:

| Backend    | Adaptation                                                     |
| ---------- | -------------------------------------------------------------- |
| macOS/iOS  | pass salts through to ASAuthorization (Apple applies the prefix) |
| Android    | pass `extensions.prf` through to Credential Manager              |
| CTAP2      | derive `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ salt)`                   |
| Windows    | unsupported — see §4                                             |

The 32-byte input restriction disappears; the digest is always 32 bytes.

### 2. PRF travels as a typed sibling, not inside the options

`webauthn-rs-proto` has no `prf` field and models the extension as `hmac-secret`, so
PRF leaves the options struct entirely. New `src/prf.rs`:

```rust
pub struct PrfRegistrationInput;                                   // `prf` was requested
pub struct PrfAuthenticationInput { first: Vec<u8>, second: Option<Vec<u8>> }
pub struct PrfRegistrationOutput { enabled: bool }
pub struct PrfAuthenticationOutput { first: Vec<u8>, second: Option<Vec<u8>> }
pub fn ctap_salt(salt: &[u8]) -> [u8; 32];                         // used only by ctap2
```

The trait becomes:

```rust
fn register(&self, origin, options, prf: Option<PrfRegistrationInput>, timeout)
    -> Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)>;
fn authenticate(&self, origin, options, prf: Option<PrfAuthenticationInput>, timeout)
    -> Result<(PublicKeyCredential, Option<PrfAuthenticationOutput>)>;
```

The proto types' `hmac_create_secret` / `hmac_get_secret` fields are never read or
written again. No backend sees the legacy spelling.

`commands.rs` deserializes the incoming JSON twice: once into the proto options
(which ignore the unknown `extensions.prf` key — the crate sets no
`deny_unknown_fields`) and once into the typed PRF input. On the way out it
serializes the credential and injects `clientExtensionResults.prf`. One spelling in,
one spelling out, no dual-shape acceptance.

### 3. Registration-time `prf.eval` is rejected

`prf.eval` at registration is valid in the browser type but is not implementable
uniformly (CTAP2 cannot do it). Passing it fails with a clear message rather than
being silently ignored, so a caller never waits for `prf.results` that will not
arrive. Registration returns `prf.enabled` only. This can be relaxed later without
breaking existing callers.

### 4. Unsupported PRF is web-shaped, not an error

Where a platform cannot do PRF (Windows), registration succeeds and returns
`clientExtensionResults.prf.enabled = false` — exactly what a browser reports for an
authenticator without `hmac-secret`. The app learns before it stores anything that it
cannot rely on PRF, and branches on the same field it would on the web.

An **assertion that actually passes salts** on such a platform errors, because
returning no secret silently risks unrecoverable user data. The error uses a new
`Error::Unsupported(String)` variant with kind `"unsupported"`, documented in
`guest-js/index.ts` alongside the other `PasskeyErrorKind` values, so callers can
branch on it rather than string-matching.

### 5. Android stops rewriting `residentKey`

`mobile.rs` currently overwrites `authenticatorSelection.residentKey` with
`"preferred"` on every Android registration, which both downgrades an explicit
`"required"` and silently inverts an explicit `"discouraged"`. New behavior:

| Caller asked      | Android does                                              |
| ----------------- | --------------------------------------------------------- |
| unset             | send `"preferred"` (Credential Manager needs it to save)   |
| `preferred`       | send `"preferred"`                                         |
| `required`        | send `"required"` — no longer downgraded                   |
| `discouraged`     | `Error::Unsupported` — Credential Manager only creates discoverable credentials |

Same options, same meaning, on every platform — or a clear error saying why not.

## What gets deleted

- `normalize.rs`'s entire PRF half: both input translations, `extension_field`'s
  multi-key/multi-container search, and `set_client_extension`'s seeding. What
  remains is the `requireResidentKey` default (~20 lines), which is still required
  because the proto type has no serde default for it.
- Android `WebauthnPlugin.kt` lines ~119–147: the `hmacGetSecret` → `prf` flip-back,
  now that Rust sends `prf` in the first place.
- iOS `WebauthnPlugin.swift`'s `hmacCreateSecret` / `hmacGetSecret` decoding, replaced
  by reading `extensions.prf`.
- CTAP2's `convert_salt` 32-byte error.

The mobile bridge's *response* contract (a flat `prf` object) is already prf-shaped on
both platforms and stays as is. macOS needs no Swift change — `macos.rs` sources the
salts from the new parameter instead of from the options extensions.

## Testing

- `prf.rs`: a known-answer test pinning `ctap_salt` to a fixed vector derived from the
  spec definition (not merely self-consistent), plus arbitrary-length salt coverage.
- CTAP2 conversion tests assert the *derived* salt, not the raw input.
- `commands.rs`: browser `prf` in, `clientExtensionResults.prf` out; `prf.eval` at
  registration rejected.
- Windows: `prf.enabled = false` at registration, `Error::Unsupported` when an
  assertion passes salts.
- Android/iOS native tests updated for the `prf` input shape; Android gains
  `residentKey` mapping tests including the `discouraged` rejection.
- `test-app/src-tauri` updated to the new trait signature.
- JS contract tests assert the single `prf` spelling in both directions.

## Non-goals

- Renaming the Android/iOS native `webauthn` identifiers (see `CLAUDE.md`).
- Supporting `prf.eval` at registration (§3).
- Adding PRF support to Windows.
