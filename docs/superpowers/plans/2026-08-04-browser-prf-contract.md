# Browser PRF Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the browser `prf` extension the single spelling a caller ever sees, and make it mean the same thing on every platform.

**Architecture:** PRF stops travelling inside `webauthn-rs-proto`'s `hmac-secret` extension fields and becomes a typed sibling value (`Option<PrfRegistrationInput>` / `Option<PrfAuthenticationInput>`) on the `Authenticator` trait, returned alongside the credential. `commands.rs` parses browser `prf` off the incoming JSON and writes browser `prf` into `clientExtensionResults` on the way out. Each backend adapts the browser-level salt to its own native layer — CTAP2 derives `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ salt)`, Apple and Android take the salt as-is because their native APIs do the derivation themselves.

**Tech Stack:** Rust (tauri plugin, `webauthn-rs-proto`, `sha2`), Kotlin (Android Credential Manager), Swift (iOS/macOS ASAuthorization), TypeScript (guest-js).

**Spec:** `docs/superpowers/specs/2026-08-04-browser-prf-contract-design.md`

## Global Constraints

- Rust edition 2021, `rust-version = "1.81"`. Do not raise the MSRV.
- `cargo clippy --all-targets -- -D warnings` must pass — CI treats warnings as errors, for both `tauri-plugin-passkey/` and `test-app/src-tauri/`.
- `cargo fmt --check`, `pnpm format`, and `pnpm lint` must pass before any commit.
- On macOS, run Rust tests via `tauri-plugin-passkey/scripts/test-macos.sh` — plain `cargo test` picks the wrong toolchain.
- Kotlin lint is `pnpm exec ktlint` (pinned version). Do not use a Homebrew ktlint.
- Android/iOS builds need `scripts/materialize-tauri-android.sh` / `scripts/materialize-tauri-ios.sh` run first.
- Backends are `cfg`-gated: on a macOS dev machine only `macos.rs` compiles. CTAP2 is verified by the ubuntu `Rust Checks` CI job, Windows by the `rust-windows` job. Keep every backend edited in the same commit that changes the trait, so no CI job sees a half-migrated tree.
- The salt derivation is exactly `SHA-256(UTF8("WebAuthn PRF") ‖ 0x00 ‖ salt)`. No other prefix, no truncation of the input salt.
- Base64url everywhere on the wire is unpadded (`URL_SAFE_NO_PAD`).

---

## File Structure

**Created:**

- `tauri-plugin-passkey/src/prf.rs` — everything PRF: the input/output types crossing the `Authenticator` trait, browser-JSON parsing and emission, the mobile-bridge flat-`prf` parsing shared by macOS and iOS/Android, and `ctap_salt`.

**Modified:**

- `tauri-plugin-passkey/src/error.rs` — new `Error::Unsupported` variant, kind `"unsupported"`.
- `tauri-plugin-passkey/src/normalize.rs` — loses its PRF half; keeps the `requireResidentKey` default and gains the Android `residentKey` policy.
- `tauri-plugin-passkey/src/commands.rs` — parses `prf` in, writes `clientExtensionResults.prf` out.
- `tauri-plugin-passkey/src/authenticators/mod.rs` — trait signature.
- `tauri-plugin-passkey/src/authenticators/{ctap2/mod.rs,ctap2/platform.rs,macos.rs,mobile.rs,windows.rs}` — per-backend adaptation.
- `tauri-plugin-passkey/android/src/main/java/WebauthnPlugin.kt` — delete the `hmacGetSecret` → `prf` translation.
- `tauri-plugin-passkey/ios/Sources/WebauthnPlugin/WebauthnPlugin.swift` — decode `extensions.prf`.
- `test-app/src-tauri/src/lib.rs` — emit browser `prf`, read `clientExtensionResults.prf`.
- `tauri-plugin-passkey/guest-js/index.ts`, `README.md`, `tauri-plugin-passkey/macos/README.md` — document the contract.

---

### Task 1: The `prf` module

Pure data-shaping code with no callers yet. Everything here is unit-testable on any host.

**Files:**

- Create: `tauri-plugin-passkey/src/prf.rs`
- Modify: `tauri-plugin-passkey/src/lib.rs:10` (add `mod prf;`), `tauri-plugin-passkey/src/error.rs`, `tauri-plugin-passkey/Cargo.toml`

**Interfaces:**

- Consumes: nothing.
- Produces:
  - `crate::Error::Unsupported(String)` → `kind() == "unsupported"`
  - `prf::PrfRegistrationInput` (unit struct), `prf::PrfAuthenticationInput { first: Vec<u8>, second: Option<Vec<u8>> }`
  - `prf::PrfRegistrationOutput { enabled: bool }`, `prf::PrfAuthenticationOutput { first: Vec<u8>, second: Option<Vec<u8>> }`
  - `prf::registration_input_from_options(&Value) -> crate::Result<Option<PrfRegistrationInput>>`
  - `prf::authentication_input_from_options(&Value) -> crate::Result<Option<PrfAuthenticationInput>>`
  - `prf::set_registration_prf_input(&mut Value)` / `prf::set_authentication_prf_input(&mut Value, &PrfAuthenticationInput)`
  - `prf::set_registration_prf(&mut Value, Option<PrfRegistrationOutput>)` / `prf::set_authentication_prf(&mut Value, Option<PrfAuthenticationOutput>)`
  - `prf::registration_output_from_bridge(&Value) -> Option<PrfRegistrationOutput>` / `prf::authentication_output_from_bridge(&Value) -> Option<PrfAuthenticationOutput>`
  - `prf::ctap_salt(&[u8]) -> [u8; 32]`

- [ ] **Step 1: Add the `sha2` dependency**

In `tauri-plugin-passkey/Cargo.toml`, under `[dependencies]`, after `base64 = "0.23.0"`:

```toml
sha2 = "0.10"
```

- [ ] **Step 2: Add the `Unsupported` error variant**

In `tauri-plugin-passkey/src/error.rs`, add to the `Error` enum after the `Authenticator` variant:

```rust
    #[error("Unsupported on this platform: {0}")]
    Unsupported(String),
```

and to `kind()` after the `Authenticator` arm:

```rust
            Error::Unsupported(_) => "unsupported",
```

- [ ] **Step 3: Write the failing tests**

Create `tauri-plugin-passkey/src/prf.rs` containing only this test module (the code above it comes in Step 5):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // SHA-256("WebAuthn PRF" || 0x00 || "salt1"), computed from the spec definition.
    const SALT1_DERIVED: &str = "2a1990f9c9bbfe1bbf56abee2b5a0f59be5f633a35c2a5f07d85533eeecbdd3c";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn ctap_salt_matches_the_spec_vector() {
        assert_eq!(hex(&ctap_salt(b"salt1")), SALT1_DERIVED);
    }

    #[test]
    fn ctap_salt_accepts_any_input_length() {
        // Browser PRF salts are arbitrary length; the digest is always 32 bytes.
        assert_eq!(ctap_salt(b"").len(), 32);
        assert_eq!(ctap_salt(&[0u8; 64]).len(), 32);
        assert_ne!(ctap_salt(b"a"), ctap_salt(b"b"));
    }

    #[test]
    fn registration_input_detects_prf() {
        let options = json!({ "extensions": { "prf": {} } });
        assert!(registration_input_from_options(&options).unwrap().is_some());
    }

    #[test]
    fn registration_input_absent_without_prf() {
        assert!(registration_input_from_options(&json!({}))
            .unwrap()
            .is_none());
        assert!(registration_input_from_options(&json!({ "extensions": {} }))
            .unwrap()
            .is_none());
    }

    #[test]
    fn registration_input_rejects_eval() {
        let options = json!({ "extensions": { "prf": { "eval": { "first": "c2FsdDE" } } } });
        let err = registration_input_from_options(&options).unwrap_err();
        assert_eq!(err.kind(), "unsupported");
    }

    #[test]
    fn authentication_input_decodes_both_salts() {
        let options = json!({
            "extensions": { "prf": { "eval": { "first": "c2FsdDE", "second": "c2FsdDI" } } }
        });
        let input = authentication_input_from_options(&options).unwrap().unwrap();
        assert_eq!(input.first, b"salt1");
        assert_eq!(input.second.as_deref(), Some(&b"salt2"[..]));
    }

    #[test]
    fn authentication_input_accepts_non_32_byte_salts() {
        // "eA" is base64url for a single byte; browser PRF puts no length limit on salts.
        let options = json!({ "extensions": { "prf": { "eval": { "first": "eA" } } } });
        let input = authentication_input_from_options(&options).unwrap().unwrap();
        assert_eq!(input.first, b"x");
        assert!(input.second.is_none());
    }

    #[test]
    fn authentication_input_requires_eval_first() {
        let options = json!({ "extensions": { "prf": {} } });
        let err = authentication_input_from_options(&options).unwrap_err();
        assert_eq!(err.kind(), "validation");
    }

    #[test]
    fn authentication_input_rejects_bad_base64() {
        let options = json!({ "extensions": { "prf": { "eval": { "first": "!!!" } } } });
        let err = authentication_input_from_options(&options).unwrap_err();
        assert_eq!(err.kind(), "validation");
    }

    #[test]
    fn prf_inputs_are_written_into_options_json() {
        let mut options = json!({ "rpId": "example.com" });
        set_registration_prf_input(&mut options);
        assert_eq!(options["extensions"]["prf"], json!({}));

        let mut options = json!({ "rpId": "example.com" });
        set_authentication_prf_input(
            &mut options,
            &PrfAuthenticationInput {
                first: b"salt1".to_vec(),
                second: Some(b"salt2".to_vec()),
            },
        );
        assert_eq!(
            options["extensions"]["prf"]["eval"],
            json!({ "first": "c2FsdDE", "second": "c2FsdDI" })
        );
    }

    #[test]
    fn registration_output_becomes_client_extension_results() {
        // webauthn-rs-proto serializes credential extensions under `extensions`;
        // the browser contract is `clientExtensionResults`.
        let mut response = json!({ "id": "cred", "extensions": { "credProps": { "rk": true } } });
        set_registration_prf(&mut response, Some(PrfRegistrationOutput { enabled: true }));
        assert_eq!(
            response["clientExtensionResults"]["prf"],
            json!({ "enabled": true })
        );
        // pre-existing extension outputs survive the move
        assert_eq!(
            response["clientExtensionResults"]["credProps"],
            json!({ "rk": true })
        );
        assert!(response.get("extensions").is_none());
    }

    #[test]
    fn registration_output_absent_leaves_empty_client_extension_results() {
        let mut response = json!({ "id": "cred", "extensions": {} });
        set_registration_prf(&mut response, None);
        assert_eq!(response["clientExtensionResults"], json!({}));
        assert!(response.get("extensions").is_none());
    }

    #[test]
    fn authentication_output_becomes_prf_results() {
        let mut response = json!({ "id": "cred", "extensions": {} });
        set_authentication_prf(
            &mut response,
            Some(PrfAuthenticationOutput {
                first: b"secret".to_vec(),
                second: None,
            }),
        );
        assert_eq!(
            response["clientExtensionResults"]["prf"]["results"]["first"],
            json!("c2VjcmV0")
        );
        assert!(response["clientExtensionResults"]["prf"]["results"]
            .get("second")
            .is_none());
    }

    #[test]
    fn bridge_outputs_are_parsed_from_the_flat_prf_object() {
        // Both Swift bridges and the Kotlin plugin resolve a flat top-level `prf`.
        let v = json!({ "id": "cred", "prf": { "enabled": true } });
        assert_eq!(
            registration_output_from_bridge(&v),
            Some(PrfRegistrationOutput { enabled: true })
        );

        let v = json!({ "id": "cred", "prf": { "first": "c2VjcmV0", "second": "c2Vjb25k" } });
        assert_eq!(
            authentication_output_from_bridge(&v),
            Some(PrfAuthenticationOutput {
                first: b"secret".to_vec(),
                second: Some(b"second".to_vec()),
            })
        );

        assert!(registration_output_from_bridge(&json!({ "id": "cred" })).is_none());
        assert!(authentication_output_from_bridge(&json!({ "id": "cred" })).is_none());
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `tauri-plugin-passkey/scripts/test-macos.sh prf::` (on Linux: `cargo test prf::` from `tauri-plugin-passkey/`)
Expected: compile error — `mod prf` not declared / `ctap_salt` not found.

Register the module first: add `mod prf;` to `tauri-plugin-passkey/src/lib.rs` next to `mod normalize;`. Re-run; expected: FAIL with "cannot find function `ctap_salt`".

- [ ] **Step 5: Write the implementation**

Insert above the test module in `tauri-plugin-passkey/src/prf.rs`:

```rust
//! The browser `prf` extension, which is this plugin's only PRF spelling.
//!
//! PRF does not travel inside the `webauthn-rs-proto` options, because that crate
//! models the extension as CTAP2 `hmac-secret`. It crosses the `Authenticator`
//! trait as its own typed value, and at that boundary it always means *browser*
//! PRF: salts are the caller's raw `prf.eval.{first,second}` bytes, of any length.
//!
//! Backends that hand the salt to a native WebAuthn layer (ASAuthorization on
//! Apple, Credential Manager on Android) pass it through untouched — those layers
//! apply the spec's derivation themselves. A backend speaking raw CTAP2 must call
//! [`ctap_salt`] first.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The caller requested PRF at registration. Carries no salts: evaluating a salt
/// during creation is not supported (see `registration_input_from_options`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrfRegistrationInput;

/// `prf.eval` — browser-level salts, any length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfAuthenticationInput {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

/// `clientExtensionResults.prf.enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrfRegistrationOutput {
    pub enabled: bool,
}

/// `clientExtensionResults.prf.results`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfAuthenticationOutput {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

/// Derive the CTAP2 `hmac-secret` salt from a browser PRF salt:
/// `SHA-256(UTF8("WebAuthn PRF") || 0x00 || salt)`.
///
/// Only raw-CTAP2 backends need this. Native WebAuthn layers do it internally,
/// and applying it twice yields a different — silently wrong — secret.
pub fn ctap_salt(salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"WebAuthn PRF");
    hasher.update([0u8]);
    hasher.update(salt);
    hasher.finalize().into()
}

fn extensions(options: &Value) -> Option<&Map<String, Value>> {
    options.get("extensions").and_then(Value::as_object)
}

fn decode_salt(value: &Value, field: &str) -> crate::Result<Vec<u8>> {
    let encoded = value.as_str().ok_or_else(|| {
        crate::Error::Validation(format!("prf.eval.{field} must be a base64url string"))
    })?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        crate::Error::Validation(format!("prf.eval.{field} is not valid base64url: {e}"))
    })
}

/// Read the `prf` extension from browser creation options.
pub fn registration_input_from_options(options: &Value) -> crate::Result<Option<PrfRegistrationInput>> {
    let Some(prf) = extensions(options).and_then(|e| e.get("prf")) else {
        return Ok(None);
    };
    if prf.get("eval").is_some() {
        return Err(crate::Error::Unsupported(
            "prf.eval at registration is not supported; register with `prf: {}` and evaluate \
             salts during authentication"
                .into(),
        ));
    }
    Ok(Some(PrfRegistrationInput))
}

/// Read the `prf.eval` salts from browser request options.
pub fn authentication_input_from_options(
    options: &Value,
) -> crate::Result<Option<PrfAuthenticationInput>> {
    let Some(prf) = extensions(options).and_then(|e| e.get("prf")) else {
        return Ok(None);
    };
    let first = prf.get("eval").and_then(|e| e.get("first")).ok_or_else(|| {
        crate::Error::Validation("prf.eval.first is required when prf is requested".into())
    })?;
    let second = prf
        .get("eval")
        .and_then(|e| e.get("second"))
        .map(|v| decode_salt(v, "second"))
        .transpose()?;
    Ok(Some(PrfAuthenticationInput {
        first: decode_salt(first, "first")?,
        second,
    }))
}

fn extensions_mut(options: &mut Value) -> Option<&mut Map<String, Value>> {
    let obj = options.as_object_mut()?;
    obj.entry("extensions")
        .or_insert_with(|| Value::Object(Map::new()));
    obj.get_mut("extensions").and_then(Value::as_object_mut)
}

/// Write `extensions.prf = {}` into options bound for a native WebAuthn layer.
pub fn set_registration_prf_input(options: &mut Value) {
    if let Some(extensions) = extensions_mut(options) {
        extensions.insert("prf".into(), json!({}));
    }
}

/// Write `extensions.prf.eval` into options bound for a native WebAuthn layer.
pub fn set_authentication_prf_input(options: &mut Value, prf: &PrfAuthenticationInput) {
    let mut eval = Map::new();
    eval.insert("first".into(), json!(URL_SAFE_NO_PAD.encode(&prf.first)));
    if let Some(second) = &prf.second {
        eval.insert("second".into(), json!(URL_SAFE_NO_PAD.encode(second)));
    }
    if let Some(extensions) = extensions_mut(options) {
        extensions.insert("prf".into(), json!({ "eval": Value::Object(eval) }));
    }
}

/// Move the credential's serialized `extensions` to the browser's
/// `clientExtensionResults` key and insert `prf` if there is one.
fn set_client_extension_results(response: &mut Value, prf: Option<Value>) {
    let Some(obj) = response.as_object_mut() else {
        return;
    };
    let mut results = obj
        .remove("extensions")
        .or_else(|| obj.remove("clientExtensionResults"))
        .and_then(|v| match v {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(prf) = prf {
        results.insert("prf".into(), prf);
    }
    obj.insert("clientExtensionResults".into(), Value::Object(results));
}

/// Publish `clientExtensionResults.prf.enabled`.
pub fn set_registration_prf(response: &mut Value, prf: Option<PrfRegistrationOutput>) {
    set_client_extension_results(response, prf.map(|p| json!({ "enabled": p.enabled })));
}

/// Publish `clientExtensionResults.prf.results`.
pub fn set_authentication_prf(response: &mut Value, prf: Option<PrfAuthenticationOutput>) {
    let prf = prf.map(|p| {
        let mut results = Map::new();
        results.insert("first".into(), json!(URL_SAFE_NO_PAD.encode(&p.first)));
        if let Some(second) = &p.second {
            results.insert("second".into(), json!(URL_SAFE_NO_PAD.encode(second)));
        }
        json!({ "results": Value::Object(results) })
    });
    set_client_extension_results(response, prf);
}

/// Parse the flat top-level `prf` object the Swift and Kotlin bridges resolve.
pub fn registration_output_from_bridge(v: &Value) -> Option<PrfRegistrationOutput> {
    let enabled = v.get("prf")?.get("enabled")?.as_bool()?;
    Some(PrfRegistrationOutput { enabled })
}

/// Parse the flat top-level `prf` object the Swift and Kotlin bridges resolve.
pub fn authentication_output_from_bridge(v: &Value) -> Option<PrfAuthenticationOutput> {
    let prf = v.get("prf")?;
    let decode = |key: &str| {
        prf.get(key)
            .and_then(Value::as_str)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
    };
    Some(PrfAuthenticationOutput {
        first: decode("first")?,
        second: decode("second"),
    })
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `tauri-plugin-passkey/scripts/test-macos.sh prf::`
Expected: PASS, 13 tests.

- [ ] **Step 7: Lint and commit**

```bash
cd tauri-plugin-passkey
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/prf.rs src/lib.rs src/error.rs Cargo.toml ../Cargo.lock
git commit -m "feat: add browser prf module with spec-correct ctap salt derivation"
```

---

### Task 2: Move PRF onto the trait boundary

Mechanical migration: PRF leaves the proto options and becomes a parameter and a returned value. **CTAP2 keeps passing salts through raw in this task** — behavior is unchanged, only plumbing moves. The derivation lands in Task 3, so a reviewer can see the fix on its own.

Every backend must be edited here or CI's ubuntu/windows jobs will not compile.

**Files:**

- Modify: `tauri-plugin-passkey/src/authenticators/mod.rs:26-40`, `src/commands.rs:17-55`, `src/normalize.rs`, `src/authenticators/ctap2/mod.rs:44-89`, `src/authenticators/ctap2/platform.rs`, `src/authenticators/macos.rs`, `src/authenticators/mobile.rs`, `src/authenticators/windows.rs`

**Interfaces:**

- Consumes: everything Task 1 produced.
- Produces:
  - `Authenticator::register(&self, origin: Url, options: PublicKeyCredentialCreationOptions, prf: Option<PrfRegistrationInput>, timeout: u32) -> crate::Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)>`
  - `Authenticator::authenticate(&self, origin: Url, options: PublicKeyCredentialRequestOptions, prf: Option<PrfAuthenticationInput>, timeout: u32) -> crate::Result<(PublicKeyCredential, Option<PrfAuthenticationOutput>)>`
  - `normalize::default_require_resident_key(&mut Value)` (renamed from `normalize_creation_options`)
  - `ctap2::platform::perform_register(.., prf: Option<PrfRegistrationInput>, ..)` and `perform_authentication(.., prf: Option<PrfAuthenticationInput>, ..)` returning the same tuples

- [ ] **Step 1: Write the failing test**

Add to `tauri-plugin-passkey/src/normalize.rs`, replacing its existing test module entirely (the PRF tests there are being deleted with the code they cover):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_require_resident_key_when_absent() {
        let mut options = json!({
            "authenticatorSelection": { "residentKey": "discouraged", "userVerification": "required" }
        });
        default_require_resident_key(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(false)
        );
    }

    #[test]
    fn require_resident_key_true_when_resident_key_required() {
        let mut options = json!({ "authenticatorSelection": { "residentKey": "required" } });
        default_require_resident_key(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(true)
        );
    }

    #[test]
    fn does_not_clobber_explicit_require_resident_key() {
        let mut options = json!({
            "authenticatorSelection": { "residentKey": "required", "requireResidentKey": false }
        });
        default_require_resident_key(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(false)
        );
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `tauri-plugin-passkey/scripts/test-macos.sh normalize::`
Expected: FAIL — "cannot find function `default_require_resident_key`".

- [ ] **Step 3: Slim `normalize.rs` down to the resident-key default**

Replace everything above the test module in `tauri-plugin-passkey/src/normalize.rs` with:

```rust
//! Reconciles browser WebAuthn JSON with `webauthn-rs-proto`'s deserializer.
//!
//! The one remaining gap: `authenticatorSelection.requireResidentKey` has no serde
//! default in the proto crate, so a spec-compliant client that omits it (the DOM
//! type marks it optional and deprecated) fails to deserialize. PRF is not handled
//! here — see [`crate::prf`].

use serde_json::Value;

/// Fill in `requireResidentKey` from `residentKey` when the caller omitted it.
pub fn default_require_resident_key(options: &mut Value) {
    let Some(selection) = options
        .get_mut("authenticatorSelection")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    if selection.contains_key("requireResidentKey") {
        return;
    }
    // residentKey "required" implies a resident key; anything else does not.
    let required = selection.get("residentKey").and_then(Value::as_str) == Some("required");
    selection.insert("requireResidentKey".into(), Value::Bool(required));
}
```

- [ ] **Step 4: Change the trait**

In `tauri-plugin-passkey/src/authenticators/mod.rs`, extend the imports with
`use crate::prf::{PrfAuthenticationInput, PrfAuthenticationOutput, PrfRegistrationInput, PrfRegistrationOutput};`
and replace the two method signatures:

```rust
    /// Register a new webauthn credential.
    ///
    /// `prf` is the browser `prf` extension input. Backends fronting a native
    /// WebAuthn layer pass its salts through unchanged; raw-CTAP2 backends must
    /// derive theirs with [`crate::prf::ctap_salt`].
    ///
    /// This is a blocking call and should be run in a separate thread.
    fn register(
        &self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        prf: Option<PrfRegistrationInput>,
        timeout: u32,
    ) -> crate::Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)>;

    /// Authenticate using webauthn.
    ///
    /// See [`Authenticator::register`] for the meaning of `prf`.
    ///
    /// This is a blocking call and should be run in a separate thread.
    fn authenticate(
        &self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        prf: Option<PrfAuthenticationInput>,
        timeout: u32,
    ) -> crate::Result<(PublicKeyCredential, Option<PrfAuthenticationOutput>)>;
```

- [ ] **Step 5: Rewrite the two commands**

In `tauri-plugin-passkey/src/commands.rs`, replace the doc comment and both command bodies:

```rust
/// Options and responses cross this boundary as raw JSON so the plugin speaks the
/// browser's WebAuthn shapes. PRF is read from `extensions.prf` and returned in
/// `clientExtensionResults.prf`; it is the only PRF spelling accepted or emitted.
/// See [`crate::prf`].
#[command]
pub(crate) async fn register<R: Runtime>(
    app: AppHandle<R>,
    origin: Url,
    mut options: Value,
    timeout: Option<u32>,
) -> Result<Value> {
    crate::normalize::default_require_resident_key(&mut options);
    let prf = crate::prf::registration_input_from_options(&options)?;
    let options: PublicKeyCredentialCreationOptions = serde_json::from_value(options)?;
    crate::validation::validate_rp_id(&origin, &options.rp.id)?;
    let (credential, prf_output) = block_in_place(|| {
        app.webauthn()
            .register(origin, options, prf, timeout.unwrap_or(DEFAULT_TIMEOUT))
            .log()
    })?;
    let mut response = serde_json::to_value(credential)?;
    crate::prf::set_registration_prf(&mut response, prf_output);
    Ok(response)
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
    app: AppHandle<R>,
    origin: Url,
    options: Value,
    timeout: Option<u32>,
) -> Result<Value> {
    let prf = crate::prf::authentication_input_from_options(&options)?;
    let options: PublicKeyCredentialRequestOptions = serde_json::from_value(options)?;
    crate::validation::validate_rp_id(&origin, &options.rp_id)?;
    let (credential, prf_output) = block_in_place(|| {
        app.webauthn()
            .authenticate(origin, options, prf, timeout.unwrap_or(DEFAULT_TIMEOUT))
            .log()
    })?;
    let mut response = serde_json::to_value(credential)?;
    crate::prf::set_authentication_prf(&mut response, prf_output);
    Ok(response)
}
```

- [ ] **Step 6: Update the macOS backend**

In `tauri-plugin-passkey/src/authenticators/macos.rs`:

1. Import `use crate::prf::{self, PrfAuthenticationInput, PrfAuthenticationOutput, PrfRegistrationInput, PrfRegistrationOutput};`
2. `register`: take `prf: Option<PrfRegistrationInput>`, return the tuple, and replace the `prf_enabled` block (lines ~103-113) with `let prf_enabled: u8 = u8::from(prf.is_some());`
3. `register`: replace the tail with

```rust
        let json = await_swift_result(receiver, timeout)?;
        let v: serde_json::Value = serde_json::from_str(&json)?;
        Ok((
            parse_registration_response(&v)?,
            prf::registration_output_from_bridge(&v),
        ))
```

4. `authenticate`: take `prf: Option<PrfAuthenticationInput>`, return the tuple, and replace the salt extraction (lines ~171-184) with

```rust
        // ASAuthorization applies the WebAuthn PRF derivation itself, so the
        // browser-level salts go across the FFI boundary unchanged.
        let (salt1_ptr, salt1_len) = prf
            .as_ref()
            .map(|p| (p.first.as_ptr(), p.first.len()))
            .unwrap_or((std::ptr::null(), 0));

        let (salt2_ptr, salt2_len) = prf
            .as_ref()
            .and_then(|p| p.second.as_ref())
            .map(|s| (s.as_ptr(), s.len()))
            .unwrap_or((std::ptr::null(), 0));
```

5. `authenticate`: tail becomes

```rust
        let json = await_swift_result(receiver, timeout)?;
        let v: serde_json::Value = serde_json::from_str(&json)?;
        Ok((
            parse_authentication_response(&v)?,
            prf::authentication_output_from_bridge(&v),
        ))
```

6. Change `parse_registration_response` / `parse_authentication_response` to take `v: &serde_json::Value` instead of `json: &str` (drop the `serde_json::from_str` line at the top of each), and delete both `// Parse PRF ... result` blocks — construct the credential with `extensions: Default::default()`. Remove the now-unused `HmacGetSecretOutput` import.
7. Update the existing tests in this file that call `parse_*_response(json_str)` to parse the JSON first and assert on the `prf::*_output_from_bridge` helpers instead of `extensions.hmac_secret` / `extensions.hmac_get_secret`.

- [ ] **Step 7: Update the mobile backend**

In `tauri-plugin-passkey/src/authenticators/mobile.rs`, replace both methods:

```rust
    fn register(
        &self,
        _origin: Url,
        options: PublicKeyCredentialCreationOptions,
        prf: Option<PrfRegistrationInput>,
        _timeout: u32,
    ) -> crate::Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)> {
        let mut options = serde_json::to_value(&options)?;
        if prf.is_some() {
            // Credential Manager and ASAuthorization both want the browser spelling.
            crate::prf::set_registration_prf_input(&mut options);
        }

        let v: serde_json::Value = self
            .0
            .run_mobile_plugin("register", serde_json::to_string(&options)?)?;

        Ok((
            parse_registration_response(&v)?,
            crate::prf::registration_output_from_bridge(&v),
        ))
    }

    fn authenticate(
        &self,
        _origin: Url,
        options: PublicKeyCredentialRequestOptions,
        prf: Option<PrfAuthenticationInput>,
        _timeout: u32,
    ) -> crate::Result<(PublicKeyCredential, Option<PrfAuthenticationOutput>)> {
        let mut options = serde_json::to_value(&options)?;
        if let Some(prf) = &prf {
            crate::prf::set_authentication_prf_input(&mut options, prf);
        }

        let v: serde_json::Value = self
            .0
            .run_mobile_plugin("authenticate", serde_json::to_string(&options)?)?;

        Ok((
            parse_authentication_response(&v)?,
            crate::prf::authentication_output_from_bridge(&v),
        ))
    }
```

Delete the two `// Parse PRF ...` blocks in `parse_registration_response` / `parse_authentication_response` and build both credentials with `extensions: Default::default()`. Drop the now-unused `HmacGetSecretOutput`, `AuthenticationExtensionsClientOutputs`, `RegistrationExtensionsClientOutputs` and `ResidentKeyRequirement` imports (the resident-key override moves in Task 5 — leave the `if let Some(auth) = &mut options.authenticator_selection` block deleted for now, Task 5 reinstates it correctly).

- [ ] **Step 8: Update the Windows backend**

In `tauri-plugin-passkey/src/authenticators/windows.rs`, take the new parameters and ignore them for now (`let _ = prf;`), returning `Ok((credential, None))` from both methods. Task 4 gives them real behavior.

```rust
    fn register(
        &self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        prf: Option<PrfRegistrationInput>,
        timeout: u32,
    ) -> crate::Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)> {
        let _ = prf;
        let mut auth = Win10::default();
        let credential = auth.perform_register(origin, options, timeout).map_err(|e| {
            #[cfg(feature = "log")]
            log::error!("Failed to register: {:?}", e);
            crate::Error::WebAuthn(e)
        })?;
        Ok((credential, None))
    }
```

and the equivalent for `authenticate` with `perform_auth`.

- [ ] **Step 9: Update the CTAP2 backend (plumbing only)**

In `tauri-plugin-passkey/src/authenticators/ctap2/mod.rs`, both methods take the new `prf` parameter and forward it to `platform::perform_register` / `platform::perform_authentication`, returning those functions' tuples unchanged.

In `tauri-plugin-passkey/src/authenticators/ctap2/platform.rs`, add
`use crate::prf::{PrfAuthenticationInput, PrfAuthenticationOutput, PrfRegistrationInput, PrfRegistrationOutput};`
and make these four changes.

The two request converters take the PRF value and stop reading the proto `hmac_*`
fields (this task keeps the salts raw; Task 3 replaces the body of the first one):

```rust
fn convert_request_authentication_extensions(
    extensions: Option<RequestAuthenticationExtensions>,
    prf: Option<&PrfAuthenticationInput>,
) -> crate::Result<AuthenticationExtensionsClientInputs> {
    let hmac_get_secret = match prf {
        Some(p) => Some(HMACGetSecretInput {
            salt1: convert_salt(p.first.clone())?,
            salt2: p.second.clone().map(convert_salt).transpose()?,
        }),
        None => None,
    };

    Ok(AuthenticationExtensionsClientInputs {
        app_id: extensions.and_then(|e| e.appid),
        hmac_get_secret,
        ..Default::default()
    })
}

fn convert_request_registration_extensions(
    extensions: Option<RequestRegistrationExtensions>,
    prf: Option<PrfRegistrationInput>,
) -> AuthenticationExtensionsClientInputs {
    let mut inputs = extensions
        .map(|e| AuthenticationExtensionsClientInputs {
            cred_props: e.cred_props,
            min_pin_length: e.min_pin_length,
            credential_protection_policy: e
                .cred_protect
                .clone()
                .map(|c| convert_credential_protection_policy(c.credential_protection_policy)),
            enforce_credential_protection_policy: e
                .cred_protect
                .and_then(|c| c.enforce_credential_protection_policy),
            ..Default::default()
        })
        .unwrap_or_default();
    inputs.hmac_create_secret = prf.map(|_| true);
    inputs
}
```

The two `perform_*` functions gain the parameter and return the tuple. In
`perform_register` (call site at line ~82) and its tail (~line 126):

```rust
        extensions: convert_request_registration_extensions(options.extensions, prf),
```

```rust
    let prf_output = prf.map(|_| PrfRegistrationOutput {
        enabled: result.extensions.hmac_create_secret.unwrap_or(false),
    });
    Ok((credential, prf_output))
```

In `perform_authentication` (call site at line ~175) and its tail (~line 231):

```rust
        extensions: convert_request_authentication_extensions(options.extensions, prf.as_ref())?,
```

```rust
    let prf_output = result
        .extensions
        .hmac_get_secret
        .as_ref()
        .map(|h| PrfAuthenticationOutput {
            first: h.output1.to_vec(),
            second: h.output2.map(|s| s.to_vec()),
        });
    Ok((credential, prf_output))
```

`convert_response_registration_extensions` and `convert_response_authentication_extensions`
still run for the credential's other outputs (`credProps`, `appid`) — leave them, but
they no longer feed PRF to anyone.

Update the tests in this file's test module to pass the new second argument:
`convert_request_authentication_extensions(None, None)`,
`convert_request_registration_extensions(Some(ext), Some(PrfRegistrationInput))`, and
delete the `hmac_create_secret: Some(true)` field from the proto extension literals
they build, asserting on the `prf` argument instead.

- [ ] **Step 10: Verify the tree compiles and tests pass**

```bash
cd tauri-plugin-passkey
scripts/test-macos.sh                      # macOS backend + prf + normalize + wire_contract
cargo clippy --all-targets -- -D warnings
```

Expected: PASS. The ctap2/windows paths are compiled by CI, so also skim their diffs for typos before committing.

- [ ] **Step 11: Commit**

```bash
git add tauri-plugin-passkey/src
git commit -m "refactor: carry browser prf across the authenticator boundary"
```

---

### Task 3: The CTAP2 derivation (the actual fix)

**Files:**

- Modify: `tauri-plugin-passkey/src/authenticators/ctap2/platform.rs:284-313` (`convert_salt`, `convert_request_authentication_extensions`)

**Interfaces:**

- Consumes: `prf::ctap_salt`, `prf::PrfAuthenticationInput` from Tasks 1-2.
- Produces: no new signatures — `convert_salt` is deleted.

- [ ] **Step 1: Write the failing test**

Replace the `convert_request_authentication_extensions_maps_valid_prf_salts` and `convert_request_authentication_extensions_rejects_bad_salt_length` tests in `platform.rs`'s test module with:

```rust
    // SHA-256("WebAuthn PRF" || 0x00 || "salt1")
    const SALT1_DERIVED: [u8; 32] = [
        0x2a, 0x19, 0x90, 0xf9, 0xc9, 0xbb, 0xfe, 0x1b, 0xbf, 0x56, 0xab, 0xee, 0x2b, 0x5a, 0x0f,
        0x59, 0xbe, 0x5f, 0x63, 0x3a, 0x35, 0xc2, 0xa5, 0xf0, 0x7d, 0x85, 0x53, 0x3e, 0xee, 0xcb,
        0xdd, 0x3c,
    ];

    #[test]
    fn authentication_extensions_derive_ctap_salts_from_browser_salts() {
        let prf = PrfAuthenticationInput {
            first: b"salt1".to_vec(),
            second: None,
        };
        let out = convert_request_authentication_extensions(None, Some(&prf)).unwrap();
        let hmac = out.hmac_get_secret.unwrap();
        assert_eq!(hmac.salt1, SALT1_DERIVED);
        assert!(hmac.salt2.is_none());
    }

    #[test]
    fn authentication_extensions_accept_salts_of_any_length() {
        // Browser PRF salts are arbitrary length; the derivation makes them 32 bytes.
        let prf = PrfAuthenticationInput {
            first: vec![7u8; 3],
            second: Some(vec![9u8; 100]),
        };
        let out = convert_request_authentication_extensions(None, Some(&prf)).unwrap();
        let hmac = out.hmac_get_secret.unwrap();
        assert_eq!(hmac.salt1, crate::prf::ctap_salt(&[7u8; 3]));
        assert_eq!(hmac.salt2, Some(crate::prf::ctap_salt(&[9u8; 100])));
    }
```

- [ ] **Step 2: Run to verify it fails**

The CTAP2 backend does not compile on macOS or Windows. Run on Linux (or a Linux container with the CI dependencies):

Run: `cargo test --manifest-path tauri-plugin-passkey/Cargo.toml platform::tests::authentication_extensions`
Expected: FAIL — salts still equal the raw input, and the 100-byte salt errors with "PRF salt must be 32 bytes".

If no Linux environment is available, state that plainly in the commit message and let the ubuntu `Rust Checks` CI job be the verification — do not claim the test passed locally.

- [ ] **Step 3: Implement the derivation**

Delete `convert_salt` (lines ~283-291) and rewrite the salt mapping:

```rust
fn convert_request_authentication_extensions(
    extensions: Option<RequestAuthenticationExtensions>,
    prf: Option<&PrfAuthenticationInput>,
) -> crate::Result<AuthenticationExtensionsClientInputs> {
    // CTAP2 hmac-secret salts are derived from the browser's PRF salts; the
    // native WebAuthn layers on the other platforms do this for us.
    let hmac_get_secret = prf.map(|p| HMACGetSecretInput {
        salt1: crate::prf::ctap_salt(&p.first),
        salt2: p.second.as_deref().map(crate::prf::ctap_salt),
    });

    Ok(AuthenticationExtensionsClientInputs {
        app_id: extensions.and_then(|e| e.appid),
        hmac_get_secret,
        ..Default::default()
    })
}
```

The function no longer fails, but keep the `crate::Result` return so the call site at line ~175 is unchanged. (If clippy objects to a `Result` that is always `Ok`, drop the `Result` and the `?` at the call site.)

- [ ] **Step 4: Run the tests**

Run: `cargo test --manifest-path tauri-plugin-passkey/Cargo.toml platform::tests::authentication_extensions`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tauri-plugin-passkey/src/authenticators/ctap2/platform.rs
git commit -m "fix(ctap2): derive hmac-secret salts from browser prf salts

Linux previously used the caller's raw prf.eval salt as the CTAP2
hmac-secret salt, so the same salt produced a different secret than
macOS, iOS, and Android, with no error. Also lifts the 32-byte salt
restriction, since the derivation always yields 32 bytes."
```

---

### Task 4: Windows reports PRF as unsupported

**Files:**

- Modify: `tauri-plugin-passkey/src/authenticators/windows.rs`

**Interfaces:**

- Consumes: `Error::Unsupported`, `PrfRegistrationOutput` from Task 1.
- Produces: no new signatures.

- [ ] **Step 1: Write the failing test**

Add a test module at the bottom of `windows.rs`. It tests the policy helper, not the FFI, so it runs without a real authenticator:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_reports_prf_as_unavailable() {
        assert_eq!(
            registration_prf_output(Some(PrfRegistrationInput)),
            Some(PrfRegistrationOutput { enabled: false })
        );
        assert_eq!(registration_prf_output(None), None);
    }

    #[test]
    fn authentication_with_salts_is_rejected() {
        let err = reject_prf(Some(&PrfAuthenticationInput {
            first: b"salt1".to_vec(),
            second: None,
        }))
        .unwrap_err();
        assert_eq!(err.kind(), "unsupported");
        assert!(reject_prf(None).is_ok());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Windows-only code. Run `cargo test --target x86_64-pc-windows-msvc` if the toolchain is installed; otherwise rely on the `rust-windows` CI job and say so in the commit message.
Expected: FAIL — `registration_prf_output` not found.

- [ ] **Step 3: Implement**

Add above the `impl` block in `windows.rs`:

```rust
/// Windows' WebAuthn API exposes no PRF/hmac-secret support. Registration still
/// succeeds and reports `prf.enabled: false` — the same signal a browser gives for
/// an authenticator without hmac-secret — so callers learn before they store
/// anything that they cannot derive a secret here.
fn registration_prf_output(prf: Option<PrfRegistrationInput>) -> Option<PrfRegistrationOutput> {
    prf.map(|_| PrfRegistrationOutput { enabled: false })
}

/// An assertion that actually asks for a secret must fail loudly: silently
/// returning no secret risks data the caller can never decrypt again.
fn reject_prf(prf: Option<&PrfAuthenticationInput>) -> crate::Result<()> {
    if prf.is_some() {
        return Err(crate::Error::Unsupported(
            "PRF is not supported by the Windows WebAuthn API".into(),
        ));
    }
    Ok(())
}
```

Wire them in: `register` returns `Ok((credential, registration_prf_output(prf)))`; `authenticate` calls `reject_prf(prf.as_ref())?` before `perform_auth` and returns `Ok((credential, None))`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --target x86_64-pc-windows-msvc` (or CI).
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tauri-plugin-passkey/src/authenticators/windows.rs
git commit -m "feat(windows): report prf as unavailable instead of silently dropping it"
```

---

### Task 5: Android stops inverting `residentKey`

**Files:**

- Modify: `tauri-plugin-passkey/src/normalize.rs`, `tauri-plugin-passkey/src/authenticators/mobile.rs`

**Interfaces:**

- Consumes: `Error::Unsupported`.
- Produces: `normalize::apply_android_resident_key(&mut PublicKeyCredentialCreationOptions) -> crate::Result<()>`

The policy lives in `normalize.rs` rather than `mobile.rs` so it compiles and is tested on every host — `mobile.rs` is `cfg(mobile)` and its Rust tests never run in CI.

- [ ] **Step 1: Write the failing test**

Add to `normalize.rs`'s test module:

```rust
    use webauthn_rs_proto::{AuthenticatorSelectionCriteria, ResidentKeyRequirement};

    fn selection(resident_key: Option<ResidentKeyRequirement>) -> AuthenticatorSelectionCriteria {
        AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key,
            require_resident_key: false,
            user_verification: webauthn_rs_proto::UserVerificationPolicy::Preferred,
        }
    }

    fn creation_options(
        selection: Option<AuthenticatorSelectionCriteria>,
    ) -> webauthn_rs_proto::PublicKeyCredentialCreationOptions {
        let mut options: webauthn_rs_proto::PublicKeyCredentialCreationOptions =
            serde_json::from_value(json!({
                "rp": { "id": "example.com", "name": "Example" },
                "user": { "id": "dXNlci1pZA", "name": "alice", "displayName": "Alice" },
                "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
                "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
            }))
            .unwrap();
        options.authenticator_selection = selection;
        options
    }

    #[test]
    fn android_defaults_unset_resident_key_to_preferred() {
        let mut options = creation_options(None);
        apply_android_resident_key(&mut options).unwrap();
        assert!(matches!(
            options.authenticator_selection.unwrap().resident_key,
            Some(ResidentKeyRequirement::Preferred)
        ));
    }

    #[test]
    fn android_preserves_required_resident_key() {
        let mut options = creation_options(Some(selection(Some(ResidentKeyRequirement::Required))));
        apply_android_resident_key(&mut options).unwrap();
        assert!(matches!(
            options.authenticator_selection.unwrap().resident_key,
            Some(ResidentKeyRequirement::Required)
        ));
    }

    #[test]
    fn android_rejects_discouraged_resident_key() {
        let mut options =
            creation_options(Some(selection(Some(ResidentKeyRequirement::Discouraged))));
        let err = apply_android_resident_key(&mut options).unwrap_err();
        assert_eq!(err.kind(), "unsupported");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `tauri-plugin-passkey/scripts/test-macos.sh normalize::android`
Expected: FAIL — `apply_android_resident_key` not found.

- [ ] **Step 3: Implement**

Add to `normalize.rs`:

```rust
use webauthn_rs_proto::{
    AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions, ResidentKeyRequirement,
};

/// Android's Credential Manager only creates discoverable credentials, and will
/// not persist the passkey unless a resident key is requested. Fill in the default
/// when the caller said nothing, honour an explicit `preferred`/`required`, and
/// refuse `discouraged` rather than silently doing the opposite.
pub fn apply_android_resident_key(
    options: &mut PublicKeyCredentialCreationOptions,
) -> crate::Result<()> {
    let selection = options
        .authenticator_selection
        .get_or_insert_with(|| AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: None,
            require_resident_key: false,
            user_verification: webauthn_rs_proto::UserVerificationPolicy::Preferred,
        });

    match selection.resident_key {
        Some(ResidentKeyRequirement::Discouraged) => Err(crate::Error::Unsupported(
            "Android Credential Manager only creates discoverable credentials; \
             residentKey \"discouraged\" is not supported"
                .into(),
        )),
        Some(_) => Ok(()),
        None => {
            selection.resident_key = Some(ResidentKeyRequirement::Preferred);
            selection.require_resident_key = false;
            Ok(())
        }
    }
}
```

If `AuthenticatorSelectionCriteria` has fields beyond those four in `webauthn-rs-proto ~0.5`, construct it with `..Default::default()` if it implements `Default`, or copy the existing field list from the compiler error — do not guess.

In `mobile.rs`'s `register`, before serializing the options:

```rust
        #[cfg(target_os = "android")]
        let options = {
            let mut options = options;
            crate::normalize::apply_android_resident_key(&mut options)?;
            options
        };
```

- [ ] **Step 4: Run the tests**

Run: `tauri-plugin-passkey/scripts/test-macos.sh normalize::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tauri-plugin-passkey/src/normalize.rs tauri-plugin-passkey/src/authenticators/mobile.rs
git commit -m "fix(android): stop overriding an explicit residentKey request"
```

---

### Task 6: Delete the Kotlin translation layer

**Files:**

- Modify: `tauri-plugin-passkey/android/src/main/java/WebauthnPlugin.kt:118-149`
- Test: `tauri-plugin-passkey/android/src/test/java/` (the existing translation tests — find them with `grep -rl translateRegistrationRequest android/src/test`)

**Interfaces:**

- Consumes: Rust now sends `extensions.prf` (Task 2).
- Produces: `translateRegistrationRequest` / `translateAuthenticationRequest` no longer exist; `flattenPrfOutput` is unchanged.

- [ ] **Step 1: Materialize the Tauri Android runtime (if not already present)**

```bash
tauri-plugin-passkey/scripts/materialize-tauri-android.sh
```

- [ ] **Step 2: Delete the translation tests and functions**

Remove `translateRegistrationRequest` and `translateAuthenticationRequest` from the `internal companion object` (keep `flattenPrfOutput` and its comment). Update the two call sites:

```kotlin
            CreatePublicKeyCredentialRequest(
                requestJson = args,
            )
```

```kotlin
            GetPublicKeyCredentialOption(
                requestJson = args,
            )
```

Delete the corresponding unit tests in the Android test sources.

- [ ] **Step 3: Add a test pinning the new expectation**

In the same Kotlin test file, add a test asserting `flattenPrfOutput` lifts Credential Manager's nested results — this is now the only PRF translation on Android:

```kotlin
    @Test
    fun `flattenPrfOutput lifts prf results to the top level`() {
        val response =
            WebauthnPlugin.flattenPrfOutput(
                """{"id":"cred","clientExtensionResults":{"prf":{"results":{"first":"c2VjcmV0"}}}}""",
            )
        val prf = response.getJSONObject("prf")
        assertEquals("c2VjcmV0", prf.getString("first"))
    }
```

- [ ] **Step 4: Run the Android tests**

Run: `pnpm test:android`
Expected: PASS, with no references to `translateRegistrationRequest` remaining (`grep -rn translateRegistrationRequest android/` returns nothing).

- [ ] **Step 5: Lint and commit**

```bash
pnpm exec ktlint --format tauri-plugin-passkey/android/src/**/*.kt
git add tauri-plugin-passkey/android
git commit -m "refactor(android): drop hmac-secret translation now that rust sends prf"
```

---

### Task 7: iOS decodes `extensions.prf`

**Files:**

- Modify: `tauri-plugin-passkey/ios/Sources/WebauthnPlugin/WebauthnPlugin.swift:29-55,88,131-132`
- Test: `tauri-plugin-passkey/ios/Tests/` (find the decoding tests with `grep -rl hmacGetSecret ios/Tests`)

**Interfaces:**

- Consumes: Rust now sends `extensions.prf` (Task 2).
- Produces: `RegistrationOptions.Extensions { prf: PrfInput? }`, `AuthenticationOptions.Extensions { prf: PrfInput? }` where `PrfInput` has an optional `eval: Eval?` with `first: String` / `second: String?`.

- [ ] **Step 1: Write the failing test**

In the iOS test target, replace any test that decodes `hmacGetSecret` with:

```swift
func testDecodesBrowserPrfSalts() throws {
    let json = """
    {"rpId":"example.com","challenge":"Y2g","extensions":{"prf":{"eval":{"first":"c2FsdDE","second":"c2FsdDI"}}}}
    """
    let options = try JSONDecoder().decode(AuthenticationOptions.self, from: Data(json.utf8))
    XCTAssertEqual(options.extensions?.prf?.eval?.first, "c2FsdDE")
    XCTAssertEqual(options.extensions?.prf?.eval?.second, "c2FsdDI")
}

func testDecodesRegistrationPrfRequest() throws {
    let json = """
    {"rp":{"id":"example.com"},"user":{"id":"dQ","name":"alice"},"challenge":"Y2g","extensions":{"prf":{}}}
    """
    let options = try JSONDecoder().decode(RegistrationOptions.self, from: Data(json.utf8))
    XCTAssertNotNil(options.extensions?.prf)
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
tauri-plugin-passkey/scripts/materialize-tauri-ios.sh
pnpm test:swift:ios
```

Expected: FAIL — no `prf` member.

- [ ] **Step 3: Implement**

Replace the two extension structs in `WebauthnPlugin.swift`:

```swift
    /// The Rust side sends the browser `prf` extension verbatim.
    struct Extensions: Decodable {
        let prf: PrfInput?
    }

    struct PrfInput: Decodable {
        let eval: Eval?

        struct Eval: Decodable {
            let first: String // base64url-encoded salt
            let second: String? // optional second salt
        }
    }
```

Declare `let extensions: Extensions?` on both `RegistrationOptions` and `AuthenticationOptions` (define `PrfInput` once at file scope so both share it), then update the two use sites:

```swift
        let prfEnabled = options.extensions?.prf != nil
```

```swift
        // ASAuthorization applies the WebAuthn PRF derivation to these salts itself.
        let prfSalt1 = options.extensions?.prf?.eval.flatMap { base64URLDecode($0.first) }
        let prfSalt2 = options.extensions?.prf?.eval?.second.flatMap { base64URLDecode($0) }
```

- [ ] **Step 4: Run the tests**

Run: `pnpm test:swift`
Expected: PASS (both the macOS bridge tests and the iOS plugin tests).

- [ ] **Step 5: Lint and commit**

```bash
swiftformat tauri-plugin-passkey/ios tauri-plugin-passkey/macos && swiftlint --strict
git add tauri-plugin-passkey/ios
git commit -m "refactor(ios): decode the browser prf extension"
```

---

### Task 8: Update the test app to the browser contract

`test-app` is a real consumer: its Rust side mints the options that the Svelte page hands to the plugin, and it currently emits the `hmacCreateSecret`/`hmacGetSecret` spelling. It must speak `prf` now.

**Files:**

- Modify: `test-app/src-tauri/src/lib.rs` (`reg_start` ~line 145, `auth_start` ~line 210, `auth_start_non_discoverable` ~line 260, `auth_finish` ~line 370, `auth_finish_non_discoverable` ~line 425)

**Interfaces:**

- Consumes: the plugin's browser-JSON contract from Tasks 1-2.
- Produces: `reg_start` / `auth_start` / `auth_start_non_discoverable` return `serde_json::Value`; `auth_finish` / `auth_finish_non_discoverable` take `response: serde_json::Value`.

- [ ] **Step 1: Emit `prf` from the option-minting commands**

`reg_start`: change the return type to `Result<serde_json::Value, String>` and replace the `if enable_prf { public_key.extensions = ... }` block with:

```rust
    let mut options = serde_json::to_value(&public_key).log_err("Failed to serialize options")?;
    if enable_prf {
        options["extensions"] = serde_json::json!({ "prf": {} });
    }
    Ok(options)
```

`auth_start` and `auth_start_non_discoverable`: change the return type to `Result<serde_json::Value, String>` and replace each `if let Some(s1) = salt1 { ... }` block (including the 32-byte `decode_salt` check — browser PRF salts may be any length now) with:

```rust
    let mut options = serde_json::to_value(&public_key).log_err("Failed to serialize options")?;
    if let Some(first) = salt1 {
        let mut eval = serde_json::json!({ "first": first });
        if let Some(second) = salt2 {
            eval["second"] = serde_json::json!(second);
        }
        options["extensions"] = serde_json::json!({ "prf": { "eval": eval } });
    }
    Ok(options)
```

Remove the now-unused `Base64UrlSafeData` / `URL_SAFE_NO_PAD` imports if nothing else uses them.

- [ ] **Step 2: Read `prf` results in the finishing commands**

`auth_finish` and `auth_finish_non_discoverable`: take `response: serde_json::Value`, pull the PRF results out of the browser shape, then convert to the proto type for verification (`PublicKeyCredential` accepts `clientExtensionResults` via a serde alias):

```rust
    let prf_results = response
        .get("clientExtensionResults")
        .and_then(|e| e.get("prf"))
        .and_then(|prf| prf.get("results"))
        .map(|results| PrfResults {
            first: results
                .get("first")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            second: results
                .get("second")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });

    let response: PublicKeyCredential =
        serde_json::from_value(response).log_err("Invalid authentication response")?;
```

Keep the rest of each function (the `finish_passkey_authentication` call) unchanged, and return `prf_results` as before.

- [ ] **Step 3: Build and lint**

```bash
cd test-app/src-tauri && cargo clippy --all-targets -- -D warnings && cargo fmt --check
cd ../.. && pnpm build
```

Expected: clean.

- [ ] **Step 4: Exercise it against a real authenticator**

Run the app on whichever platform is available and register + authenticate with a PRF salt filled in:

```bash
cd test-app && ./build-macos-dev.sh && open src-tauri/target/debug/bundle/macos/test-app.app
```

Expected: registration logs success, authentication logs `PRF Results: {...}` with a non-empty `first`.

If no authenticator is available, say so rather than claiming the manual check passed.

- [ ] **Step 5: Commit**

```bash
git add test-app
git commit -m "refactor(test-app): use the browser prf extension"
```

---

### Task 9: Documentation and final verification

**Files:**

- Modify: `tauri-plugin-passkey/guest-js/index.ts` (the `PasskeyErrorKind` doc block ~line 70), `README.md`, `tauri-plugin-passkey/macos/README.md`

- [ ] **Step 1: Document the `unsupported` error kind**

In `guest-js/index.ts`, add `| "unsupported"` to the `PasskeyErrorKind` union (before the `(string & {})` catch-all) with a comment naming the three cases that raise it: PRF on Windows, `prf.eval` at registration, and `residentKey: "discouraged"` on Android.

- [ ] **Step 2: Document the PRF contract**

In `README.md`, add a short "PRF" section stating:

- `extensions.prf` is the only accepted spelling; results come back in `clientExtensionResults.prf`.
- Salts may be any length and are used exactly as a browser would use them, on every platform.
- `prf.eval` at registration is rejected; register with `prf: {}` and evaluate during authentication.
- Windows returns `prf.enabled: false` and errors if an assertion requests salts.

In `tauri-plugin-passkey/macos/README.md`, correct the browser-PRF paragraph added in `d1adb0a` so it describes the new contract rather than the `hmacGetSecret` translation.

- [ ] **Step 3: Full verification**

```bash
pnpm format
pnpm lint
pnpm build
pnpm test
tauri-plugin-passkey/scripts/test-macos.sh
```

Expected: all green. Record any suite that cannot run in this environment (Linux CTAP2, Windows) rather than reporting it as passing.

- [ ] **Step 4: Confirm the old spelling is gone**

```bash
grep -rn "hmacGetSecret\|hmacCreateSecret\|hmac_get_secret\|hmac_create_secret" \
  tauri-plugin-passkey/src tauri-plugin-passkey/ios tauri-plugin-passkey/android \
  tauri-plugin-passkey/guest-js test-app/src test-app/src-tauri/src
```

Expected: matches only inside `ctap2/platform.rs` (where the CTAP2 wire format legitimately uses those names) and in `webauthn-rs-proto` field references that are set to `None`/`Default`.

- [ ] **Step 5: Commit**

```bash
git add README.md tauri-plugin-passkey/macos/README.md tauri-plugin-passkey/guest-js/index.ts
git commit -m "docs: document the browser prf contract and the unsupported error kind"
```

---

## Notes on testing choices

The spec called for JS contract tests asserting the single `prf` spelling. `guest-js/index.ts` passes options through to `invoke` untouched, so a vitest assertion there would only test the mock. The wire format is pinned in Rust instead — `src/prf.rs` for the translation and `src/wire_contract.rs` for proto deserialization — which is where a regression would actually appear. No vitest changes are planned.
