# Security/Correctness Review Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the security, correctness, and quality findings from the July 2026 repo review of tauri-plugin-webauthn, in priority order.

**Architecture:** This is a Tauri v2 plugin with one Rust backend per platform selected by `cfg` in `src/lib.rs`: `src/authenticators/ctap2/` (Linux, talks CTAP2 to USB keys via the `authenticator` crate), `src/authenticators/macos.rs` (calls Swift in `macos/Sources/WebauthnBridge/` over a C FFI), `src/authenticators/mobile.rs` (delegates to `ios/Sources/WebauthnPlugin/` and `android/src/main/java/WebauthnPlugin.kt`), and `src/authenticators/windows.rs`. The webview calls commands defined in `src/commands.rs`; the JS API is `guest-js/index.ts`. Fixes are ordered: security first, then user-visible bugs, then protocol correctness, then docs/CI.

**Tech Stack:** Rust (edition 2021, 2-space indent per `rustfmt.toml`), Swift 6 (AuthenticationServices), Kotlin (androidx.credentials), TypeScript. Crates already in the dependency tree that these tasks use: `webauthn-rs-proto` 0.5.4, `authenticator` 0.5.0 (Linux only), `base64` 0.22, `base64urlsafedata` 0.5, `serde_json`, `tauri` 2.x.

## Global Constraints

- **Dev machine is macOS.** The `ctap2` module (Linux-only) does NOT compile locally. Tasks touching `src/authenticators/ctap2/` are verified by: (a) careful adherence to the type signatures quoted in the task (they were verified against the vendored crate sources), and (b) the Linux CI job added in Task 5. Do not claim ctap2 code "passes tests" locally — say "compiles on Linux CI".
- **Canonical local test command (macOS).** Plain `swift` on this machine is an old swiftly-managed 5.9.2 that cannot build the Swift packages; Xcode's Swift 6.3 must win. Always build/test the Rust crate with:
  ```bash
  PATH="$(dirname "$(xcrun --find swift)"):$PATH" RUSTFLAGS="-C linker=/usr/bin/cc" cargo test
  ```
  (The `RUSTFLAGS` linker override avoids a nix/devenv `cc` that cannot find macOS system libraries.) This exact command was verified to pass on this machine. Task 1 wraps it in `scripts/test-macos.sh`; later tasks invoke that script.
- **Swift package build check:** `cd macos && xcrun swift build` (verified working). The iOS package generally cannot be built standalone on the CLI; verify iOS Swift changes by keeping them structurally identical to the macOS twin and via review.
- Rust style: 2-space indent, `crate::Result` / `crate::Error` for fallible APIs, `#[cfg(feature = "log")]` around every `log::` call. Never log challenge bytes, PRF salts/outputs, or PINs.
- Commit after every task with a conventional-commit message. Do not push, do not touch `examples/webauthn/src-tauri/gen/`, `node_modules/`, `target/`, or `dist-js/` (dist-js is build output of `guest-js`).
- All wire field names between Rust and JS are camelCase unless a task says otherwise (`attempts_remaining` and `max_length` in existing PIN events are intentionally snake_case — do not "fix" them).

---

### Task 1: rp_id ↔ origin validation (security — highest priority)

**Why:** On Linux the plugin itself acts as the WebAuthn client, and today it accepts any `origin` + `rp.id` pair from the webview. XSS in the webview can mint assertions for arbitrary sites (e.g. `origin: "https://github.com"`). Browsers enforce that the rpId is a "registrable suffix" of the origin host; we add that check for all platforms in the shared command layer.

**Files:**

- Create: `scripts/test-macos.sh`
- Create: `src/validation.rs`
- Modify: `src/lib.rs` (add `mod validation;`)
- Modify: `src/error.rs` (add `Validation` variant)
- Modify: `src/commands.rs` (call the validator in `register` and `authenticate`)

**Interfaces:**

- Produces: `pub fn validate_rp_id(origin: &tauri::Url, rp_id: &str) -> crate::Result<()>` in `src/validation.rs` — later tasks do not depend on it, but Task 2 adds a second function to the same file.
- Produces: `crate::Error::Validation(String)` — display format `"Validation error: {0}"`.

- [ ] **Step 1: Create the test script**

```bash
#!/bin/sh
# Runs the Rust test suite on macOS. Plain `swift` here is an old swiftly
# toolchain that cannot build the WebauthnBridge package, and the devenv `cc`
# cannot see macOS system libraries — override both.
set -e
cd "$(dirname "$0")/.."
PATH="$(dirname "$(xcrun --find swift)"):$PATH" \
RUSTFLAGS="-C linker=/usr/bin/cc" \
exec cargo test "$@"
```

Save as `scripts/test-macos.sh`, then `chmod +x scripts/test-macos.sh`. Run `./scripts/test-macos.sh` once now — expected: compiles, `0 passed; 0 failed`.

- [ ] **Step 2: Add the error variant**

In `src/error.rs`, inside `pub enum Error`, after the `NoToken` variant add:

```rust
  #[error("Validation error: {0}")]
  Validation(String),
```

- [ ] **Step 3: Write the failing tests**

Create `src/validation.rs`:

```rust
use tauri::Url;

/// Enforce the WebAuthn client rule that the relying party id must be the
/// origin's effective domain or a registrable suffix of it, and that the
/// origin is a secure context. Without this check, any code running in the
/// webview could request credentials for an arbitrary third-party site.
///
/// Limitation: we do not consult the Public Suffix List, so an app whose
/// webview is compromised could still use an rp_id like "com". Browsers
/// reject that; we accept it. Documented trade-off to avoid a PSL dependency.
pub fn validate_rp_id(origin: &Url, rp_id: &str) -> crate::Result<()> {
  let host = origin
    .host_str()
    .ok_or_else(|| validation_error("origin must have a host"))?;

  let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
  match origin.scheme() {
    "https" => {}
    "http" if is_loopback => {}
    scheme => {
      return Err(validation_error(&format!(
        "origin scheme must be https (or http on loopback), got {scheme}"
      )))
    }
  }

  if rp_id.is_empty() {
    return Err(validation_error("rpId must not be empty"));
  }

  let matches_rp = match origin.domain() {
    Some(domain) => domain == rp_id || domain.ends_with(&format!(".{rp_id}")),
    // IP-address origins get no suffix matching: "1.2.3.4" must not
    // satisfy rp_id "3.4".
    None => host == rp_id,
  };
  if matches_rp {
    Ok(())
  } else {
    Err(validation_error(&format!(
      "rpId {rp_id:?} is not a registrable suffix of origin host {host:?}"
    )))
  }
}

fn validation_error(msg: &str) -> crate::Error {
  crate::Error::Validation(msg.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
  }

  #[test]
  fn accepts_exact_host_match() {
    assert!(validate_rp_id(&url("https://example.com"), "example.com").is_ok());
  }

  #[test]
  fn accepts_registrable_suffix() {
    assert!(validate_rp_id(&url("https://app.login.example.com"), "example.com").is_ok());
  }

  #[test]
  fn rejects_unrelated_domain() {
    assert!(validate_rp_id(&url("https://example.com"), "github.com").is_err());
  }

  #[test]
  fn rejects_partial_label_suffix() {
    // "evil-example.com" ends with the *string* "example.com" but not on a
    // dot boundary — must be rejected.
    assert!(validate_rp_id(&url("https://evil-example.com"), "example.com").is_err());
  }

  #[test]
  fn rejects_plain_http() {
    assert!(validate_rp_id(&url("http://example.com"), "example.com").is_err());
  }

  #[test]
  fn accepts_http_localhost() {
    assert!(validate_rp_id(&url("http://localhost:1420"), "localhost").is_ok());
  }

  #[test]
  fn rejects_ip_suffix_trick() {
    assert!(validate_rp_id(&url("https://1.2.3.4"), "3.4").is_err());
  }

  #[test]
  fn accepts_exact_ip_match() {
    assert!(validate_rp_id(&url("https://127.0.0.1"), "127.0.0.1").is_ok());
  }

  #[test]
  fn rejects_empty_rp_id() {
    assert!(validate_rp_id(&url("https://example.com"), "").is_err());
  }
}
```

In `src/lib.rs` add `mod validation;` next to the existing `mod` lines.

- [ ] **Step 4: Run tests, expect pass**

Run: `./scripts/test-macos.sh validation`
Expected: all 9 tests pass. (The implementation and tests land together here because the function is self-contained; if any test fails, fix the implementation, not the test — the test cases encode the WebAuthn client rules.)

- [ ] **Step 5: Wire into the command layer**

In `src/commands.rs`, in `register`, before the `block_in_place` call insert:

```rust
  crate::validation::validate_rp_id(&origin, &options.rp.id)?;
```

In `authenticate`, before its `block_in_place` call insert:

```rust
  crate::validation::validate_rp_id(&origin, &options.rp_id)?;
```

(`options.rp.id` and `options.rp_id` are both `String` in webauthn-rs-proto 0.5.4.)

- [ ] **Step 6: Full test run and commit**

Run: `./scripts/test-macos.sh`
Expected: PASS.

```bash
git add scripts/test-macos.sh src/validation.rs src/lib.rs src/error.rs src/commands.rs
git commit -m "fix(security): validate rpId is a registrable suffix of the origin"
```

---

### Task 2: clientDataJSON origin serialization (interop bug)

**Why:** On Linux the plugin builds `clientDataJSON` with `origin` typed as `Url`, which serializes `https://example.com` as `https://example.com/` (trailing slash). Server libraries that string-compare `expectedOrigin` (e.g. @simplewebauthn/server) reject every response. The fix builds the JSON with the origin's ASCII serialization (`https://example.com`, no slash) — the same form browsers emit.

**Files:**

- Modify: `src/validation.rs` (add `build_client_data` + tests — this file compiles on every platform, so the tests run on macOS)
- Modify: `src/authenticators/ctap2/platform.rs` (use it; Linux-compile-only, verified via CI in Task 5)

**Interfaces:**

- Consumes: nothing from other tasks.
- Produces: `pub fn build_client_data(type_: &str, challenge: &base64urlsafedata::Base64UrlSafeData, origin: &tauri::Url) -> crate::Result<Vec<u8>>` — returns the serialized clientDataJSON bytes.

- [ ] **Step 1: Write the failing tests**

Append to `src/validation.rs` (above the `tests` module):

```rust
/// Build the clientDataJSON bytes the way a browser would: `origin` is the
/// ASCII serialization of the URL's origin (scheme://host[:port], no path,
/// no trailing slash). Serializing a `Url` directly appends "/" and breaks
/// servers that string-compare expectedOrigin.
pub fn build_client_data(
  type_: &str,
  challenge: &base64urlsafedata::Base64UrlSafeData,
  origin: &Url,
) -> crate::Result<Vec<u8>> {
  serde_json::to_vec(&serde_json::json!({
    "type": type_,
    "challenge": challenge,
    "origin": origin.origin().ascii_serialization(),
    "crossOrigin": false,
  }))
  .map_err(Into::into)
}
```

Append to the `tests` module in the same file:

```rust
  #[test]
  fn client_data_origin_has_no_trailing_slash() {
    let challenge = base64urlsafedata::Base64UrlSafeData::from(vec![1u8, 2, 3]);
    let bytes =
      build_client_data("webauthn.create", &challenge, &url("https://example.com")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["origin"], "https://example.com");
    assert_eq!(v["type"], "webauthn.create");
    assert_eq!(v["challenge"], "AQID"); // base64url of [1,2,3], no padding
    assert_eq!(v["crossOrigin"], false);
  }

  #[test]
  fn client_data_origin_keeps_port() {
    let challenge = base64urlsafedata::Base64UrlSafeData::from(vec![9u8]);
    let bytes =
      build_client_data("webauthn.get", &challenge, &url("http://localhost:1420")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["origin"], "http://localhost:1420");
  }
```

- [ ] **Step 2: Run tests**

Run: `./scripts/test-macos.sh validation`
Expected: PASS (2 new tests green, 9 old tests still green). If `challenge` does not serialize to `"AQID"`, stop and inspect — `Base64UrlSafeData`'s serde impl is base64url-unpadded and this expectation was pre-verified.

- [ ] **Step 3: Use it in the ctap2 backend**

In `src/authenticators/ctap2/platform.rs`:

1. Delete the `CollectedClientData` import from the `webauthn_rs_proto` use-list.
2. In `perform_register`, replace the whole `let client_data: Vec<u8> = serde_json::to_vec(&CollectedClientData { ... })?;` block with:

```rust
    let client_data =
      crate::validation::build_client_data("webauthn.create", &options.challenge, &url)?;
```

3. In `perform_authentication`, replace its `CollectedClientData` block with:

```rust
    let client_data =
      crate::validation::build_client_data("webauthn.get", &options.challenge, &url)?;
```

Note: the old code moved `options.challenge` into the struct; the new call borrows it, so no ownership changes ripple. The `url.clone()` that fed the old struct disappears; `url` is still used later for `RegisterArgs.origin: url.to_string()` — leave that field as-is (it only feeds the authenticator's CTAP1 fallback display, not clientDataJSON).

- [ ] **Step 4: Verify and commit**

Run: `./scripts/test-macos.sh` (macOS cannot compile the ctap2 file — that part is covered by Linux CI from Task 5; re-read your platform.rs diff once to check names against the snippets above).

```bash
git add src/validation.rs src/authenticators/ctap2/platform.rs
git commit -m "fix(ctap2): serialize clientDataJSON origin without trailing slash"
```

---

### Task 3: cancel() must dismiss the native sheet (macOS + iOS)

**Why:** `PasskeyHandler.cancel()` resumes the Rust caller but never calls `ASAuthorizationController.cancel()`, so the system passkey dialog stays on screen. Also, when the Rust side times out (`recv_timeout` in `macos.rs`), nothing cancels the Swift side at all — stale sheet plus leaked handler.

**Files:**

- Modify: `macos/Sources/WebauthnBridge/PasskeyHandler.swift` (the `cancel()` func, currently lines 96–102)
- Modify: `ios/Sources/WebauthnPlugin/PasskeyHandler.swift` (the `cancel()` func, currently lines 97–103 — identical shape)
- Modify: `src/authenticators/macos.rs` (`await_swift_result`, currently lines 203–215)

**Interfaces:**

- Consumes: existing FFI export `webauthn_cancel()` (already declared in `macos.rs` `extern "C"` block).
- Produces: nothing new — behavior fix only.

- [ ] **Step 1: Fix both Swift handlers**

In **both** `macos/Sources/WebauthnBridge/PasskeyHandler.swift` and `ios/Sources/WebauthnPlugin/PasskeyHandler.swift`, replace the body of `cancel()` with:

```swift
    func cancel() {
        // Dismiss the system sheet. This asynchronously triggers
        // didCompleteWithError(ASAuthorizationError.canceled), which is a
        // no-op because the continuations are nil-ed below first.
        activeController?.cancel()
        activeController = nil
        registrationContinuation?.resume(throwing: CancellationError())
        registrationContinuation = nil
        assertionContinuation?.resume(throwing: CancellationError())
        assertionContinuation = nil
    }
```

(In the macOS file the method is declared `public func cancel()` — keep the `public`.)

- [ ] **Step 2: Cancel the Swift side on Rust timeout**

In `src/authenticators/macos.rs`, replace the body of `await_swift_result` with:

```rust
fn await_swift_result(
  receiver: mpsc::Receiver<Result<String, String>>,
  timeout: u32,
) -> crate::Result<String> {
  receiver
    .recv_timeout(Duration::from_millis(timeout as u64))
    .map_err(|e| {
      // The user never answered the sheet — tear it down so it does not
      // linger after we have already reported failure to the webview.
      unsafe { webauthn_cancel() };
      crate::Error::Authenticator(format!("Timeout waiting for authenticator: {e}"))
    })?
    .map_err(|e| {
      #[cfg(feature = "log")]
      log::error!("Failed to complete passkey operation: {e}");
      crate::Error::Authenticator(e)
    })
}
```

Memory-safety note (do not "simplify" this): after the timeout, the boxed sender given to Swift is still owned by the pending callback. `webauthn_cancel()` makes the Swift task fail, its callback fires, `ffi_callback` reclaims the `Box` and sends into a dropped receiver — a harmless no-op. Exactly one callback per operation is the documented invariant; nothing here changes it.

- [ ] **Step 3: Build both sides**

Run: `cd macos && xcrun swift build && cd ..`
Expected: `Build complete!`
Run: `./scripts/test-macos.sh`
Expected: compiles and tests pass (this also re-links the Swift package into the Rust build).
iOS: no standalone build available — confirm by eye that the iOS `cancel()` is character-identical to the macOS one except for `public`.

- [ ] **Step 4: Commit**

```bash
git add macos/Sources/WebauthnBridge/PasskeyHandler.swift ios/Sources/WebauthnPlugin/PasskeyHandler.swift src/authenticators/macos.rs
git commit -m "fix(apple): dismiss the passkey sheet on cancel and on Rust-side timeout"
```

---

### Task 4: Android cancel command

**Why:** `mobile.rs` invokes a `cancel` command on both mobile platforms, but the Android plugin doesn't define one — the call silently errors and the CredentialManager coroutine keeps running.

**Files:**

- Modify: `android/src/main/java/WebauthnPlugin.kt`

**Interfaces:**

- Consumes: the existing Rust call `self.0.run_mobile_plugin("cancel", ())` in `mobile.rs` (already present — no Rust change needed).
- Produces: `@Command fun cancel(invoke: Invoke)` on the Android plugin.

- [ ] **Step 1: Track the in-flight job and add the command**

In `android/src/main/java/WebauthnPlugin.kt`:

1. Add imports:

```kotlin
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
```

2. Add a field next to `private val scope = ...`:

```kotlin
  private var currentJob: Job? = null
```

3. In **both** `register` and `authenticate`, change `scope.launch {` to `currentJob = scope.launch {`, and change the catch clauses to rethrow cancellation instead of reporting it as a generic failure:

```kotlin
      } catch (e: CancellationException) {
        invoke.reject("Operation cancelled")
        throw e
      } catch (e: Exception) {
        invoke.reject(e.message ?: e.javaClass.simpleName)
      }
```

(`throw e` after rejecting is required: swallowing `CancellationException` breaks structured concurrency. Also note the `?: e.javaClass.simpleName` — the old code passed a possibly-null message to `reject`. Remove the old `e.printStackTrace()` lines while you're there.)

4. Add the command after `authenticate`:

```kotlin
  @Command
  fun cancel(invoke: Invoke) {
    currentJob?.cancel()
    currentJob = null
    invoke.resolve()
  }
```

- [ ] **Step 2: Verify**

There is no standalone Gradle build for the plugin directory in this repo. Verification is: (a) re-read the diff — every `scope.launch` assigned to `currentJob`, both catch chains updated, imports added; (b) if the Android example toolchain is set up (`examples/webauthn/src-tauri/gen/android` exists), run `pnpm tauri android build` from `examples/webauthn` — treat toolchain absence as acceptable and note it in the task report.

- [ ] **Step 3: Commit**

```bash
git add android/src/main/java/WebauthnPlugin.kt
git commit -m "fix(android): implement cancel command and stop swallowing coroutine cancellation"
```

---

### Task 5: CI test workflow (enabler for all ctap2 tasks)

**Why:** There are zero tests in CI and the Linux-only ctap2 module cannot even be compiled on the macOS dev machine. This workflow gives every later ctap2 task its verification story. It deliberately uses plain `pull_request` (not `pull_request_target`) so untrusted PR code never runs with elevated tokens.

**Files:**

- Create: `.github/workflows/test.yml`

**Interfaces:** none consumed/produced in code; later tasks cite this job as their Linux verification.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/test.yml`:

```yaml
name: Tests
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  linux:
    name: cargo test (linux / ctap2 backend)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
      - uses: awalsh128/cache-apt-pkgs-action@latest
        with:
          packages: libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libudev-dev libpcsclite-dev libssl-dev
          version: 1.1
      - uses: Swatinem/rust-cache@v2
        with:
          shared-key: 'test_cache_linux'
      - run: cargo test -p tauri-plugin-webauthn

  macos:
    name: cargo test (macos / swift bridge)
    runs-on: macos-15
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
        with:
          shared-key: 'test_cache_macos'
      - run: cargo test -p tauri-plugin-webauthn
```

Notes for the implementer: `-p tauri-plugin-webauthn` is required — the workspace also contains the example app, whose build needs a frontend bundle and mobile toolchains. The apt package list is copied from the working `checks.yml` plus `libssl-dev` (the ctap2 backend links OpenSSL).

- [ ] **Step 2: Validate YAML locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/test.yml')); print('ok')"` (or `npx yaml-lint` if python/yaml is unavailable).
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: run cargo test on linux and macos for pull requests"
```

After this commit, pushing the branch and opening a PR runs the Linux job — that is the compile gate for Tasks 2, 6, 7, 8, 9.

---

### Task 6: ctap2 cancel deadlock

**Why:** On Linux, `register`/`authenticate` hold the `manager` mutex for their entire blocking wait, and `cancel()` needs the same mutex — so cancel can never fire during the only window where it matters. Fix: lock only around the non-blocking dispatch call (`AuthenticatorService::register/sign` spawn transport threads and return), then wait on the result channel without the lock.

**Files:**

- Modify: `src/authenticators/ctap2/platform.rs` (change `perform_register` / `perform_authentication` from trait methods on `AuthenticatorService` to free functions taking `&Mutex<AuthenticatorService>`)
- Modify: `src/authenticators/ctap2/mod.rs` (call sites; delete the trait import)

**Interfaces:**

- Consumes: `crate::validation::build_client_data` (Task 2).
- Produces (used by `mod.rs` in this same task):
  - `pub fn perform_register(manager: &Mutex<AuthenticatorService>, status_tx: Sender<StatusUpdate>, url: Url, options: PublicKeyCredentialCreationOptions, timeout: u64) -> crate::Result<RegisterPublicKeyCredential>`
  - `pub fn perform_authentication(manager: &Mutex<AuthenticatorService>, status_tx: Sender<StatusUpdate>, url: Url, options: PublicKeyCredentialRequestOptions, timeout: u64) -> crate::Result<PublicKeyCredential>`

- [ ] **Step 1: Convert the trait to free functions**

In `src/authenticators/ctap2/platform.rs`:

1. Delete the `pub trait AuthenticatorExt { ... }` block and the `impl AuthenticatorExt for AuthenticatorService` line (keep the two function bodies — they become free functions).
2. Add `Mutex` to the std imports: `use std::sync::{mpsc::{channel, Sender}, Mutex};`
3. Reshape each function. For register, the signature and the dispatch/wait section become:

```rust
pub fn perform_register(
  manager: &Mutex<AuthenticatorService>,
  status_tx: Sender<StatusUpdate>,
  url: Url,
  options: PublicKeyCredentialCreationOptions,
  timeout: u64,
) -> crate::Result<RegisterPublicKeyCredential> {
  // ... existing client_data / args construction, unchanged ...

  let (register_tx, register_rx) = channel();
  let callback = StateCallback::new(Box::new(move |rv| {
    let _ = register_tx.send(rv);
  }));

  // Hold the manager lock only for this dispatch: `register` hands the work
  // to transport threads and returns. The blocking wait below must run
  // WITHOUT the lock so that `cancel()` can acquire it mid-operation.
  manager
    .lock()
    .unwrap()
    .register(timeout, args, status_tx, callback)?;

  let result = register_rx
    .recv()
    .map_err(|_| crate::Error::Authenticator("Registration ended without a result".to_string()))??;

  // ... existing result conversion, unchanged ...
}
```

Apply the same reshape to `perform_authentication` (`manager.lock().unwrap().sign(timeout, args, status_tx, callback)?;` followed by the lock-free `sign_rx.recv()`).

4. All references to `self.register(...)` / `self.sign(...)` are gone after this; the compiler will catch stragglers.

- [ ] **Step 2: Update the call sites**

In `src/authenticators/ctap2/mod.rs`:

1. Remove `use platform::AuthenticatorExt;`.
2. In `Authenticator::register`, replace the two-line lock-then-call with:

```rust
    platform::perform_register(&self.manager, self.status_tx.clone(), origin, options, timeout as u64)
      .map_err(|e| {
        #[cfg(feature = "log")]
        log::error!("Failed to register: {e:?}");
        e
      })
```

3. Same shape in `Authenticator::authenticate` with `platform::perform_authentication(...)`.
4. `cancel()` stays exactly as it is (`self.manager.lock().unwrap().cancel()`) — it now actually acquires the lock during an operation.

Behavior note to record in the commit body: two overlapping register/authenticate calls no longer queue on the mutex; the `authenticator` crate cancels the in-flight transaction when a new one is dispatched. That is the same behavior browsers have and is acceptable.

- [ ] **Step 3: Verify**

Local: `./scripts/test-macos.sh` still passes (proves no cross-platform file broke). ctap2 compile: Linux CI (Task 5) on push. Manual desk-check: search `platform.rs` for `self.` — there must be no remaining method-style calls.

- [ ] **Step 4: Commit**

```bash
git add src/authenticators/ctap2/platform.rs src/authenticators/ctap2/mod.rs
git commit -m "fix(ctap2): release manager lock during blocking wait so cancel() works"
```

---

### Task 7: ctap2 honors allowCredentials / excludeCredentials / userVerification / residentKey

**Why:** The Linux backend hardcodes `exclude_list: Vec::new()`, `allow_list: Vec::new()`, and forces UV and resident-key to `Required`. Consequences today: duplicate registrations are possible, non-discoverable credentials can never authenticate, and server policies are ignored.

**Files:**

- Modify: `src/authenticators/ctap2/platform.rs`

**Interfaces:**

- Consumes: `perform_register`/`perform_authentication` shapes from Task 6.
- Produces: private conversion helpers used only inside this file (exact signatures below).

Verified type facts (from vendored `authenticator-0.5.0` and `webauthn-rs-proto-0.5.4` sources — trust these over guesses):

- `authenticator::ctap2::server::PublicKeyCredentialDescriptor { id: Vec<u8>, transports: Vec<Transport> }`; `Transport` variants: `USB, NFC, BLE, Internal`.
- `authenticator` `UserVerificationRequirement` and `ResidentKeyRequirement` both have `Discouraged, Preferred, Required`.
- proto `PublicKeyCredentialDescriptor`/`AllowCredentials` both have `id: Base64UrlSafeData`, `transports: Option<Vec<AuthenticatorTransport>>`.
- proto `UserVerificationPolicy` variants: `Required, Preferred, Discouraged_DO_NOT_USE`.
- proto `AuthenticatorSelectionCriteria { authenticator_attachment, resident_key: Option<ResidentKeyRequirement>, require_resident_key: bool, user_verification: UserVerificationPolicy }`.
- proto creation options: `exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>`, `authenticator_selection: Option<AuthenticatorSelectionCriteria>`; request options: `allow_credentials: Vec<AllowCredentials>`, `user_verification: UserVerificationPolicy`.

- [ ] **Step 1: Add the conversion helpers**

Add near the other `convert_*` functions in `platform.rs`:

```rust
fn convert_transports(transports: Vec<webauthn_rs_proto::AuthenticatorTransport>) -> Vec<Transport> {
  transports
    .into_iter()
    .filter_map(|t| match t {
      webauthn_rs_proto::AuthenticatorTransport::Usb => Some(Transport::USB),
      webauthn_rs_proto::AuthenticatorTransport::Nfc => Some(Transport::NFC),
      webauthn_rs_proto::AuthenticatorTransport::Ble => Some(Transport::BLE),
      webauthn_rs_proto::AuthenticatorTransport::Internal => Some(Transport::Internal),
      _ => None, // Hybrid etc. have no CTAP2-crate equivalent
    })
    .collect()
}

fn convert_exclude_list(
  list: Option<Vec<webauthn_rs_proto::PublicKeyCredentialDescriptor>>,
) -> Vec<PublicKeyCredentialDescriptor> {
  list
    .unwrap_or_default()
    .into_iter()
    .map(|d| PublicKeyCredentialDescriptor {
      id: d.id.into(),
      transports: d.transports.map(convert_transports).unwrap_or_default(),
    })
    .collect()
}

fn convert_allow_list(
  list: Vec<webauthn_rs_proto::AllowCredentials>,
) -> Vec<PublicKeyCredentialDescriptor> {
  list
    .into_iter()
    .map(|c| PublicKeyCredentialDescriptor {
      id: c.id.into(),
      transports: c.transports.map(convert_transports).unwrap_or_default(),
    })
    .collect()
}

fn convert_user_verification(
  policy: webauthn_rs_proto::UserVerificationPolicy,
) -> UserVerificationRequirement {
  match policy {
    webauthn_rs_proto::UserVerificationPolicy::Required => UserVerificationRequirement::Required,
    webauthn_rs_proto::UserVerificationPolicy::Preferred => UserVerificationRequirement::Preferred,
    webauthn_rs_proto::UserVerificationPolicy::Discouraged_DO_NOT_USE => {
      UserVerificationRequirement::Discouraged
    }
  }
}

fn convert_resident_key(
  selection: Option<&webauthn_rs_proto::AuthenticatorSelectionCriteria>,
) -> ResidentKeyRequirement {
  match selection.and_then(|s| s.resident_key) {
    Some(webauthn_rs_proto::ResidentKeyRequirement::Required) => ResidentKeyRequirement::Required,
    Some(webauthn_rs_proto::ResidentKeyRequirement::Preferred) => ResidentKeyRequirement::Preferred,
    Some(webauthn_rs_proto::ResidentKeyRequirement::Discouraged) => {
      ResidentKeyRequirement::Discouraged
    }
    // WebAuthn Level 1 compatibility: the boolean is authoritative when the
    // enum is absent.
    None if selection.map(|s| s.require_resident_key).unwrap_or(false) => {
      ResidentKeyRequirement::Required
    }
    None => ResidentKeyRequirement::Preferred,
  }
}
```

(If `resident_key` turns out not to be `Copy`, change the first match line to `selection.and_then(|s| s.resident_key.clone())` — that is the only permitted deviation.)

- [ ] **Step 2: Use them in `perform_register`**

In the `RegisterArgs` literal, replace the hardcoded fields:

```rust
      user_verification_req: options
        .authenticator_selection
        .as_ref()
        .map(|s| convert_user_verification(s.user_verification.clone()))
        .unwrap_or(UserVerificationRequirement::Preferred),
      exclude_list: convert_exclude_list(options.exclude_credentials),
      resident_key_req: convert_resident_key(options.authenticator_selection.as_ref()),
```

Field-ordering caution: `options.exclude_credentials` and `options.authenticator_selection` are both moved/borrowed here — take `exclude_credentials` by move _after_ the two `as_ref()` uses of `authenticator_selection`, or bind the converted values to locals above the struct literal (preferred):

```rust
    let user_verification_req = options
      .authenticator_selection
      .as_ref()
      .map(|s| convert_user_verification(s.user_verification.clone()))
      .unwrap_or(UserVerificationRequirement::Preferred);
    let resident_key_req = convert_resident_key(options.authenticator_selection.as_ref());
    let exclude_list = convert_exclude_list(options.exclude_credentials);
```

then use the three locals in the struct literal.

- [ ] **Step 3: Use them in `perform_authentication`**

In the `SignArgs` literal:

```rust
      user_verification_req: convert_user_verification(options.user_verification.clone()),
      allow_list: convert_allow_list(options.allow_credentials),
```

(`options.user_verification` on request options is a plain field, not inside a selection struct. If `UserVerificationPolicy` is `Copy`, drop the `.clone()` — clippy on CI will tell you.)

- [ ] **Step 4: Verify and commit**

Local: `./scripts/test-macos.sh` (cross-platform files unaffected — must still pass). Linux compile: CI. Desk-check: grep `platform.rs` for `Vec::new()` — the only remaining hardcoded lists must be none in `RegisterArgs`/`SignArgs`.

```bash
git add src/authenticators/ctap2/platform.rs
git commit -m "fix(ctap2): honor allow/exclude credential lists, userVerification, and residentKey"
```

---

### Task 8: ctap2 registration id/rawId + robust authenticatorData bytes

**Why:** Registration responses currently return `id: ""` / `raw_id: []`, which standard server libraries reject; the credential id is available inside the attestation object. Assertions slice CBOR bytes with `data[2..]`, which silently corrupts authenticatorData once it exceeds 255 bytes; the crate provides `AuthenticatorData::to_vec()` which does this correctly.

**Files:**

- Modify: `src/authenticators/ctap2/platform.rs`

**Interfaces:**

- Consumes: `perform_register`/`perform_authentication` from Task 6.

Verified type facts: `AttestationObject { auth_data: AuthenticatorData, att_stmt: ... }`; `AuthenticatorData { rp_id_hash, flags, counter, credential_data: Option<AttestedCredentialData>, extensions }`; `AttestedCredentialData { aaguid, credential_id: Vec<u8>, credential_public_key }`; `AuthenticatorData::to_vec(&self) -> Vec<u8>` exists and yields the raw (non-CBOR-wrapped) bytes.

- [ ] **Step 1: Fill in registration id/rawId**

In `perform_register`, after obtaining `result` and before the `Ok(...)` literal, add:

```rust
    let raw_id = result
      .att_obj
      .auth_data
      .credential_data
      .as_ref()
      .map(|c| c.credential_id.clone())
      .ok_or_else(|| {
        crate::Error::Authenticator("attestation object is missing credential data".to_string())
      })?;
```

Then in the returned `RegisterPublicKeyCredential` replace:

```rust
      id: String::new(),
      raw_id: Vec::new().into(),
```

with:

```rust
      id: BASE64_URL_SAFE_NO_PAD.encode(&raw_id),
      raw_id: raw_id.into(),
```

(`BASE64_URL_SAFE_NO_PAD` is already imported in this file; the `raw_id` extraction must come before `serde_cbor_2::to_vec(&result.att_obj)` only if that call moves `result` — it borrows, so order is free; keep the extraction first for readability.)

- [ ] **Step 2: Replace the CBOR slice hack**

In `perform_authentication`, replace:

```rust
    let data = serde_cbor_2::to_vec(&result.assertion.auth_data)?;
```

and the later `authenticator_data: data[2..].into(),` with:

```rust
    let auth_data = result.assertion.auth_data.to_vec();
```

and `authenticator_data: auth_data.into(),`.

- [ ] **Step 3: Verify and commit**

Local: `./scripts/test-macos.sh`. Linux compile: CI. Desk-check: `grep -n "data\[2..\]" src/authenticators/ctap2/platform.rs` returns nothing.

```bash
git add src/authenticators/ctap2/platform.rs
git commit -m "fix(ctap2): return real credential id and correctly-framed authenticatorData"
```

---

### Task 9: selectKey event payload matches its TypeScript type

**Why:** The `selectKey` event carries `authenticator`-crate `PublicKeyCredentialUserEntity` values whose `id: Vec<u8>` serializes to a JSON **number array**, while `guest-js/index.ts` declares `AuthKey.id: string`. Emit our own struct with a base64url string id instead.

**Files:**

- Modify: `src/authenticators/ctap2/event.rs`

**Interfaces:**

- Consumes: nothing new.
- Produces: event wire shape `{ type: "selectKey", keys: [{ id: "<base64url>", name?: string, displayName?: string }] }` — this now matches the existing TS `AuthKey` type, which needs no change.

- [ ] **Step 1: Add the serializable user struct**

In `src/authenticators/ctap2/event.rs`:

1. Add imports:

```rust
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
```

2. Add below the `WebauthnEvent` enum:

```rust
/// User entry offered to the frontend for key selection. `id` is the
/// credential user handle, base64url-encoded (unpadded) — the crate's own
/// type would serialize it as a JSON number array, which does not match the
/// TS `AuthKey` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectKeyUser {
  pub id: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub display_name: Option<String>,
}

impl From<PublicKeyCredentialUserEntity> for SelectKeyUser {
  fn from(user: PublicKeyCredentialUserEntity) -> Self {
    SelectKeyUser {
      id: BASE64_URL_SAFE_NO_PAD.encode(&user.id),
      name: user.name,
      display_name: user.display_name,
    }
  }
}
```

3. Change the enum variant from `SelectKey { keys: Vec<PublicKeyCredentialUserEntity> }` to:

```rust
  SelectKey {
    keys: Vec<SelectKeyUser>,
  },
```

4. In `from_status`, change the `SelectResultNotice` arm to:

```rust
      StatusUpdate::SelectResultNotice(.., users) => Some(WebauthnEvent::SelectKey {
        keys: users.into_iter().map(Into::into).collect(),
      }),
```

- [ ] **Step 2: Verify and commit**

`guest-js/index.ts` `AuthKey` already declares `{ id: string; name?: string; displayName?: string }` — confirm by reading it; no TS change. Local: `./scripts/test-macos.sh`. Linux compile: CI.

```bash
git add src/authenticators/ctap2/event.rs
git commit -m "fix(ctap2): emit selectKey user ids as base64url strings to match the TS types"
```

---

### Task 10: macOS/iOS pass excludeCredentials and displayName through

**Why:** The Apple backends drop `excludeCredentials` (duplicate registrations possible) and `user.displayName` (username shown twice in the passkey UI). Apple supports `excludedCredentials` on platform registration requests from macOS 14 / iOS 17.4, and on security-key registration requests unconditionally at our minimums.

**Files:**

- Modify: `src/authenticators/macos.rs` (FFI signature + call)
- Modify: `macos/Sources/WebauthnBridge/Exports.swift` (`webauthn_register` export)
- Modify: `macos/Sources/WebauthnBridge/PasskeyHandler.swift` (`register` params + requests)
- Modify: `ios/Sources/WebauthnPlugin/WebauthnPlugin.swift` (decode new fields)
- Modify: `ios/Sources/WebauthnPlugin/PasskeyHandler.swift` (same as macOS handler)

**Interfaces:**

- Produces (new FFI contract — Rust and Swift must change in the same commit):

```
webauthn_register(domain, challenge_ptr, challenge_len, username, display_name,
                  user_id_ptr, user_id_len, exclude_credentials_json,
                  prf_enabled, context, callback)
```

where `display_name: *const c_char` (never null; falls back to username) and `exclude_credentials_json: *const c_char` (nullable; JSON array of base64url credential-id strings — same encoding the authenticate path already uses for `allow_credentials_json`).

- [ ] **Step 1: Rust side (`src/authenticators/macos.rs`)**

1. In the `extern "C"` block, change `webauthn_register` to:

```rust
  fn webauthn_register(
    domain: *const c_char,
    challenge_ptr: *const c_uchar,
    challenge_len: usize,
    username: *const c_char,
    display_name: *const c_char,
    user_id_ptr: *const c_uchar,
    user_id_len: usize,
    exclude_credentials_json: *const c_char,
    prf_enabled: u8,
    context: u64,
    callback: WebauthnCallback,
  );
```

2. In `register`, after the existing `username` binding add:

```rust
    let display_name = to_cstring(options.user.display_name.as_str())?;

    let exclude_creds_json = {
      let ids: Vec<String> = options
        .exclude_credentials
        .iter()
        .flatten()
        .map(|c| base64_url_encode(c.id.as_slice()))
        .collect();
      if ids.is_empty() {
        None
      } else {
        Some(to_cstring(&serde_json::to_string(&ids)?)?)
      }
    };
    // SAFETY: same invariant as allow_creds_json in `authenticate` — the
    // Swift export copies this into a Swift String before returning.
    let exclude_ptr = exclude_creds_json
      .as_deref()
      .map(|c| c.as_ptr())
      .unwrap_or(std::ptr::null());
```

(`options.exclude_credentials` is `Option<Vec<PublicKeyCredentialDescriptor>>`; `.iter().flatten()` iterates the inner vec or nothing. `options.user.display_name` is `String` in webauthn-rs-proto.)

3. Update the `unsafe { webauthn_register(...) }` call to pass `display_name.as_ptr()` after `username.as_ptr()`, and `exclude_ptr` after the user-id pair, matching the new signature order exactly.

- [ ] **Step 2: macOS Swift export (`Exports.swift`)**

Change `webauthnRegister`'s signature and prologue to:

```swift
@_cdecl("webauthn_register")
public func webauthnRegister(
    domain: UnsafePointer<CChar>,
    challengePtr: UnsafePointer<UInt8>,
    challengeLen: UInt,
    username: UnsafePointer<CChar>,
    displayName: UnsafePointer<CChar>,
    userIdPtr: UnsafePointer<UInt8>,
    userIdLen: UInt,
    excludeCredentialsJson: UnsafePointer<CChar>?,
    prfEnabled: UInt8,
    context: UInt64,
    callback: WebauthnCallback
) {
    let domainStr = String(cString: domain)
    let challengeData = Data(bytes: challengePtr, count: Int(challengeLen))
    let usernameStr = String(cString: username)
    let displayNameStr = String(cString: displayName)
    let userIdData = Data(bytes: userIdPtr, count: Int(userIdLen))
    let wantPrf = prfEnabled != 0

    var excludedCredentials: [Data] = []
    if let jsonPtr = excludeCredentialsJson {
        let jsonStr = String(cString: jsonPtr)
        if let jsonData = jsonStr.data(using: .utf8),
           let arr = try? JSONSerialization.jsonObject(with: jsonData) as? [String] {
            excludedCredentials = arr.compactMap { base64URLDecode($0) }
        }
    }
```

and pass the new values through in the `Task` body:

```swift
            let auth = try await handler.register(
                domain: domainStr,
                challenge: challengeData,
                username: usernameStr,
                displayName: displayNameStr,
                userID: userIdData,
                excludeCredentials: excludedCredentials,
                prfEnabled: wantPrf
            )
```

- [ ] **Step 3: Both PasskeyHandlers**

In `macos/Sources/WebauthnBridge/PasskeyHandler.swift` (and mirrored in `ios/Sources/WebauthnPlugin/PasskeyHandler.swift`, with `macOS 14.0` → `iOS 17.4` in the availability check), change `register`'s signature to:

```swift
    public func register(
        domain: String, challenge: Data, username: String, displayName: String,
        userID: Data, excludeCredentials: [Data], prfEnabled: Bool
    ) async throws -> ASAuthorization {
```

(iOS version is `func register(...)` without `public`.) Then:

1. After creating `platformRequest`, add:

```swift
        if !excludeCredentials.isEmpty {
            if #available(macOS 14.0, *) {
                platformRequest.excludedCredentials = excludeCredentials.map {
                    ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
                }
            }
        }
```

2. Change the security-key request to use the real display name and the exclude list:

```swift
        let securityKeyRequest = securityKeyProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            displayName: displayName,
            name: username,
            userID: userID
        )
        securityKeyRequest.credentialParameters = [
            ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)
        ]
        if !excludeCredentials.isEmpty {
            securityKeyRequest.excludedCredentials = excludeCredentials.map {
                ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: $0,
                    transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                )
            }
        }
```

(The platform provider's `createCredentialRegistrationRequest` has no displayName parameter — the platform UI uses `name`; only the security-key request takes both. That asymmetry is Apple's API, not a bug.)

- [ ] **Step 4: iOS plugin decodes the new fields (`WebauthnPlugin.swift`)**

1. Extend the Decodable wrappers:

```swift
    struct User: Decodable {
        let id: String
        let name: String
        let displayName: String?
    }
```

and add to `RegistrationOptions`:

```swift
    let excludeCredentials: [CredentialDescriptor]?

    struct CredentialDescriptor: Decodable {
        let id: String
    }
```

2. In `register`, before the `Task`:

```swift
        let excluded = (options.excludeCredentials ?? []).compactMap { base64URLDecode($0.id) }
```

and update the handler call:

```swift
                let auth = try await handler.register(
                    domain: options.rp.id,
                    challenge: challengeData,
                    username: options.user.name,
                    displayName: options.user.displayName ?? options.user.name,
                    userID: userIDData,
                    excludeCredentials: excluded,
                    prfEnabled: prfEnabled
                )
```

- [ ] **Step 5: Build and commit**

Run: `cd macos && xcrun swift build && cd .. && ./scripts/test-macos.sh`
Expected: both succeed. (This is the task most likely to produce a Rust↔Swift signature mismatch; a mismatch shows up as a **linker** success but runtime garbage — so re-read both signatures side by side and confirm the parameter order matches the FFI contract above exactly.) iOS: structural review against the macOS twin.

```bash
git add src/authenticators/macos.rs macos/Sources/WebauthnBridge ios/Sources/WebauthnPlugin
git commit -m "feat(apple): pass excludeCredentials and displayName through to ASAuthorization"
```

---

### Task 11: Swift response fidelity (attestation object, userHandle)

**Why:** Two silent-corruption paths: a nil `rawAttestationObject` currently becomes an **empty** attestation object (guaranteed server rejection with a confusing error), and `userHandle` is always emitted even when empty (spec says omit when absent; some servers validate this).

**Files:**

- Modify: `macos/Sources/WebauthnBridge/Exports.swift` (`registrationJSON`, `assertionJSON`, `BridgeError`)
- Modify: `ios/Sources/WebauthnPlugin/PasskeyHandler.swift` (same two funcs + `PasskeyHandlerError`)

**Interfaces:** wire shape only — `response.userHandle` may now be absent; the Rust parsers in `macos.rs`/`mobile.rs` already treat it as optional (`as_str().and_then(...)`), so no Rust change.

- [ ] **Step 1: Fail loudly on missing attestation object**

macOS `Exports.swift`: extend the error enum:

```swift
private enum BridgeError: LocalizedError {
    case unexpectedCredentialType
    case missingAttestationObject

    var errorDescription: String? {
        switch self {
        case .unexpectedCredentialType: return "Unexpected credential type in authorization response"
        case .missingAttestationObject: return "Registration returned no attestation object"
        }
    }
}
```

In `registrationJSON`, replace the `(reg.rawAttestationObject ?? Data())` usage:

```swift
    guard let attestationObject = reg.rawAttestationObject else {
        throw BridgeError.missingAttestationObject
    }
```

then use `attestationObject.base64URLEncodedString()` in the dictionary.

iOS `PasskeyHandler.swift`: add the same `missingAttestationObject` case to `PasskeyHandlerError` (mirror the enum shape above with a `switch`) and the same guard in its `registrationJSON`.

- [ ] **Step 2: Omit empty userHandle**

In both `assertionJSON` implementations, build the response dictionary in two steps:

```swift
    var response: [String: Any] = [
        "authenticatorData": assertion.rawAuthenticatorData.base64URLEncodedString(),
        "clientDataJSON": assertion.rawClientDataJSON.base64URLEncodedString(),
        "signature": assertion.signature.base64URLEncodedString()
    ]
    if !assertion.userID.isEmpty {
        response["userHandle"] = assertion.userID.base64URLEncodedString()
    }
    var json: [String: Any] = [
        "id": assertion.credentialID.base64URLEncodedString(),
        "rawId": assertion.credentialID.base64URLEncodedString(),
        "type": "public-key",
        "response": response
    ]
```

(keep each file's existing PRF block after this, unchanged — it mutates `json`, not `response`).

- [ ] **Step 3: Build and commit**

Run: `cd macos && xcrun swift build && cd .. && ./scripts/test-macos.sh`
Expected: both succeed.

```bash
git add macos/Sources/WebauthnBridge/Exports.swift ios/Sources/WebauthnPlugin/PasskeyHandler.swift
git commit -m "fix(apple): reject missing attestation objects and omit empty userHandle"
```

---

### Task 12: Documentation and repo hygiene

**Why:** README still lists iOS as unsupported (it now works); JSDoc claims cancel "does nothing on windows and mobile" (now stale on three platforms); provisioning profiles must never be committed.

**Files:**

- Modify: `README.md`
- Modify: `guest-js/index.ts` (doc comments only)
- Modify: `.gitignore`

- [ ] **Step 1: README platform table + notes**

In `README.md` change the iOS row from `| iOS      | x         |` to `| iOS      | ✓         |`. Below the Requirements section for macOS, add an iOS section:

```markdown
### iOS

iOS support uses Apple's ASAuthorization framework. It requires iOS 15+ (PRF extension: iOS 18+), code signing with Associated Domains entitlements (`webcredentials:your.domain.com`), and an `apple-app-site-association` file hosted on the relying party domain.
```

Also add one sentence to the Usage paragraph: `On Linux, non-discoverable credentials require the server's allowCredentials list to be passed through unmodified, and the origin string must exactly match the server's expectedOrigin (no trailing slash).`

- [ ] **Step 2: Fix stale JSDoc in `guest-js/index.ts`**

- `cancel()` doc: replace "Does nothing on windows and mobile." with "Cancels the pending operation on Linux, macOS, iOS, and Android. Does nothing on Windows."
- `sendPin` doc: replace "Does nothing on windows and mobile." with "Only needed on Linux; PIN entry is handled natively elsewhere."
- `registerListener` doc: replace "No events are triggered on windows and mobile." with "Events are only emitted on Linux; other platforms show native UI instead."
- Fix the typo "sendPint" in `README.md` if present (search for it).

Then rebuild the JS bindings so `dist-js` stays in sync: `pnpm build` (check `package.json` scripts for the exact name; it is a rollup build). If the pnpm toolchain is unavailable, note it and leave `dist-js` untouched.

- [ ] **Step 3: gitignore provisioning profiles**

Append to `.gitignore`:

```
*.provisionprofile
*.mobileprovision
```

Verify `git status --short` no longer lists `examples/webauthn/embedded.provisionprofile` as untracked-visible (it should disappear from status once ignored).

- [ ] **Step 4: Commit**

```bash
git add README.md guest-js/index.ts .gitignore
git add dist-js 2>/dev/null || true
git commit -m "docs: update platform support matrix, cancel/pin semantics, and ignore provisioning profiles"
```

---

## Deferred / decision-needed (not tasks)

Record these in the PR description; they need the maintainer's call, not code:

1. **CI `pull_request_target` hardening.** `checks.yml` and `auto-merge.yml` run on `pull_request_target` with a `PERSONAL_TOKEN`. Recommended: move linting to plain `pull_request` and keep `pull_request_target` only for jobs that never check out or build PR code. Not done here because this repo is a fork and the workflows track upstream (Profiidev/tauri-plugin-webauthn) — changing them creates permanent merge friction.
2. **Public-suffix validation.** Task 1 documents that rp_id suffix matching does not consult the Public Suffix List. Adding the `publicsuffix` crate closes the gap at the cost of a dependency + bundled list. Fine to defer.
3. **ctap2 forced `pin: None`.** The Linux backend never pre-supplies a PIN (it arrives via the event round-trip). That matches the current UX design; no change planned.

## Verification matrix (which check proves which task)

| Task       | Local proof                                                      | CI proof                  |
| ---------- | ---------------------------------------------------------------- | ------------------------- |
| 1, 2       | `./scripts/test-macos.sh` (unit tests run on macOS)              | both jobs                 |
| 3, 10, 11  | `xcrun swift build` + `./scripts/test-macos.sh` link             | macOS job                 |
| 4          | diff review (no Android toolchain assumed)                       | none (manual device test) |
| 5          | YAML lint                                                        | the workflow itself       |
| 6, 7, 8, 9 | `./scripts/test-macos.sh` proves no cross-platform breakage only | Linux job compiles ctap2  |
| 12         | `git status` / reading                                           | n/a                       |
