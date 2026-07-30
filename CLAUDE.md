# Tauri Plugin WebAuthn

A Tauri plugin providing WebAuthn/FIDO2/passkey authentication for Linux, Windows,
macOS, iOS, and Android.

This is a **pnpm workspace monorepo**: the plugin lives in `tauri-plugin-webauthn/` and
an example app in `test-app/`.

## Naming: repo vs. runtime identity

The repository, the directory, and the iOS Swift package are all named `webauthn`
(`tauri-plugin-webauthn`, `net.kackman.webauthn`, `WebauthnPlugin`, etc.) — that naming
is historical and stays as-is. The published crate/npm identity and the runtime plugin
name were renamed to `passkey`:

- Crate: `tauri-plugin-passkey` (`Cargo.toml` in `tauri-plugin-webauthn/`)
- npm package: `tauri-plugin-passkey-api`
- Tauri plugin name used by `Builder::new("passkey")` in `src/lib.rs`, invoked from JS
  as `plugin:passkey|<command>`, permissions identifiers `passkey:*`
- Android plugin class registration still uses `net.kackman.webauthn` / `WebauthnPlugin`

Don't be surprised when file/directory names say `webauthn` but Cargo.toml, package.json,
and permission strings say `passkey` — that split is intentional.

## Architecture

- `src/authenticators/mod.rs` — the `Authenticator<R>` trait (`register`, `authenticate`,
  `send_pin`, `select_key`, `cancel`), implemented per-backend and cfg-selected:
  - `ctap2/` — Linux, direct CTAP2 authenticator client
  - `macos.rs` — macOS, FFI into the Swift bridge (`macos/Sources/WebauthnBridge/`)
  - `mobile.rs` — iOS + Android, via the Tauri mobile plugin bridge
  - `windows.rs` — Windows
- `src/lib.rs` — picks the backend via `cfg`, registers the five commands
  (`register`, `authenticate`, `send_pin`, `select_key`, `cancel`) with
  `Builder::new("passkey")`
- `src/commands.rs` — the `#[command]` handlers invoked from JS
- `build.rs` — `COMMANDS` array (must match `invoke_handler` and `commands.rs`) and the
  Swift linker setup for macOS
- Native code:
  - `macos/Sources/WebauthnBridge/` — Swift FFI bridge (Exports.swift, PasskeyHandler.swift)
  - `ios/Sources/WebauthnPlugin/` — Tauri mobile plugin (WebauthnPlugin.swift,
    PasskeyHandler.swift)
  - `android/src/main/java/WebauthnPlugin.kt` — Android Credential Manager integration
- `guest-js/index.ts` — the JS/TS API surface

## Development Workflow

### Prerequisites

Beyond Rust/Node/pnpm/Tauri CLI:

- iOS/macOS: Xcode, swiftformat, swiftlint
- Android: Android Studio, Android SDK, ktlint (via `pnpm exec ktlint`, pinned version —
  don't install a separate one from Homebrew/`~/.ktlint`, it can disagree with CI)
- macOS: a provisioning profile with Associated Domains entitlements and
  `com.apple.security.get-task-allow`; ASAuthorizationController requires a real `.app`
  bundle, not a bare signed binary — see `test-app/build-macos-dev.sh`

### `.tauri/tauri-api` materialization

`android/.tauri/tauri-api` and the iOS equivalent are gitignored copies of the Tauri
mobile runtime that the Tauri CLI normally drops in place while building an app for
mobile. Nothing in this repo creates them on a fresh checkout, so Gradle/Xcode builds
and tests fail until you run:

```bash
tauri-plugin-webauthn/scripts/materialize-tauri-android.sh
tauri-plugin-webauthn/scripts/materialize-tauri-ios.sh
```

Required before any Android Gradle task or iOS Xcode build/test.

### Building and testing

```bash
pnpm install
pnpm build        # pnpm -r build, dependency order (dist-js before test-app)
pnpm test         # pnpm -r test
pnpm test:rust    # cargo test (macOS: use scripts/test-macos.sh for the right toolchain)
pnpm test:swift   # materializes iOS deps, then xcodebuild test
pnpm test:android # ./gradlew test (needs materialize-tauri-android.sh first)
```

### Running the test app

```bash
cd test-app
pnpm tauri ios dev
pnpm tauri android dev
pnpm tauri dev              # Windows/Linux

# macOS (needs a signed .app bundle, not the raw binary)
./build-macos-dev.sh
open src-tauri/target/debug/bundle/macos/test-app.app
```

### Before committing

```bash
pnpm format   # Format all code
pnpm lint     # Rust, Swift, Kotlin, JS lints
pnpm build    # Everything builds
```

## Release flow

1. `./bump-version.sh X.Y.Z[-suffix]` — bumps `Cargo.toml` + `package.json` in lockstep
   and regenerates `CHANGELOG.md` from conventional commits (requires `git-cliff` for
   the changelog step)
2. Review the diff, commit
3. `./tag-release.sh vX.Y.Z[-suffix]` — validates the tag matches the bumped versions,
   tags, and pushes, which triggers `.github/workflows/publish.yml` (crates.io + npm)

## Debugging

Android logs: `./adb-logs.sh`.
