# Tauri Plugin Passkey

A Tauri plugin providing WebAuthn/FIDO2/passkey authentication for Linux, Windows,
macOS, iOS, and Android — a near drop-in replacement for `@simplewebauthn/browser`
where the app also passes an origin URL to the register and authenticate calls.

[![npm](https://img.shields.io/npm/v/tauri-plugin-passkey-api)](https://www.npmjs.com/package/tauri-plugin-passkey-api)
[![Crates.io Downloads (latest version)](https://img.shields.io/crates/dv/tauri-plugin-passkey)](https://crates.io/crates/tauri-plugin-passkey)

> **Using the plugin in your app?** The consumer documentation — installation, API
> reference, and per-platform setup — lives in
> **[`tauri-plugin-passkey/README.md`](tauri-plugin-passkey/README.md)**, which is
> also what renders on
> [npm](https://www.npmjs.com/package/tauri-plugin-passkey-api) and
> [crates.io](https://crates.io/crates/tauri-plugin-passkey). This file covers working
> on the repository itself.

## Repository layout

A pnpm workspace monorepo:

| Path                                             | What it is                                                               |
| ------------------------------------------------ | ------------------------------------------------------------------------ |
| [`tauri-plugin-passkey/`](tauri-plugin-passkey/) | The plugin — Rust core, Swift (iOS/macOS), Kotlin (Android), TS bindings |
| [`test-app/`](test-app/)                         | A Tauri (SvelteKit) app exercising the plugin on each platform           |

Some internal identifiers (the iOS Swift module `WebauthnPlugin`, the Android
package `net.kackman.webauthn`) still use the plugin's historical `webauthn` name.
The published crate/npm package, the directory, and the runtime Tauri plugin identity
are `passkey` (crate `tauri-plugin-passkey`, npm `tauri-plugin-passkey-api`, invoked
from JS as `plugin:passkey|<command>`). See [`CLAUDE.md`](CLAUDE.md) for the full
naming rationale and architecture notes.

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable)
- [Node.js](https://nodejs.org/) and [pnpm](https://pnpm.io/)
- [Tauri system dependencies](https://v2.tauri.app/start/prerequisites/)

Per platform:

- **Linux** — no extra setup; uses a CTAP2 authenticator client directly
- **iOS / macOS** — Xcode; swiftformat and swiftlint for the lint tasks. macOS also
  needs a provisioning profile with Associated Domains entitlements — see
  [`tauri-plugin-passkey/macos/README.md`](tauri-plugin-passkey/macos/README.md)
- **Android** — Android Studio and the Android SDK. Do **not** install ktlint
  yourself: the lint scripts run `pnpm exec ktlint`, which resolves a pinned version
  that `android/build.gradle.kts` also pins for the Gradle ktlint plugin. A `ktlint` on
  `PATH` from Homebrew or `~/.ktlint` is a different version that will disagree with CI.
- **Windows** — Visual Studio Build Tools and the Windows SDK, for Windows Hello/CTAP2

## Build

```bash
pnpm install
pnpm build
```

Build order matters: the plugin's TypeScript bindings (`dist-js/`) must exist before
the test app builds. `pnpm build` from the root handles this in dependency order.

### `.tauri/tauri-api` must be materialized before mobile work

`tauri-plugin-passkey/android/.tauri/tauri-api` (and the iOS equivalent) are gitignored
copies of the Tauri mobile runtime that the Tauri CLI normally drops in place while
building an app for a mobile target. Nothing in this repo creates them on a fresh
checkout, so Gradle tasks and Xcode builds/tests fail until you run:

```bash
tauri-plugin-passkey/scripts/materialize-tauri-android.sh
tauri-plugin-passkey/scripts/materialize-tauri-ios.sh
```

Do this before `./gradlew` anything in `tauri-plugin-passkey/android`, or any
`xcodebuild`/`pnpm tauri ios` work.

## Running the test app

```bash
cd test-app

pnpm tauri ios dev        # iOS
pnpm tauri android dev    # Android
pnpm tauri dev            # Windows/Linux
```

**macOS** needs a signed `.app` bundle with the right entitlements — `pnpm tauri dev`
runs the raw binary, which ASAuthorizationController will refuse. Use:

```bash
cd test-app
./build-macos-dev.sh
open src-tauri/target/debug/bundle/macos/test-app.app
```

## Before committing

```bash
pnpm format   # Format all code
pnpm lint     # Rust, Swift, Kotlin and JS lints
pnpm build    # Everything builds
```

Rust tests run with `pnpm test:rust` (on macOS, `tauri-plugin-passkey/scripts/test-macos.sh`
sets up the right toolchain); Android with `pnpm test:android` (after the `.tauri`
materialization step above); iOS with `pnpm test:swift`.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT OR Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- [Plugin documentation](tauri-plugin-passkey/README.md)
- [Repository](https://github.com/dkackman/tauri-plugin-passkey)
- [Issues](https://github.com/dkackman/tauri-plugin-passkey/issues)
