# VS Code Debugging Configuration

This directory contains VS Code launch configurations for debugging the Tauri test app.

## Prerequisites

1. **CodeLLDB Extension**: Install the [CodeLLDB extension](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) for Rust debugging support.

2. **Rust Toolchain**: Ensure Rust is installed and `cargo` is in your PATH.

## macOS caveat

ASAuthorizationController only works from a signed `.app` bundle with the Associated
Domains entitlement, so on macOS the "Launch" configurations start the app but every
passkey ceremony fails. Build the bundle with `test-app/build-macos-dev.sh`, open it, and
use **Attach to Tauri App** (pick the `webauthn` process) instead.

## Launch Configurations

### 1. Launch Tauri App (Debug)

- **Purpose**: Launches the test app binary (`target/debug/webauthn`) directly with the debugger attached
- **Use Case**: Quick debugging of the Rust backend without the full Tauri dev environment
- **Note**: This may not work perfectly as Tauri apps typically need the full dev environment

### 2. Attach to Tauri App

- **Purpose**: Attaches the debugger to an already running test app process
- **Use Case**:
  1. Start the app manually with `pnpm tauri dev` in the test-app directory (or open the macOS bundle)
  2. Select this configuration and choose the `webauthn` process from the list
  3. Set breakpoints in your Rust code and debug

### 3. Launch Tauri App (Tauri Dev)

- **Purpose**: Starts the app using `pnpm tauri dev` (normal development mode)
- **Use Case**: Running the app without debugging, or as part of the compound configuration

### 4. Launch Tauri App (Full Debug) - Compound

- **Purpose**: Attempts to launch the app and attach the debugger
- **Use Case**: One-click debugging setup
- **Note**: The attach step may require manual process selection

## Tasks

The `tasks.json` file includes build tasks:

- `build-test-app`: Builds the test app Rust code
- `build-plugin`: Builds the plugin Rust code
- `build-plugin-js`: Builds the plugin TypeScript/JavaScript
- `build-plugin-bundle`: Bundles the plugin JavaScript
- `build-all`: Builds everything in sequence

On macOS under devenv, the Rust tasks may need the system toolchain
(`CC=/usr/bin/cc` etc. — see CLAUDE.md).

## Troubleshooting

- **Can't find process**: Make sure the app is running before trying to attach
- **Breakpoints not working**: Ensure you're using a debug build (`cargo build` not `cargo build --release`)
- **Source maps**: The configuration includes source map settings for Rust standard library
