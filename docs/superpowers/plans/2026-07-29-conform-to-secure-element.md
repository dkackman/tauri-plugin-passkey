# Conform `tauri-plugin-webauthn` to `tauri-plugin-secure-element` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure and re-tool `tauri-plugin-webauthn` so its repo layout, CI, release flow, format/lint scripts, config, licensing, and naming match the `tauri-plugin-secure-element` (SE) reference project, while preserving webauthn-specific assets.

**Architecture:** pnpm-workspace monorepo — the plugin crate + native + JS bindings live in `tauri-plugin-webauthn/`, the example app in `test-app/` as a sibling. A single reusable `ci.yml` is invoked by `publish.yml` as a release gate. Publishing is OIDC trusted-publishing (no long-lived tokens), driven by a preflight-checked `tag-release.sh` + git-cliff changelog. Local and CI share one set of `pnpm -r` format/lint/build/test scripts.

**Tech Stack:** Rust (tauri-plugin 2.x), Swift (macOS FFI + iOS Tauri plugin), Kotlin (Android Credential Manager), TypeScript (rollup dual ESM/CJS), pnpm workspaces, GitHub Actions, git-cliff, cargo-semver-checks, swiftformat/swiftlint, ktlint, prettier.

## Reference sources (canonical — read before adapting)

SE lives at `/Users/don/src/dkackman/tauri-plugin-secure-element`. Unless a task gives literal content, **copy the named SE file and apply the Standard Substitutions below.** SE is the source of truth; do not invent equivalents.

**Standard Substitutions (apply to every copied SE file):**
| SE token | webauthn token |
|---|---|
| `secure-element` | `webauthn` |
| `secure_element` | `webauthn` |
| `secureelement` | `webauthn` |
| `SecureElement` | `Webauthn` |
| `SecureEnclave` | `Passkey` |
| `SecureKeysPlugin` | `WebauthnPlugin` |
| `tauri-plugin-secure-element-api` | `tauri-plugin-webauthn-api` |
| `net.kackman.secureelement` | `net.kackman.webauthn` |
| plugin name `"secure-element"` | `"webauthn"` |
| commands (`generate_secure_key`, …) | webauthn commands (`register`, `authenticate`, `send_pin`, `select_key`, `cancel`) |

**Do NOT rename** Tauri ABI symbols: `init_plugin_webauthn`, `webauthn_register`, `webauthn_authenticate`, `webauthn_free_string`, `webauthn_cancel`.

## Global Constraints

- **License:** `MIT OR Apache-2.0` in every `Cargo.toml` and `package.json` `license` field. Retain ProfiiDev + fendent MIT attribution; add Don Kackman.
- **Ownership metadata:** `authors`/`repository`/`homepage`/`documentation` point to `dkackman` / `github.com/dkackman/tauri-plugin-webauthn`. No occurrence of `Profiidev`/`ProfiiDev`/`profidev` as *owner* (attribution in license/NOTICE only).
- **Android namespace:** `net.kackman.webauthn` everywhere (build.gradle, `package` decls, instrumented-test assertion).
- **Plugin runtime name:** `"webauthn"`; commands invoked as `plugin:webauthn|<command>`.
- **npm package name:** `tauri-plugin-webauthn-api`. **Crate name:** `tauri-plugin-webauthn`. **Root monorepo package:** `tauri-plugin-webauthn-monorepo` (private).
- **Package manager:** pnpm only. No npm `workspaces` field, no stray root `pnpm-lock` from npm.
- **Publishing:** OIDC trusted publishing only. No `PERSONAL_TOKEN`/`CRATES_IO_API_TOKEN`/`NODE_AUTH_TOKEN` in any workflow.
- **Commands source-of-truth:** `build.rs` `COMMANDS` array and `lib.rs` `invoke_handler!` must list the same 5 commands.
- **Rust formatting:** default rustfmt (4-space), no `rustfmt.toml`. **Prettier:** `semi: true`, `singleQuote: false`, `trailingComma: es5`, `tabWidth: 2`, `printWidth: 80`.

---

## Phase 0 — Provenance & licensing

### Task 0.1: Dual-license files

**Files:**
- Create: `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`
- Delete: `LICENSE`

- [ ] **Step 1:** Move current MIT text to `LICENSE-MIT`; update the copyright block to `Copyright (c) 2025 ProfiiDev; Copyright (c) 2025 fendent; Copyright (c) 2026 Don Kackman` (retain original holders, add yours).
- [ ] **Step 2:** Copy SE's `LICENSE` (Apache-2.0 full text) to `LICENSE-APACHE` verbatim.
- [ ] **Step 3:** Create `NOTICE`:

```
tauri-plugin-webauthn
Copyright 2026 Don Kackman

This product is a derivative of tauri-plugin-webauthn by ProfiiDev
(https://github.com/Profiidev/tauri-plugin-webauthn), originally forked from
fendent (https://github.com/fendent/tauri-plugin-webauthn), used under the MIT
License. Original MIT copyright notices are retained in LICENSE-MIT.

Licensed under either of Apache License, Version 2.0 (LICENSE-APACHE) or
MIT License (LICENSE-MIT) at your option.
```

- [ ] **Step 4:** `git rm LICENSE` (the single old file).
- [ ] **Step 5: Commit** — `git commit -m "chore: dual-license MIT OR Apache-2.0, retain fork attribution"`

### Task 0.2: Ownership metadata

**Files:**
- Modify: `Cargo.toml` (`authors`, `repository`, `license`; add `homepage`/`documentation`/`keywords`/`categories`)
- Modify: `package.json` (`author`, `repository`, `license`)

- [ ] **Step 1:** In `Cargo.toml` set `license = "MIT OR Apache-2.0"`, `authors = ["Don Kackman"]`, `repository = "https://github.com/dkackman/tauri-plugin-webauthn"`, and add `homepage`, `documentation = "https://docs.rs/tauri-plugin-webauthn"`, plus `keywords`/`categories` mirroring SE's shape (webauthn/passkey/fido2 themed).
- [ ] **Step 2:** In `package.json` set `"license": "MIT OR Apache-2.0"`, `"author": "Don Kackman"`, and `repository.url` to the dkackman URL.
- [ ] **Step 3: Verify** — `cargo metadata --no-deps --format-version 1 >/dev/null` succeeds; `grep -ri "profidev\|profiidev" Cargo.toml package.json` returns nothing.
- [ ] **Step 4: Commit** — `git commit -m "chore: set ownership metadata to dkackman"`

### Task 0.3: Android namespace rename

**Files:**
- Modify: `android/build.gradle.kts` (`namespace`)
- Modify: the 3 `android/src/**/*.kt` files (`package` declaration)
- Modify: `android/src/androidTest/**/ExampleInstrumentedTest.kt` (asserted package name)

- [ ] **Step 1:** Replace `de.plugin.webauthn` with `net.kackman.webauthn` in `build.gradle.kts` `namespace`.
- [ ] **Step 2:** Update `package de.plugin.webauthn` → `package net.kackman.webauthn` in all 3 `.kt` files. Move files into the matching directory layout if the source tree is path-based (`src/main/java/net/kackman/webauthn/`), otherwise leave flat as the fork had it (match the fork's existing layout — the fork used a flat `src/main/java/WebauthnPlugin.kt`, so only the `package` line changes).
- [ ] **Step 3:** Update the hardcoded `assertEquals("de.plugin.webauthn", ...)` in `ExampleInstrumentedTest.kt` to `net.kackman.webauthn`.
- [ ] **Step 4: Verify** — `grep -rn "de.plugin.webauthn" android/` returns nothing.
- [ ] **Step 5: Commit** — `git commit -m "chore(android): rename namespace to net.kackman.webauthn"`

---

## Phase 1 — Monorepo restructure (isolated; land & verify before Phase 2+)

> Do this whole phase in one PR. Use `git mv` for every move so history is preserved. After the moves, the single most important gate is: `cargo check` in the plugin dir, `pnpm build`, and `pnpm -r` scripts all resolve.

### Task 1.1: Move the plugin into a subdirectory

**Files:**
- Move (git mv): `src/`, `guest-js/`, `dist-js/`, `android/`, `ios/`, `macos/`, `permissions/`, `build.rs`, `Cargo.toml`, `package.json`, `rollup.config.js`, `tsconfig.json`, `CHANGELOG.md`, consumer `README.md` → under `tauri-plugin-webauthn/`
- Keep at root: `.github/`, `docs/`, `LICENSE-*`, `NOTICE`, `.gitignore`, `cliff.toml`, dev tooling

- [ ] **Step 1:** `mkdir tauri-plugin-webauthn` then `git mv` each listed path into it. Move `Cargo.lock` too (plugin becomes standalone).
- [ ] **Step 2:** In the moved `Cargo.toml`, **remove the `[workspace]` table + `members`** (plugin is now standalone; SE pattern). Keep `links = "tauri-plugin-webauthn"`.
- [ ] **Step 3: Verify** — from `tauri-plugin-webauthn/`, `cargo check` succeeds (build.rs `android_path("android")`/`ios_path("ios")` remain valid since they're relative to the crate).
- [ ] **Step 4: Commit** — `git commit -m "refactor: move plugin into tauri-plugin-webauthn/ subdir"`

### Task 1.2: Rename example to test-app

**Files:**
- Move (git mv): `examples/webauthn/` → `test-app/`

- [ ] **Step 1:** `git mv examples/webauthn test-app` and remove the now-empty `examples/`.
- [ ] **Step 2:** In `test-app/src-tauri/Cargo.toml`, update the path dependency on the plugin to `{ path = "../../tauri-plugin-webauthn" }`. Make `test-app/src-tauri` a standalone crate (no shared workspace).
- [ ] **Step 3:** Update any script paths inside `test-app/` that referenced `examples/webauthn`.
- [ ] **Step 4: Verify** — `cd test-app/src-tauri && cargo check` resolves the plugin path dependency.
- [ ] **Step 5: Commit** — `git commit -m "refactor: rename examples/webauthn to test-app sibling"`

### Task 1.3: pnpm workspace at root

**Files:**
- Create: `pnpm-workspace.yaml`, root `package.json`
- Modify/delete: remove npm `workspaces` field from old root config; remove the stray root `pnpm-lock.yaml` (regenerate)
- Copy-adapt from SE: root `package.json`, `pnpm-workspace.yaml`, `.npmrc`

- [ ] **Step 1:** Copy SE's `pnpm-workspace.yaml`; set members to `tauri-plugin-webauthn` and `test-app` (keep SE's `onlyBuiltDependencies` if present).
- [ ] **Step 2:** Copy SE's root `package.json`, apply Standard Substitutions, name it `tauri-plugin-webauthn-monorepo`, `"private": true`. This brings the `pnpm -r` `build`/`test` and `format:*`/`lint:*` fan-out scripts (Task 3.4 refines them).
- [ ] **Step 3:** Copy SE's `.npmrc` to root and to `tauri-plugin-webauthn/`.
- [ ] **Step 4:** Remove the old npm-`workspaces` field wherever it lived; delete the stray root `pnpm-lock.yaml`.
- [ ] **Step 5: Verify** — `pnpm install` at root succeeds and produces a single root `pnpm-lock.yaml`; `pnpm -r ls` lists both members.
- [ ] **Step 6: Commit** — `git commit -m "build: convert root to pnpm workspace"`

### Task 1.4: Materialize scripts + .tauri gitignore

**Files:**
- Create: `tauri-plugin-webauthn/scripts/materialize-tauri-ios.sh`, `tauri-plugin-webauthn/scripts/materialize-tauri-android.sh`
- Modify: `.gitignore` (ignore `**/.tauri`)
- Copy-adapt from SE: `tauri-plugin-secure-element/scripts/materialize-tauri-{ios,android}.sh`

- [ ] **Step 1:** Copy both SE materialize scripts, apply Standard Substitutions. They locate the `tauri` crate via `cargo metadata` and copy its mobile Swift/Android package into `.tauri/tauri-api`.
- [ ] **Step 2:** Ensure `.gitignore` ignores `**/.tauri` and remove any committed `.tauri/` from the index (`git rm -r --cached tauri-plugin-webauthn/.tauri` if present).
- [ ] **Step 3: Verify** — from `tauri-plugin-webauthn/`, run `bash scripts/materialize-tauri-ios.sh` and confirm `ios/` `swift build` (or at least package resolution) finds `../.tauri/tauri-api`.
- [ ] **Step 4: Commit** — `git commit -m "build: gitignore .tauri and add materialize scripts"`

---

## Phase 2 — CI/CD rebuild

### Task 2.1: Reusable ci.yml

**Files:**
- Create: `.github/workflows/ci.yml`
- Delete: `.github/workflows/checks.yml`, `.github/workflows/test.yml`
- Copy-adapt from SE: `.github/workflows/ci.yml`

- [ ] **Step 1:** Copy SE's `ci.yml`. Apply Standard Substitutions. Set every job's `working-directory: tauri-plugin-webauthn`.
- [ ] **Step 2:** Adjust the `rust` job's apt deps to webauthn's needs (add `libpcsclite-dev`, `libudev-dev` — required by the ctap2/authenticator backend — alongside SE's webkit/appindicator/rsvg/patchelf/libssl-dev set).
- [ ] **Step 3:** Keep SE's `rust-windows` and `rust-macos` jobs (they double as native-link checks). The webauthn Linux `rust` job's `cargo test` already exercises the ctap2 backend — this preserves the fork's two-axis coverage.
- [ ] **Step 4:** Confirm no reference to `profiidev/rust-lint-action` remains; lint is now `pnpm lint` (Task 3.4).
- [ ] **Step 5: Verify** — `actionlint .github/workflows/ci.yml` passes (or `gh workflow view` after push). Push a branch and confirm all jobs are green.
- [ ] **Step 6: Commit** — `git commit -m "ci: replace fork CI with reusable SE-style ci.yml"`

### Task 2.2: cargo-semver-checks job

**Files:**
- Modify: `.github/workflows/ci.yml` (add `semver` job)

- [ ] **Step 1:** Add a `semver` job (ubuntu) running `obi1kenobi/cargo-semver-checks-action` (or `cargo install cargo-semver-checks && cargo semver-checks`) against `tauri-plugin-webauthn`, recovering the semver safety that release-plz's `semver_check = true` provided.
- [ ] **Step 2: Verify** — job passes on the branch.
- [ ] **Step 3: Commit** — `git commit -m "ci: add cargo-semver-checks job"`

### Task 2.3: publish.yml (OIDC)

**Files:**
- Create: `.github/workflows/publish.yml`
- Delete: `.github/workflows/release.yml` (release-plz), `.github/workflows/auto-merge.yml`
- Copy-adapt from SE: `.github/workflows/publish.yml`

- [ ] **Step 1:** Copy SE's `publish.yml`, apply Standard Substitutions. Keep: `v*` tag trigger, `uses: ./.github/workflows/ci.yml` gate, `publish-crates` (OIDC via `rust-lang/crates-io-auth-action` + version==tag assert), `publish-npm` (OIDC `--provenance`, dist-tag from suffix, `verify:package` gate, version==tag assert), `create-release`.
- [ ] **Step 2:** Delete `release.yml` and `auto-merge.yml`. Remove `cliff.toml`'s release-plz coupling if any (git-cliff stays, invoked by tag-release.sh in Task 3.1).
- [ ] **Step 3: Verify** — `actionlint` passes; `grep -rn "PERSONAL_TOKEN\|CRATES_IO_API_TOKEN\|NODE_AUTH_TOKEN\|release-plz" .github/` returns nothing.
- [ ] **Step 4: Commit** — `git commit -m "ci: OIDC trusted-publishing publish.yml, drop release-plz + auto-merge"`

### Task 2.4: Dependabot cleanup

**Files:**
- Modify: `.github/dependabot.yml`

- [ ] **Step 1:** Keep the three ecosystems (npm/cargo/github-actions), grouped weekly. Fix the duplicated "Cargo" comment. Update the `directory` values if the monorepo move changed manifest locations (npm → `/`, cargo → `/tauri-plugin-webauthn`).
- [ ] **Step 2: Verify** — `directory` paths point at real manifest locations post-move.
- [ ] **Step 3: Commit** — `git commit -m "ci: fix dependabot comment and post-move directories"`

---

## Phase 3 — Release tooling, format/lint, config

### Task 3.1: tag-release.sh + bump-version.sh

**Files:**
- Create: `tag-release.sh`, `bump-version.sh` (root)
- Copy-adapt from SE: `tag-release.sh`

- [ ] **Step 1:** Copy SE's `tag-release.sh`, apply Standard Substitutions. It must read the version from `tauri-plugin-webauthn/Cargo.toml` and `tauri-plugin-webauthn/package.json`, assert both == tag, require clean tree + on `main == origin/main`, tag unused locally and on origin, and map prerelease suffix → dist-tag (`-alpha`→alpha, `-beta`→beta, `-rc`→next, else latest) with a hard error on unrecognized suffixes.
- [ ] **Step 2:** Write `bump-version.sh` taking one arg `X.Y.Z[-suffix]`, editing the `version` field in both `tauri-plugin-webauthn/Cargo.toml` and `tauri-plugin-webauthn/package.json`, then running git-cliff to regenerate `tauri-plugin-webauthn/CHANGELOG.md` for that version:

```bash
#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:?usage: bump-version.sh X.Y.Z[-suffix]}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
PLUGIN="$ROOT/tauri-plugin-webauthn"
# Cargo.toml: only the [package] version (first `version =` under [package])
perl -0pi -e 's/^(version\s*=\s*")[^"]*(")/${1}'"$VERSION"'${2}/m' "$PLUGIN/Cargo.toml"
# package.json version
perl -0pi -e 's/("version"\s*:\s*")[^"]*(")/${1}'"$VERSION"'${2}/' "$PLUGIN/package.json"
# Regenerate changelog from conventional commits up to this tag
git -C "$ROOT" cliff --tag "v$VERSION" -o "$PLUGIN/CHANGELOG.md"
echo "Bumped to $VERSION. Review the diff, commit, then run ./tag-release.sh v$VERSION"
```

- [ ] **Step 3:** Move/keep `cliff.toml` at root and confirm it points at `tauri-plugin-webauthn` history scope.
- [ ] **Step 4: Verify** — `./bump-version.sh 0.2.1` edits both files identically and regenerates the changelog; `git diff` shows only version + changelog. Revert the test bump.
- [ ] **Step 5: Commit** — `git commit -m "release: add tag-release.sh and bump-version.sh"`

### Task 3.2: verify-package.mjs

**Files:**
- Create: `tauri-plugin-webauthn/scripts/verify-package.mjs`
- Modify: `tauri-plugin-webauthn/package.json` (add `verify:package` + `prepublishOnly` scripts)
- Copy-adapt from SE: `tauri-plugin-secure-element/scripts/verify-package.mjs`

- [ ] **Step 1:** Copy SE's `verify-package.mjs` verbatim (it's package-agnostic — reads `exports`/`main`/`module`/`types` and cross-checks against `npm pack --dry-run --json`).
- [ ] **Step 2:** Add `"verify:package": "node scripts/verify-package.mjs"` and `"prepublishOnly": "pnpm build && pnpm verify:package"` to the plugin `package.json`.
- [ ] **Step 3: Verify** — `cd tauri-plugin-webauthn && pnpm build && pnpm verify:package` passes (all declared entry points present in the tarball).
- [ ] **Step 4: Commit** — `git commit -m "build: add npm package entry-point verification"`

### Task 3.3: Config conformance

**Files:**
- Create: `.editorconfig`, `.prettierrc.json`, `.prettierignore` (root), `tauri-plugin-webauthn/.swiftlint.yml`, `tauri-plugin-webauthn/.swiftformat`
- Delete: `tauri-plugin-webauthn/rustfmt.toml`, old `.prettierrc`
- Copy-adapt from SE: `.editorconfig`, `.prettierrc.json`, `.prettierignore`, `.swiftlint.yml`, `.swiftformat`

- [ ] **Step 1:** Copy SE's `.editorconfig`, `.prettierrc.json` (semi/double-quote/es5/2-space/80), `.prettierignore` to root. Delete the fork's `.prettierrc` (single-quote/no-trailing-comma).
- [ ] **Step 2:** Delete `tauri-plugin-webauthn/rustfmt.toml` (adopt default 4-space).
- [ ] **Step 3:** Copy SE's `.swiftlint.yml` + `.swiftformat` into `tauri-plugin-webauthn/`; adjust the `.swiftlint.yml` `included`/`excluded` paths to webauthn's Swift layout (`macos/Sources`, `ios/Sources`).
- [ ] **Step 4: Bulk reformat (mechanical, separate commit):** run `cargo fmt` (in plugin), `pnpm format:js`, `swiftformat`, `ktlintFormat`. This is expected large churn.
- [ ] **Step 5: Verify** — `pnpm lint` passes clean (see Task 3.4 for the scripts; if sequencing inline, run the raw tools).
- [ ] **Step 6: Commit** — two commits: `git commit -m "chore: adopt SE editorconfig/prettier/swift lint config"` then `git commit -m "style: bulk reformat to conform to SE config"`.

### Task 3.4: Format/lint fan-out scripts

**Files:**
- Modify: root `package.json`, `tauri-plugin-webauthn/package.json`, `tauri-plugin-webauthn/android/build.gradle.kts`
- Copy-adapt from SE: the `format:*`/`lint:*` script blocks in both SE `package.json`s

- [ ] **Step 1:** In root `package.json`, add scripts matching SE: `build`/`test` (`pnpm -r`), `format` + `lint` (run all four languages), and `format:js`/`lint:js`, `format:rust`/`lint:rust`, `format:swift`/`lint:swift`, `format:kotlin`/`lint:kotlin` delegating to the plugin package.
- [ ] **Step 2:** In `tauri-plugin-webauthn/package.json`, add the concrete per-language commands (prettier write/check; `cargo fmt`/`cargo fmt --check` + `cargo clippy -- -D warnings`; `swiftformat`/`--lint` + `swiftlint`; ktlint via `@naturalcycles/ktlint`). Add `@naturalcycles/ktlint` to devDependencies at the version SE pins.
- [ ] **Step 3:** Add the `org.jlleitschuh.gradle.ktlint` plugin to `android/build.gradle.kts` with the ktlint version pinned to match the CLI (as SE does).
- [ ] **Step 4: Verify** — `pnpm lint` runs all four language linters and passes; `pnpm format` is idempotent (running twice yields no diff).
- [ ] **Step 5: Commit** — `git commit -m "build: add SE-style format/lint fan-out scripts"`

### Task 3.5: cargo package stub + CI packaging check

**Files:**
- Modify: `tauri-plugin-webauthn/src/lib.rs` (add `#[cfg(not(any(desktop, mobile)))]` stub)
- Modify: `.github/workflows/ci.yml` (`cargo package --allow-dirty` in the `rust` job)

- [ ] **Step 1:** Add a `stub` module gated on `#[cfg(not(any(desktop, mobile)))]` providing a no-op `Webauthn<R>` impl of the `Authenticator`/`WebauthnExt` surface so the crate compiles during `cargo package` (mirrors SE's `stub`). Match SE's shape.
- [ ] **Step 2:** Add `cargo package --allow-dirty` to the `rust` CI job (build.rs regenerates permissions, so `--allow-dirty` is required).
- [ ] **Step 3: Verify** — `cd tauri-plugin-webauthn && cargo package --allow-dirty` succeeds.
- [ ] **Step 4: Commit** — `git commit -m "build: add cfg-stub and cargo package CI check"`

---

## Phase 4 — Loose-end fixes, docs, & tooling reconciliation

### Task 4.1: Fix stray artifacts

**Files:**
- Delete: `tauri-plugin-webauthn/permissions/autogenerated/commands/.toml`
- Verify: `Cargo.lock` committed (not ignored) for plugin + test-app

- [ ] **Step 1:** `git rm tauri-plugin-webauthn/permissions/autogenerated/commands/.toml` (empty-named stray).
- [ ] **Step 2:** Ensure `.gitignore` does NOT ignore `Cargo.lock` for these crates (SE commits them); `git add` both `Cargo.lock` files if untracked.
- [ ] **Step 3: Verify** — `cargo build` regenerates no unexpected permission files (`git status` clean after build); both `Cargo.lock` tracked.
- [ ] **Step 4: Commit** — `git commit -m "chore: remove stray permission file, commit Cargo.lock"`

### Task 4.2: Reconcile shared Apple/toolchain scripts to SE

**Files:**
- Modify: `test-app/build-macos-dev.sh`, `test-app/src-tauri/sign_app.sh` (if present), `test-app/setup-dev.sh`, `tauri-plugin-webauthn/scripts/test-macos.sh`
- Reference: the SE counterparts (`test-app/build-macos-dev.sh`, `test-app/src-tauri/sign_app.sh`, `test-app/scripts/*`, plugin `scripts/`)

- [ ] **Step 1:** For each script, `diff` webauthn's copy against SE's current version. Port SE's improvements into webauthn's copy.
- [ ] **Step 2:** Preserve only webauthn-specific deltas that the passkey domain requires (different entitlements, `associated-domains`/AASA handling, bundle IDs). Document each retained delta with a comment `# webauthn-specific: <reason>`.
- [ ] **Step 3: Verify** — on macOS, `bash test-app/build-macos-dev.sh` (dry portions) and `bash tauri-plugin-webauthn/scripts/test-macos.sh` run without regression relative to before.
- [ ] **Step 4: Commit** — `git commit -m "chore: reconcile Apple/toolchain scripts to SE current versions"`

### Task 4.3: Docs & meta

**Files:**
- Create: `SECURITY.md`, `CLAUDE.md`, root dev-facing `README.md`
- Keep: `tauri-plugin-webauthn/README.md` (consumer doc — renders on npm/crates.io), `tauri-plugin-webauthn/macos/README.md`, `tauri-plugin-webauthn/ios/README.md`
- Copy-adapt from SE: `SECURITY.md`, `CLAUDE.md`, root `README.md`

- [ ] **Step 1:** Copy SE's `SECURITY.md` (private reporting + scope), apply Standard Substitutions and webauthn scope.
- [ ] **Step 2:** Copy SE's `CLAUDE.md` (dev-workflow notes) and its `.claude/skills/add-plugin-command/SKILL.md` checklist, adapting the command list to webauthn's 5 commands and layer paths.
- [ ] **Step 3:** Write a root dev-facing `README.md` (layout table, per-platform prerequisites, the `.tauri` materialization requirement, build order, before-committing checklist) modeled on SE's root README. Keep the existing plugin README as the consumer doc.
- [ ] **Step 4: Verify** — links resolve; `pnpm lint:js` passes on markdown if prettier covers it.
- [ ] **Step 5: Commit** — `git commit -m "docs: add SECURITY.md, CLAUDE.md, root dev README; split consumer README"`

### Task 4.4: Full green-build gate

- [ ] **Step 1:** From a clean checkout: `pnpm install`, `pnpm -r build`, `pnpm lint`, and `cd tauri-plugin-webauthn && cargo test` all pass locally.
- [ ] **Step 2:** Push the branch; confirm every `ci.yml` job (rust, typescript, swift, kotlin, rust-windows, rust-macos, semver) is green.
- [ ] **Step 3:** Do a prerelease dry-run: `./bump-version.sh 0.2.1-beta.1`, review changelog/version diff, `./tag-release.sh v0.2.1-beta.1` — confirm `publish.yml` gate runs (OIDC must be provisioned first; see Out-of-band). Revert if this is only a rehearsal.

---

## Out-of-band actions (owner, outside the repo — required before first publish)

- [ ] Configure a crates.io **OIDC trusted publisher** for `tauri-plugin-webauthn`.
- [ ] Configure npm **trusted publishing / provenance** for `tauri-plugin-webauthn-api`.
- [ ] Create the GitHub **`release` environment**.
- [ ] After OIDC verified working: delete inherited `PERSONAL_TOKEN`, `CRATES_IO_API_TOKEN`, `NODE_AUTH_TOKEN` repo/org secrets.

---

## Self-Review notes

- **Spec coverage:** all four locked decisions map to tasks — structure (Phase 1), release (Tasks 2.3, 3.1, 3.2), license (Task 0.1/0.2), Dependabot keep-drop-automerge (Task 2.3 deletes auto-merge, Task 2.4 keeps Dependabot). Format/lint fan-out (Task 3.4). Keepers/reconciliation (Task 4.2/4.3).
- **Ordering:** Phase 1 is isolated and verified before CI is rebuilt against the new paths. Config reformat (3.3) is a standalone mechanical commit to keep diffs reviewable.
- **Known dependency:** publish.yml cannot succeed until the Out-of-band OIDC setup is done — flagged in Task 4.4 Step 3.
