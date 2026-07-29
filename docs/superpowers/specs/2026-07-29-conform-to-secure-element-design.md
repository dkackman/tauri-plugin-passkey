# Design: Conform `tauri-plugin-webauthn` to `tauri-plugin-secure-element` conventions

**Date:** 2026-07-29
**Owner:** Don Kackman (dkackman)
**Status:** Approved for planning

## Purpose

`tauri-plugin-webauthn` was forked from `Profiidev/tauri-plugin-webauthn` (itself
forked from `fendent/tauri-plugin-webauthn`). Before taking it forward, we are
conforming its ergonomics — CI, helper scripts, structure, naming, config,
licensing, and release tooling — to the patterns established in the sibling
project `tauri-plugin-secure-element` (SE), so both repos share one mental model.
Genuinely good practices already present in the fork are carried forward rather
than discarded.

The two projects already share the important architecture (four-platform
trait-split authenticator/secure-element, `-api` npm package suffix,
`plugin:<name>|<command>` invoke wiring, tauri-plugin permission generation), so
this is a conformance effort, not a rearchitecture.

## Decisions (locked)

1. **Repo structure:** Full monorepo move — plugin into a `tauri-plugin-webauthn/`
   subdirectory, example renamed to `test-app/` as a root sibling. Root becomes a
   pnpm workspace. Matches SE exactly.
2. **Release flow:** Hybrid. OIDC trusted publishing (crates.io + npm) +
   `tag-release.sh` preflight backbone + reusable `ci.yml` gate, augmented with
   git-cliff changelog generation, `cargo-semver-checks` in CI, and a
   `bump-version.sh` helper. Drops release-plz automation and all long-lived
   publish tokens. Unified with SE's flow.
3. **License:** Dual **MIT OR Apache-2.0**. Retain original ProfiiDev/fendent MIT
   attribution; add Don Kackman. Rust-ecosystem standard, maximum downstream
   flexibility.
4. **Dependabot:** Keep the fork's grouped Dependabot config (npm/cargo/actions,
   weekly). Drop the Dependabot auto-merge workflow — a bad dependency bump into a
   security-sensitive plugin should be human-reviewed.

## Non-goals

- Renaming Tauri ABI / entry-point symbols (`init_plugin_webauthn`,
  `webauthn_register`, `webauthn_authenticate`, `webauthn_free_string`,
  `webauthn_cancel`). These are protocol/plugin-name-derived names, not provenance.
- Rearchitecting the `Authenticator<R>` trait split or any platform backend logic.
- Changing the plugin's public command surface (`register`, `authenticate`,
  `send_pin`/`sendPin`, `select_key`/`selectKey`, `cancel`).

## Plan (phased)

Each phase is an independently reviewable unit of work. Phase ordering isolates the
most invasive structural move (Phase 1) between low-risk bookends.

### Phase 0 — Provenance & licensing

- Add `LICENSE-MIT` (retain ProfiiDev + fendent copyright lines, add Don Kackman)
  and `LICENSE-APACHE`. Replace the single MIT `LICENSE`.
- Add a `NOTICE` (or attribution section) preserving the fork lineage.
- Set `license = "MIT OR Apache-2.0"` in `Cargo.toml` and the `license` field in
  `package.json`.
- Update `authors`, `repository`, `homepage`, `documentation` metadata in
  `Cargo.toml` and `package.json` to dkackman URLs/identity.
- Rename Android namespace `de.plugin.webauthn` → `net.kackman.webauthn`
  (mirrors SE's `net.kackman.secureelement`): the 3 `.kt` files
  (`package` declarations), `android/build.gradle.kts` (`namespace`), and the
  `ExampleInstrumentedTest` hardcoded package-name assertion.

### Phase 1 — Monorepo restructure (most invasive; isolated PR)

- Move the plugin into `tauri-plugin-webauthn/`: `src/`, `guest-js/`, `android/`,
  `ios/`, `macos/`, `permissions/`, `build.rs`, `Cargo.toml`, `package.json`,
  `rollup.config.js`, `tsconfig.json`, `dist-js/`, the consumer `README.md`, and
  `CHANGELOG.md`.
- Rename `examples/webauthn/` → `test-app/` as a root sibling; adopt SE test-app
  conventions.
- Convert root to a **pnpm workspace**: `pnpm-workspace.yaml` (members:
  `tauri-plugin-webauthn`, `test-app`), private root `package.json` named
  `tauri-plugin-webauthn-monorepo` with `pnpm -r` delegating scripts. Retire the
  npm-`workspaces` field and the stray root `pnpm-lock.yaml`/npm mix.
- Drop the Cargo workspace so the plugin is a standalone publishable crate (SE
  pattern; per-crate `Cargo.lock`). `test-app/src-tauri` becomes its own crate.
- Gitignore `.tauri/` and add `scripts/materialize-tauri-ios.sh` /
  `scripts/materialize-tauri-android.sh` (reconstruct `.tauri/tauri-api` from
  cargo's downloaded `tauri` source) so mobile lint/test run on a fresh checkout.
- `build.rs` `android_path`/`ios_path` stay relative to the plugin dir, so no
  change beyond its new location.

### Phase 2 — CI/CD rebuild (SE-style)

- Delete `checks.yml` (removes the `profiidev/rust-lint-action` third-party
  dependency), `test.yml`, the release-plz `release.yml`, and `auto-merge.yml`.
- Add `.github/workflows/ci.yml`: jobs `rust`, `typescript`, `swift`, `kotlin`,
  `rust-windows`, `rust-macos`, plus a `cargo-semver-checks` job.
  `workflow_call`-enabled; jobs set `working-directory: tauri-plugin-webauthn`.
  Preserves the fork's valuable two-axis test coverage (Linux ctap2 backend +
  macOS Swift bridge). Each job invokes the shared `pnpm` format/lint/test scripts
  (see Phase 3) rather than duplicating tool invocations.
- Add `.github/workflows/publish.yml`: tag-triggered (`v*`), reuses `ci.yml` as a
  gate via `workflow_call`, OIDC trusted publishing to crates.io
  (`rust-lang/crates-io-auth-action`) and npm (`--provenance`), version==tag
  assertions on both, dist-tag derived from prerelease suffix, auto-generated
  GitHub release.
- Keep `dependabot.yml` (fix the duplicated "Cargo" comment). Remove
  `auto-merge.yml`.

### Phase 3 — Release tooling, format/lint, & config conformance

- **Release tooling:** add root `tag-release.sh` (preflight: versions match tag,
  clean tree, on `main` == `origin/main`, tag unused locally + on origin,
  recognized prerelease suffix → correct dist-tag) and `bump-version.sh`
  (co-bumps `Cargo.toml` + `package.json`). Keep `cliff.toml`; wire git-cliff
  changelog regeneration into the release flow. Add `verify-package.mjs`
  (npm entry-point/tarball drift guard).
- **Format/lint fan-out (match SE):** root `package.json` scripts delegating via
  `pnpm -r`:
  - `format:js` / `lint:js` — prettier `--write` / `--check`
  - `format:rust` / `lint:rust` — `cargo fmt` / `cargo fmt --check` + `cargo clippy -- -D warnings`
  - `format:swift` / `lint:swift` — swiftformat / `swiftformat --lint` + swiftlint
  - `format:kotlin` / `lint:kotlin` — ktlintFormat / ktlint (`@naturalcycles/ktlint`)
  - aggregate `format` and `lint` running all four; `build` / `test` via `pnpm -r`.
  CI calls these same scripts so local and CI share one source of truth.
- **Config conformance:** adopt SE's `.editorconfig`; replace the fork's
  `.prettierrc` (`singleQuote: true`, `trailingComma: none`) with SE's
  `.prettierrc.json` (`semi: true`, `singleQuote: false`, `trailingComma: es5`,
  `tabWidth: 2`, `printWidth: 80`) — reformats JS/TS. Drop the fork's
  `rustfmt.toml` (`tab_spaces = 2`) for default rustfmt 4-space per `.editorconfig`
  — reformats Rust. Add `.swiftlint.yml` and `.swiftformat`. Wire ktlint into the
  Android Gradle build (`org.jlleitschuh.gradle.ktlint`).
- **Crate packaging:** add the `#[cfg(not(any(desktop, mobile)))]` stub module so
  `cargo package` builds cleanly; add `cargo package --allow-dirty` (or
  equivalent) verification to CI.
- **Docs/meta:** add `SECURITY.md`, `CLAUDE.md`, and split the root dev-facing
  README from the plugin consumer README (the latter is what renders on npm and
  crates.io).

### Phase 4 — Loose-end fixes & explicit keepers

- **Fix:** stray empty-named `permissions/autogenerated/commands/.toml`;
  `Cargo.lock` gitignore-vs-commit inconsistency (commit it for the binary-ish
  plugin + test-app, keep consistent with SE).
- **Keep from the fork (do not regress):** `examples`→`test-app` `setup-dev.sh`
  and `build-macos-dev.sh` (robust Apple signing/provisioning tooling),
  `scripts/test-macos.sh` (Swift-toolchain shim), the production-grade
  `macos/README.md` and `ios/README.md` with troubleshooting tables, and the
  security-remediation `validation.rs` (rpId/origin + PRF salt validation).

## Out-of-band actions (owner, outside the repo)

Flagged here because CI/publish will not function until these are done:

- Configure an OIDC **trusted publisher** on crates.io for the crate.
- Configure npm **trusted publishing / provenance** for `tauri-plugin-webauthn-api`.
- Create the GitHub `release` **environment**.
- Delete the inherited `PERSONAL_TOKEN`, `CRATES_IO_API_TOKEN`, and (broken)
  `NODE_AUTH_TOKEN` secrets once OIDC is verified working.

## Risks & mitigations

- **Structural move breaks paths (Phase 1).** Mitigation: isolate in its own PR;
  verify `cargo check`, `pnpm build`, and CI green before layering later phases.
- **Reformatting churn (prettier/rustfmt changes).** Mitigation: land the config +
  bulk-reformat as a single mechanical commit, separate from logic changes, so
  diffs stay reviewable.
- **OIDC not yet provisioned when a tag is pushed.** Mitigation: complete
  out-of-band actions and do a dry-run/prerelease tag before the first real
  release.

## Success criteria

- Repo layout, CI jobs, release flow, format/lint scripts, config files, and
  naming match SE's conventions (allowing for `webauthn` vs `secure-element`
  domain differences).
- `pnpm lint` and `pnpm build` pass locally; full `ci.yml` passes on all platforms.
- A prerelease tag publishes to crates.io + npm via OIDC with no long-lived tokens.
- No remaining references to ProfiiDev/fendent as owner (attribution retained in
  license/NOTICE only); Android namespace is `net.kackman.webauthn`.
- The fork's kept assets (Apple tooling, platform READMEs, `validation.rs`) remain
  intact.
