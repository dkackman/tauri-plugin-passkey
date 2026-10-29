#!/usr/bin/env bash
set -euo pipefail

# Bumps the crate + npm versions in lockstep (publish.yml and tag-release.sh both
# assert Cargo.toml and package.json agree with the tag), updates the pinned version
# in the README install snippets, then prepends this release's section to the
# changelog from conventional commits. Review the diff and commit before tagging.

VERSION="${1:?usage: bump-version.sh X.Y.Z[-suffix]}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="$ROOT/tauri-plugin-passkey"

# Only the [package] version sits at column 0 in Cargo.toml; dependency versions are
# nested, so an anchored match touches just the package version.
perl -0pi -e 's/^(version\s*=\s*")[^"]*(")/${1}'"$VERSION"'${2}/m' "$PLUGIN/Cargo.toml"
perl -0pi -e 's/("version"\s*:\s*")[^"]*(")/${1}'"$VERSION"'${2}/' "$PLUGIN/package.json"

# Cargo treats prereleases as mutually incompatible, so the install snippets pin an
# exact version and must move with every release.
for readme in "$PLUGIN/README.md" "$PLUGIN/macos/README.md" "$PLUGIN/ios/README.md"; do
    perl -pi -e 's/^(tauri-plugin-passkey\s*=\s*")[^"]*(")/${1}'"$VERSION"'${2}/' "$readme"
done

# Prepend only, never regenerate: the changelog is hand-curated (the history before
# 0.1.0-alpha.1 belongs to upstream tauri-plugin-webauthn and is summarized, not
# listed), and a full regeneration would overwrite that.
if command -v git-cliff >/dev/null 2>&1; then
    git -C "$ROOT" cliff --unreleased --tag "v$VERSION" --prepend "$PLUGIN/CHANGELOG.md"
    echo "Bumped to $VERSION and prepended its section to $PLUGIN/CHANGELOG.md."
else
    echo "Bumped to $VERSION. git-cliff not found — update $PLUGIN/CHANGELOG.md manually (or install git-cliff: https://git-cliff.org)."
fi

echo "Review the diff, commit, then run ./tag-release.sh v$VERSION"
