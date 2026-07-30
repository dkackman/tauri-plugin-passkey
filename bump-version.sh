#!/usr/bin/env bash
set -euo pipefail

# Bumps the crate + npm versions in lockstep (publish.yml and tag-release.sh both
# assert Cargo.toml and package.json agree with the tag), then regenerates the
# changelog from conventional commits. Review the diff and commit before tagging.

VERSION="${1:?usage: bump-version.sh X.Y.Z[-suffix]}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="$ROOT/tauri-plugin-passkey"

# Only the [package] version sits at column 0 in Cargo.toml; dependency versions are
# nested, so an anchored match touches just the package version.
perl -0pi -e 's/^(version\s*=\s*")[^"]*(")/${1}'"$VERSION"'${2}/m' "$PLUGIN/Cargo.toml"
perl -0pi -e 's/("version"\s*:\s*")[^"]*(")/${1}'"$VERSION"'${2}/' "$PLUGIN/package.json"

if command -v git-cliff >/dev/null 2>&1; then
    git -C "$ROOT" cliff --tag "v$VERSION" -o "$PLUGIN/CHANGELOG.md"
    echo "Bumped to $VERSION and regenerated $PLUGIN/CHANGELOG.md."
else
    echo "Bumped to $VERSION. git-cliff not found — update $PLUGIN/CHANGELOG.md manually (or install git-cliff: https://git-cliff.org)."
fi

echo "Review the diff, commit, then run ./tag-release.sh v$VERSION"
