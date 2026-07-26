#!/bin/bash
# Build and sign macOS app for WebAuthn platform authenticator development
#
# PREREQUISITES:
# 1. Run ./setup-dev.sh to generate src-tauri/Entitlements.plist
# 2. Register App ID (identifier from src-tauri/tauri.conf.json) with Associated Domains
#    at https://developer.apple.com/account/resources/identifiers/list
# 3. Create a Mac Development provisioning profile at:
#    https://developer.apple.com/account/resources/profiles/list
# 4. Place the downloaded profile as: examples/webauthn/embedded.provisionprofile
# 5. Deploy apple-app-site-association on the associated domain (see Entitlements.plist)
#
# Run this script from anywhere; it operates on its own directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration - derived from config files
ENTITLEMENTS="src-tauri/Entitlements.plist"
PROVISIONING_PROFILE="embedded.provisionprofile"
TAURI_CONF="src-tauri/tauri.conf.json"

# ---------------------------------------------------------------------------
# Prerequisite checks
#
# These must run BEFORE any value extraction: reading a missing plist makes
# PlistBuddy exit 1, which would abort the script with a cryptic
# "Entry ... Does Not Exist" instead of the guidance below.
# ---------------------------------------------------------------------------

if [ ! -f "$ENTITLEMENTS" ]; then
    echo "ERROR: Entitlements file not found at $ENTITLEMENTS"
    echo ""
    echo "Generate it with your Team ID, bundle ID and associated domain:"
    echo "   cd $SCRIPT_DIR && ./setup-dev.sh"
    exit 1
fi

if [ ! -f "$TAURI_CONF" ]; then
    echo "ERROR: Tauri config not found at $TAURI_CONF"
    exit 1
fi

if [ ! -f "$PROVISIONING_PROFILE" ]; then
    echo "ERROR: Provisioning profile not found at $PROVISIONING_PROFILE"
    echo ""
    echo "You need to create a Mac Development provisioning profile:"
    echo ""
    echo "1. Go to https://developer.apple.com/account/resources/identifiers/list"
    echo "   - Register the App ID from $TAURI_CONF"
    echo "   - Enable: Associated Domains"
    echo ""
    echo "2. Go to https://developer.apple.com/account/resources/profiles/list"
    echo "   - Click '+' to create a new profile"
    echo "   - Select 'macOS App Development'"
    echo "   - Select your App ID"
    echo "   - Select your development certificate"
    echo "   - Select your Mac device(s)"
    echo "   - Download the profile"
    echo ""
    echo "3. Copy the downloaded .provisionprofile file to:"
    echo "   $SCRIPT_DIR/$PROVISIONING_PROFILE"
    echo ""
    exit 1
fi

# ---------------------------------------------------------------------------
# Pull values from their source-of-truth config files
#
# jq -r prints the string "null" (and exits 0) for a missing key, so use -e to
# fail loudly rather than building a path like ".../null.app".
# ---------------------------------------------------------------------------

BUNDLE_ID=$(jq -er '.identifier' "$TAURI_CONF")
APP_NAME=$(jq -er '.productName' "$TAURI_CONF")
TEAM_ID=$(/usr/libexec/PlistBuddy -c "Print :com.apple.developer.team-identifier" "$ENTITLEMENTS")

if [ -z "$TEAM_ID" ]; then
    echo "ERROR: com.apple.developer.team-identifier is empty in $ENTITLEMENTS"
    exit 1
fi

# ---------------------------------------------------------------------------
# Validate the provisioning profile against the entitlements
#
# A stale or mismatched profile still signs cleanly but makes passkey requests
# fail at runtime with an opaque error, so catch it here instead.
#
# `security cms -D` exits 0 even on undecodable input, so test the output.
# ---------------------------------------------------------------------------

PROFILE_PLIST="$(mktemp -t webauthn-profile)"
trap 'rm -f "$PROFILE_PLIST"' EXIT

security cms -D -i "$PROVISIONING_PROFILE" >"$PROFILE_PLIST" 2>/dev/null || true
if [ ! -s "$PROFILE_PLIST" ]; then
    echo "ERROR: Could not decode $PROVISIONING_PROFILE"
    echo "The file may be corrupt or not a provisioning profile."
    exit 1
fi

# macOS profiles carry com.apple.application-identifier; iOS profiles use the
# unprefixed application-identifier. Accept either so this keeps working if the
# profile is generated for a different platform target.
PROFILE_APP_ID=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.application-identifier" "$PROFILE_PLIST" 2>/dev/null || echo "")
if [ -z "$PROFILE_APP_ID" ]; then
    PROFILE_APP_ID=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" "$PROFILE_PLIST" 2>/dev/null || echo "")
fi
if [ -z "$PROFILE_APP_ID" ]; then
    echo "ERROR: Could not read an application identifier from $PROVISIONING_PROFILE"
    exit 1
fi
EXPECTED_APP_ID="$TEAM_ID.$BUNDLE_ID"

# Profiles may carry a wildcard App ID (TEAMID.com.example.*), which is valid
# for any matching bundle ID.
case "$PROFILE_APP_ID" in
    "$EXPECTED_APP_ID") ;;
    *\*)
        if [[ "$EXPECTED_APP_ID" != ${PROFILE_APP_ID%\*}* ]]; then
            echo "ERROR: Provisioning profile does not cover this app."
            echo "  Profile App ID:  $PROFILE_APP_ID"
            echo "  This app:        $EXPECTED_APP_ID"
            exit 1
        fi
        ;;
    *)
        echo "ERROR: Provisioning profile does not match this app."
        echo "  Profile App ID:  $PROFILE_APP_ID"
        echo "  Expected:        $EXPECTED_APP_ID"
        echo ""
        echo "Re-download a profile for App ID $BUNDLE_ID, or re-run ./setup-dev.sh"
        echo "if the Team ID or bundle identifier changed."
        exit 1
        ;;
esac

# Expiry check is best-effort: PlistBuddy date formatting is locale dependent,
# so a parse failure skips the check rather than blocking the build.
PROFILE_EXPIRY=$(/usr/libexec/PlistBuddy -c "Print :ExpirationDate" "$PROFILE_PLIST" 2>/dev/null || echo "")
if [ -n "$PROFILE_EXPIRY" ]; then
    EXPIRY_EPOCH=$(date -j -f "%a %b %d %T %Z %Y" "$PROFILE_EXPIRY" +%s 2>/dev/null || echo "")
    if [ -n "$EXPIRY_EPOCH" ] && [ "$EXPIRY_EPOCH" -lt "$(date +%s)" ]; then
        echo "ERROR: Provisioning profile expired on $PROFILE_EXPIRY"
        echo "Download a fresh profile from"
        echo "  https://developer.apple.com/account/resources/profiles/list"
        exit 1
    fi
fi

# Note: the ProvisionedDevices list is deliberately not checked. On Apple
# silicon the registered Provisioning UDID differs from the hardware UUID, so
# such a check reports false failures.

# ---------------------------------------------------------------------------
# Find a signing identity belonging to $TEAM_ID
#
# The parenthetical in an "Apple Development: ..." common name is the
# certificate's own ID, not the team, e.g.
#   CN=Apple Development: dev@example.com (P55387UKSL), OU=86TDY6D9V2
# The team is the OU, so read that rather than trusting `head -1`. Signing with
# another team's certificate either fails late or produces a bundle whose
# webcredentials association silently does not work.
# ---------------------------------------------------------------------------

IDENTITY=""
MATCH_COUNT=0
ALL_CANDIDATES=""

while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    ALL_CANDIDATES="$ALL_CANDIDATES  $candidate"$'\n'
    cert_team=$(security find-certificate -c "$candidate" -p 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | tr ',/' '\n\n' \
        | sed -n 's/^ *OU *= *//p' \
        | head -1)
    if [ "$cert_team" = "$TEAM_ID" ]; then
        MATCH_COUNT=$((MATCH_COUNT + 1))
        [ -n "$IDENTITY" ] || IDENTITY="$candidate"
    fi
done <<<"$(security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development[^"]*\)".*/\1/p')"

if [ -z "$IDENTITY" ]; then
    echo "ERROR: No Apple Development signing identity found for team $TEAM_ID."
    if [ -n "$ALL_CANDIDATES" ]; then
        echo ""
        echo "Available Apple Development identities (none in team $TEAM_ID):"
        printf '%s' "$ALL_CANDIDATES"
        echo ""
        echo "Either install a certificate for team $TEAM_ID, or re-run"
        echo "./setup-dev.sh with the Team ID these certificates belong to."
    else
        echo "Make sure you have a valid development certificate installed."
    fi
    exit 1
fi

if [ "$MATCH_COUNT" -gt 1 ]; then
    echo "NOTE: $MATCH_COUNT identities match team $TEAM_ID; using the first."
fi

# Resolve the target directory rather than assuming ../../target, which is
# wrong under CARGO_TARGET_DIR or a custom --target.
TARGET_DIR=$(cd src-tauri && cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.target_directory')
if [ -z "$TARGET_DIR" ] || [ "$TARGET_DIR" = "null" ]; then
    TARGET_DIR="$SCRIPT_DIR/../../target"
fi

echo "=== Building macOS App for WebAuthn Development ==="
echo "Team ID: $TEAM_ID"
echo "Bundle ID: $BUNDLE_ID"
echo "Signing Identity: $IDENTITY"
echo "Profile App ID: $PROFILE_APP_ID"
echo ""

# Step 1: Build the Tauri app as a bundle (debug mode)
echo "Step 1: Building Tauri app bundle..."
pnpm tauri build --debug --bundles app

BUNDLE_PATH="$TARGET_DIR/debug/bundle/macos/${APP_NAME}.app"

if [ ! -d "$BUNDLE_PATH" ]; then
    echo "ERROR: Bundle not found at $BUNDLE_PATH"
    echo "Make sure 'pnpm tauri build --debug --bundles app' succeeded."
    exit 1
fi

echo "Bundle found at: $BUNDLE_PATH"

# Step 2: Copy provisioning profile into bundle.
# This must happen before signing: the profile is covered by the code seal.
echo ""
echo "Step 2: Embedding provisioning profile..."
cp "$PROVISIONING_PROFILE" "$BUNDLE_PATH/Contents/embedded.provisionprofile"

# Step 3: Sign the bundle with entitlements.
# --force replaces any signature the Tauri bundler applied, so there is no need
# to --remove-signature first. --timestamp is omitted deliberately: development
# builds are not notarized, and the timestamp server round-trip would make this
# fail offline.
echo ""
echo "Step 3: Signing bundle with entitlements..."
codesign --force \
    --sign "$IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    --timestamp=none \
    "$BUNDLE_PATH"

# Step 4: Verify the signature is actually valid.
# `codesign -dv` only displays a signature, so validate first and let a failure
# abort the script before "Build Complete" is printed.
echo ""
echo "Step 4: Verifying signature..."
codesign --verify --strict --verbose=2 "$BUNDLE_PATH"

echo ""
echo "Step 5: Signature details..."
codesign -dv --verbose=4 "$BUNDLE_PATH" 2>&1 | head -20

echo ""
echo "Step 6: Verifying entitlements..."
codesign -d --entitlements - "$BUNDLE_PATH" 2>&1

echo ""
echo "=== Build Complete ==="
echo ""
echo "The signed app bundle is at:"
echo "  $BUNDLE_PATH"
echo ""
echo "To run: open '$BUNDLE_PATH'"
echo ""
echo "Or run directly: '$BUNDLE_PATH/Contents/MacOS/$APP_NAME'"
echo ""
