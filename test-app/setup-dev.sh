#!/bin/bash
# One-time setup for developer-specific identifiers.
# Run this from anywhere; it operates on its own directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TAURI_CONF="src-tauri/tauri.conf.json"
ENTITLEMENTS="src-tauri/Entitlements.plist"
ENTITLEMENTS_TEMPLATE="src-tauri/Entitlements.plist.example"
IOS_ENTITLEMENTS_TEMPLATE="src-tauri/Entitlements.iOS.plist.example"

# Temp files are declared up front so the trap is valid under `set -u`.
RENDER_TMP=""
TMP_CONF=""
TMP_ENV=""
cleanup() {
    rm -f "$RENDER_TMP" "$TMP_CONF" "$TMP_ENV"
}
trap cleanup EXIT

for tmpl in "$ENTITLEMENTS_TEMPLATE" "$IOS_ENTITLEMENTS_TEMPLATE"; do
    if [ ! -f "$tmpl" ]; then
        echo "ERROR: Template not found at $tmpl"
        exit 1
    fi
done

if [ ! -f "$TAURI_CONF" ]; then
    echo "ERROR: Tauri config not found at $TAURI_CONF"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required. Install it with: brew install jq"
    exit 1
fi

# This script is interactive. Without a terminal `read` fails immediately and
# `set -e` would abort with no explanation at all.
if [ ! -t 0 ]; then
    echo "ERROR: setup-dev.sh must be run interactively (no terminal on stdin)."
    echo "Edit $ENTITLEMENTS by hand using $ENTITLEMENTS_TEMPLATE instead."
    exit 1
fi

# If Entitlements.plist already exists, confirm overwrite
if [ -f "$ENTITLEMENTS" ]; then
    echo "Entitlements.plist already exists."
    read -rp "Overwrite with fresh values? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Remember the current identifier so we can warn about stale generated
# platform projects further down.
OLD_BUNDLE_ID=$(jq -r '.identifier // ""' "$TAURI_CONF")

# ---------------------------------------------------------------------------
# Prompt for values
#
# Each value is validated before use. A malformed domain in particular does not
# fail loudly: it produces an entitlement like
# `webcredentials:https://example.com/?mode=developer` that signs cleanly and
# then makes passkey requests fail at runtime with an opaque error.
# ---------------------------------------------------------------------------

echo ""
echo "=== Developer Setup ==="
echo ""
echo "You'll need your Apple Developer Team ID and a bundle identifier."
echo "Find your Team ID at: https://developer.apple.com/account#MembershipDetailsCard"
echo ""

while true; do
    read -rp "Apple Developer Team ID (e.g., ABCDE12345): " TEAM_ID
    # Team IDs are uppercase. build-macos-dev.sh matches this value against the
    # signing certificate's OU exactly, so normalize rather than reject.
    TEAM_ID=$(printf '%s' "$TEAM_ID" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
    if [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
        break
    fi
    echo "  A Team ID is exactly 10 letters and digits, e.g. ABCDE12345."
done

while true; do
    read -rp "Bundle identifier (e.g., com.example.webauthn) [de.webauthn.test]: " BUNDLE_ID
    BUNDLE_ID=$(printf '%s' "${BUNDLE_ID:-de.webauthn.test}" | tr -d '[:space:]')
    if [[ "$BUNDLE_ID" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]]; then
        break
    fi
    echo "  Use reverse-DNS form with letters, digits and hyphens only,"
    echo "  e.g. com.example.webauthn"
done

while true; do
    read -rp "Associated domain for passkeys (e.g., webauthn.example.com): " DOMAIN
    DOMAIN=$(printf '%s' "$DOMAIN" | tr -d '[:space:]')
    if [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then
        break
    fi
    echo "  Enter a bare hostname with no scheme, port or path,"
    echo "  e.g. webauthn.example.com"
done

# ---------------------------------------------------------------------------
# Render the template
#
# Bash parameter expansion is used rather than sed: the replacement text is
# taken literally, so a value containing '/' or '&' cannot break the
# substitution or be reinterpreted as sed syntax.
# ---------------------------------------------------------------------------

render_template() {
    local content
    content="$(cat "$1")"
    content="${content//TEAM_ID_PLACEHOLDER/$TEAM_ID}"
    content="${content//BUNDLE_ID_PLACEHOLDER/$BUNDLE_ID}"
    content="${content//DOMAIN_PLACEHOLDER/$DOMAIN}"
    printf '%s\n' "$content"
}

# Renders <template> to <destination>, but only once the result is known good.
# Redirecting straight onto the destination would truncate it first, so any
# failure mid-render would leave an empty entitlements file behind.
render_plist_to() {
    local template="$1" dest="$2"
    RENDER_TMP="$(mktemp -t webauthn-plist)"
    render_template "$template" > "$RENDER_TMP"

    if grep -q '_PLACEHOLDER' "$RENDER_TMP"; then
        echo "ERROR: unsubstituted placeholders remain after rendering $template:"
        grep -n --color=never '_PLACEHOLDER' "$RENDER_TMP"
        echo "The template may have gained a placeholder this script does not"
        echo "know about. $dest was left unchanged."
        exit 1
    fi

    if ! plutil -lint "$RENDER_TMP" >/dev/null 2>&1; then
        echo "ERROR: rendered $template is not a valid plist."
        echo "$dest was left unchanged."
        exit 1
    fi

    mv "$RENDER_TMP" "$dest"
    RENDER_TMP=""
    # mktemp creates files 0600; these are ordinary build inputs, not secrets.
    chmod 644 "$dest"
}

echo ""
echo "Creating $ENTITLEMENTS..."
render_plist_to "$ENTITLEMENTS_TEMPLATE" "$ENTITLEMENTS"

# ---------------------------------------------------------------------------
# Generate the iOS entitlements
#
# `tauri ios init` regenerates gen/apple and overwrites this file with an empty
# dict, silently dropping the associated-domains entry that passkeys require.
# Rendering it from a template makes that recoverable: re-run this script after
# any `ios init`.
# ---------------------------------------------------------------------------

APP_NAME=$(jq -er '.productName' "$TAURI_CONF")
IOS_ENTITLEMENTS="src-tauri/gen/apple/${APP_NAME}_iOS/${APP_NAME}_iOS.entitlements"

if [ -d "$(dirname "$IOS_ENTITLEMENTS")" ]; then
    echo "Creating $IOS_ENTITLEMENTS..."
    render_plist_to "$IOS_ENTITLEMENTS_TEMPLATE" "$IOS_ENTITLEMENTS"
    IOS_ENTITLEMENTS_WRITTEN=yes
else
    IOS_ENTITLEMENTS_WRITTEN=no
fi

# ---------------------------------------------------------------------------
# Update tauri.conf.json
#
# jq edits the value structurally. The previous regex substitution was greedy
# and unanchored, so on a compact JSON line it deleted every key that followed
# the identifier.
# ---------------------------------------------------------------------------

echo "Updating identifier in $TAURI_CONF..."
TMP_CONF="$(mktemp -t webauthn-tauri-conf)"
jq --arg id "$BUNDLE_ID" '.identifier = $id' "$TAURI_CONF" > "$TMP_CONF"
mv "$TMP_CONF" "$TAURI_CONF"
TMP_CONF=""

# ---------------------------------------------------------------------------
# Set up .env
# ---------------------------------------------------------------------------

DEFAULT_RP_HOST="webauthn.dkackman.com"

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "Creating .env from .env.example..."
    TMP_ENV="$(mktemp -t webauthn-env)"
    env_content="$(cat .env.example)"
    env_content="${env_content//$DEFAULT_RP_HOST/$DOMAIN}"
    printf '%s\n' "$env_content" > "$TMP_ENV"
    mv "$TMP_ENV" ".env"
    TMP_ENV=""
    echo "  Review .env and adjust WEBAUTHN_RP_ORIGIN if needed."
elif [ -f ".env" ] && grep -q "$DEFAULT_RP_HOST" ".env"; then
    # An existing .env is never overwritten, so say so rather than leaving the
    # placeholder domain in place silently.
    echo ""
    echo "WARNING: .env still refers to $DEFAULT_RP_HOST"
    echo "  Update WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN to use $DOMAIN"
fi

# ---------------------------------------------------------------------------
# Warn about generated platform projects
#
# The bundle identifier is baked into the committed Android project, including
# the Java package directory path, so changing it leaves those files stale.
# ---------------------------------------------------------------------------

if [ -n "$OLD_BUNDLE_ID" ] && [ "$OLD_BUNDLE_ID" != "$BUNDLE_ID" ]; then
    # tr, not ${//./\/}: bash 3.2 keeps the escaping backslashes in the
    # replacement text, which yields a path that never matches.
    OLD_PACKAGE_PATH="src-tauri/gen/android/app/src/main/java/$(printf '%s' "$OLD_BUNDLE_ID" | tr '.' '/')"
    if [ -d "src-tauri/gen/android" ]; then
        echo ""
        echo "WARNING: the generated Android project still uses $OLD_BUNDLE_ID"
        if [ -d "$OLD_PACKAGE_PATH" ]; then
            echo "  Stale package directory: $OLD_PACKAGE_PATH"
        fi
        echo "  'pnpm tauri android init' creates the new package alongside it;"
        echo "  remove the stale directory afterwards."
    fi
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "  Team ID:    $TEAM_ID"
echo "  Bundle ID:  $BUNDLE_ID"
echo "  Domain:     $DOMAIN"
echo ""
if [ "$IOS_ENTITLEMENTS_WRITTEN" = no ]; then
    echo "NOTE: $IOS_ENTITLEMENTS was not written because gen/apple does not"
    echo "  exist yet. Run 'pnpm tauri ios init', then re-run this script."
    echo ""
fi

echo "Next steps:"
echo "  1. Register your Mac at"
echo "     https://developer.apple.com/account/resources/devices/list"
echo "     Apple silicon Macs must be registered with the Provisioning UDID"
echo "     from 'system_profiler SPHardwareDataType', not the Hardware UUID."
echo "  2. Register App ID '$BUNDLE_ID' with Associated Domains enabled"
echo "     at https://developer.apple.com/account/resources/identifiers/list"
echo "  3. Create a provisioning profile including your Mac and your"
echo "     development certificate, and save it as:"
echo "     $SCRIPT_DIR/embedded.provisionprofile"
echo "  4. Deploy your AASA file at https://$DOMAIN/.well-known/apple-app-site-association"
echo "  5. Regenerate platform files if needed:"
echo "     pnpm tauri ios init"
echo "     pnpm tauri android init"
echo "     Both overwrite generated project files. 'ios init' empties the iOS"
echo "     entitlements, so re-run ./setup-dev.sh afterwards to restore the"
echo "     associated-domains entry."
echo "  6. Build: ./build-macos-dev.sh"
echo ""
