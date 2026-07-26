#!/bin/bash
# One-time setup for developer-specific identifiers.
# Run this from the examples/webauthn directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TAURI_CONF="src-tauri/tauri.conf.json"
ENTITLEMENTS="src-tauri/Entitlements.plist"
ENTITLEMENTS_TEMPLATE="src-tauri/Entitlements.plist.example"

if [ ! -f "$ENTITLEMENTS_TEMPLATE" ]; then
    echo "ERROR: Template not found at $ENTITLEMENTS_TEMPLATE"
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

# Prompt for values
echo ""
echo "=== Developer Setup ==="
echo ""
echo "You'll need your Apple Developer Team ID and a bundle identifier."
echo "Find your Team ID at: https://developer.apple.com/account#MembershipDetailsCard"
echo ""

read -rp "Apple Developer Team ID (e.g., ABCDE12345): " TEAM_ID
if [ -z "$TEAM_ID" ]; then
    echo "ERROR: Team ID is required."
    exit 1
fi

read -rp "Bundle identifier (e.g., com.example.webauthn) [de.webauthn.test]: " BUNDLE_ID
BUNDLE_ID="${BUNDLE_ID:-de.webauthn.test}"

read -rp "Associated domain for passkeys (e.g., webauthn.example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo "ERROR: Domain is required."
    exit 1
fi

# Generate Entitlements.plist from template
echo ""
echo "Creating $ENTITLEMENTS..."
sed -e "s/TEAM_ID_PLACEHOLDER/$TEAM_ID/g" \
    -e "s/BUNDLE_ID_PLACEHOLDER/$BUNDLE_ID/g" \
    -e "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" \
    "$ENTITLEMENTS_TEMPLATE" > "$ENTITLEMENTS"

# Update tauri.conf.json identifier
echo "Updating identifier in $TAURI_CONF..."
ESCAPED_BUNDLE_ID=$(echo "$BUNDLE_ID" | sed 's/[&/\]/\\&/g')
sed -i '' "s/\"identifier\": \".*\"/\"identifier\": \"$ESCAPED_BUNDLE_ID\"/" "$TAURI_CONF"

# Set up .env if not present
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "Creating .env from .env.example..."
    sed -e "s/tauri-plugin-webauthn-example.glitch.me/$DOMAIN/g" \
        ".env.example" > ".env"
    echo "  Review .env and adjust RP_ORIGIN if needed."
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "  Team ID:    $TEAM_ID"
echo "  Bundle ID:  $BUNDLE_ID"
echo "  Domain:     $DOMAIN"
echo ""
echo "Next steps:"
echo "  1. Register App ID '$BUNDLE_ID' with Associated Domains enabled"
echo "     at https://developer.apple.com/account/resources/identifiers/list"
echo "  2. Create a provisioning profile and save it as:"
echo "     $SCRIPT_DIR/embedded.provisionprofile"
echo "  3. Deploy your AASA file at https://$DOMAIN/.well-known/apple-app-site-association"
echo "  4. Regenerate platform files:"
echo "     pnpm tauri ios init"
echo "     pnpm tauri android init"
echo "  5. Build: ./build-macos-dev.sh"
echo ""
