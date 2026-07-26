# WebAuthn Example App

A Tauri + SvelteKit example demonstrating the `tauri-plugin-webauthn` plugin across macOS, iOS, and Android.

## Prerequisites

- [Node.js](https://nodejs.org/) and [pnpm](https://pnpm.io/)
- [Rust](https://www.rust-lang.org/tools/install)
- [Tauri CLI](https://v2.tauri.app/start/prerequisites/)
- An Apple Developer account (for macOS and iOS)
- A domain you control (for Associated Domains)

From the **repository root**:

```bash
pnpm install
pnpm build
```

## Developer Setup

Each developer needs their own Apple Team ID, bundle identifier, and associated domain. Run the setup script to configure these:

```bash
cd examples/webauthn
./setup-dev.sh
```

This updates `src-tauri/tauri.conf.json` and generates `src-tauri/Entitlements.plist` from the committed template. The script prints next steps for registering your App ID, creating a provisioning profile, and regenerating platform files.

To edit values manually instead, see `src-tauri/Entitlements.plist.example` for the template.

For more detail on platform-specific signing requirements, see the [macOS](../../macos/README.md) and [iOS](../../ios/README.md) READMEs.

## Relying Party Domain

WebAuthn requires an AASA file hosted at `https://<your-domain>/.well-known/apple-app-site-association` and (for Android) an asset links file at `/.well-known/assetlinks.json`.

Copy `.env.example` to `.env` and set your RP domain:

```env
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_ORIGIN=https://your-domain.com/
```

### Hosting with Cloudflare Workers

A [Cloudflare Worker](https://developers.cloudflare.com/workers/) is a simple way to serve the well-known association files. Create a worker with the following handler:

```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Apple Associated Domains
    if (url.pathname === '/.well-known/apple-app-site-association' ||
        url.pathname === '/.well-known/apple-app-site-data') {
      return new Response(JSON.stringify({
        webcredentials: {
          apps: ["TEAM_ID.BUNDLE_ID"]
        }
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // Android Digital Asset Links
    else if (url.pathname === '/.well-known/assetlinks.json') {
      return new Response(JSON.stringify([{
        relation: [
          "delegate_permission/common.handle_all_urls",
          "delegate_permission/common.get_login_creds"
        ],
        target: {
          namespace: "android_app",
          package_name: "BUNDLE_ID",
          sha256_cert_fingerprints: [
            "YOUR_SHA256_FINGERPRINT"
          ]
        }
      }]), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    return new Response('WebAuthn RP', { status: 200 });
  }
};
```

Replace the placeholders:

| Placeholder | Value | Where to find it |
| --- | --- | --- |
| `TEAM_ID` | Your Apple Developer Team ID | [Apple Developer > Membership](https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/) |
| `BUNDLE_ID` | Your app's bundle identifier | `identifier` in `tauri.conf.json` |
| `YOUR_SHA256_FINGERPRINT` | Android signing certificate fingerprint | `./gradlew signingReport` in the Android project |

The `apps` array entry must be `TEAM_ID.BUNDLE_ID` with a dot separator (not a slash).

Deploy with `wrangler deploy`, then [add a custom domain](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) in the Cloudflare dashboard.

### Verify

```bash
curl https://your-domain.com/.well-known/apple-app-site-association
curl https://your-domain.com/.well-known/assetlinks.json

# Apple's CDN cache (may take minutes to hours to propagate)
curl https://app-site-association.cdn-apple.com/a/v1/your-domain.com
```

## Running

### macOS

Enable Associated Domains developer mode (one-time):

```bash
sudo swcutil developer-mode -e true
```

Place your provisioning profile at `examples/webauthn/embedded.provisionprofile`, then build and sign:

```bash
cd examples/webauthn
./build-macos-dev.sh
```

Run the binary directly to pass environment variables (using `open` will not forward them):

```bash
../../target/debug/bundle/macos/webauthn.app/Contents/MacOS/webauthn
```

### iOS

Requires a physical device — the iOS Simulator does not support passkeys.

```bash
pnpm tauri ios dev
```

Or open in Xcode for more control over signing and debugging:

```bash
pnpm tauri ios dev --open
```

## Notes

- Credentials are stored in memory and will be lost when the app restarts.
- The in-app console shows color-coded log entries for registration/authentication flow.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
