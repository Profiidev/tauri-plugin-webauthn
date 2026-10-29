# WebAuthn Example App

A Tauri + SvelteKit example demonstrating the `tauri-plugin-dkackman-passkey` plugin across
macOS, iOS, Android, Windows, and Linux. The PIN-entry and key-selection UI only
activates on Linux; other platforms use native OS dialogs for those steps.

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
cd test-app
./setup-dev.sh
```

This updates `src-tauri/tauri.conf.json` and generates `src-tauri/Entitlements.plist` from the committed template. The script prints next steps for registering your App ID, creating a provisioning profile, and regenerating platform files.

To edit values manually instead, see `src-tauri/Entitlements.plist.example` for the template.

For more detail on platform-specific signing requirements, see the [macOS](../tauri-plugin-passkey/macos/README.md) and [iOS](../tauri-plugin-passkey/ios/README.md) READMEs.

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
    if (
      url.pathname === "/.well-known/apple-app-site-association" ||
      url.pathname === "/.well-known/apple-app-site-data"
    ) {
      return new Response(
        JSON.stringify({
          webcredentials: {
            apps: ["TEAM_ID.BUNDLE_ID"],
          },
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    // Android Digital Asset Links
    else if (url.pathname === "/.well-known/assetlinks.json") {
      return new Response(
        JSON.stringify([
          {
            relation: [
              "delegate_permission/common.handle_all_urls",
              "delegate_permission/common.get_login_creds",
            ],
            target: {
              namespace: "android_app",
              package_name: "BUNDLE_ID",
              sha256_cert_fingerprints: ["YOUR_SHA256_FINGERPRINT"],
            },
          },
        ]),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    return new Response("WebAuthn RP", { status: 200 });
  },
};
```

Replace the placeholders:

| Placeholder               | Value                                   | Where to find it                                                                                               |
| ------------------------- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `TEAM_ID`                 | Your Apple Developer Team ID            | [Apple Developer > Membership](https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/) |
| `BUNDLE_ID`               | Your app's bundle identifier            | `identifier` in `tauri.conf.json`                                                                              |
| `YOUR_SHA256_FINGERPRINT` | Android signing certificate fingerprint | `./gradlew signingReport` in the Android project                                                               |

The `apps` array entry must be `TEAM_ID.BUNDLE_ID` with a dot separator (not a slash).

Deploy with `wrangler deploy`, then [add a custom domain](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) in the Cloudflare dashboard.

### Android: the signing cert is also the app's WebAuthn origin

`assetlinks.json` is only half the job. On Android, Credential Manager does not put the web origin in `clientDataJSON` — it puts

```text
android:apk-key-hash:<base64url(SHA-256(signing cert DER)), unpadded>
```

That is the _same_ certificate hash as `sha256_cert_fingerprints`, just base64url instead of colon-separated hex. The relying party has to allow that origin as well, or you get a confusing failure mode: `assetlinks.json` validates, the biometric prompt appears and succeeds, and then verification rejects the credential with `InvalidRPOrigin`.

This test app's local verifier reads the value from `PASSKEY_APK_KEY_HASH`, defaulting to the standard Android debug keystore. Derive it straight from the keystore you sign with:

```bash
keytool -exportcert -keystore ~/.android/debug.keystore \
    -storepass android -alias androiddebugkey \
  | openssl dgst -sha256 -binary \
  | openssl base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
```

Then set it in `.env`:

```env
PASSKEY_APK_KEY_HASH=android:apk-key-hash:<value from above>
```

Keep the two in sync — whenever you change the fingerprint in `assetlinks.json`, change this too. `sha256_cert_fingerprints` is an array, so a worker can serve debug and release fingerprints at once, but the app allows one origin at a time.

Under [Play App Signing](https://developer.android.com/studio/publish/app-signing#app-signing-google-play), the certificate that matters is Google's re-signing cert from the Play Console, not your upload key — take the fingerprint from **Release > Setup > App signing** and derive the hash from that.

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

Place your provisioning profile at `test-app/embedded.provisionprofile`, then build and sign:

```bash
cd test-app
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

- `src-tauri/tauri.conf.json` sets `plugins.dkackman-passkey.allowedOrigins` to `[]`
  on purpose: the relying-party origin is editable in the UI, so pinning it would
  break the example. A real app should list its origin(s) — see the plugin README's
  [Security model](../tauri-plugin-passkey/README.md#security-model).
- Registered credentials are persisted to `passkey-store.json` in the app data
  directory, so they survive restarts. Delete that file to reset the demo state.
- The in-app console shows color-coded log entries for registration/authentication flow.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
