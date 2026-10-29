# Tauri Plugin Passkey

WebAuthn / FIDO2 / passkey authentication for Tauri 2 apps on **macOS, iOS, Android, Windows, and Linux**.

The plugin talks to each platform's native passkey API (ASAuthorization on Apple platforms, Credential Manager on Android, Windows WebAuthn API, direct CTAP2 over USB on Linux) and exposes one JS API that consumes standard WebAuthn JSON options — the same shapes your relying-party server library (e.g. `webauthn-rs`, `@simplewebauthn/server`) already produces.

## Platform support

| Capability                          | Linux                     | macOS 14+       | iOS 17.4+       | Android 9+      | Windows 10 1903+     |
| ----------------------------------- | ------------------------- | --------------- | --------------- | --------------- | -------------------- |
| `register` / `authenticate`         | ✅ USB security keys only | ✅              | ✅              | ✅              | ✅                   |
| Platform authenticator (passkeys)   | ❌                        | ✅              | ✅              | ✅              | ✅ Windows Hello     |
| PRF / hmac-secret extension         | ✅                        | ✅ (macOS 15+)  | ✅ (iOS 18+)    | ✅              | ❌ (see [PRF](#prf)) |
| Credential discovery (usernameless) | ✅                        | ✅              | ✅              | ✅              | ❌                   |
| Timeout enforced                    | ✅                        | ✅              | ✅              | ✅              | ✅                   |
| `cancel`                            | ✅                        | ✅              | ✅              | ✅              | ❌ (no-op)           |
| `sendPin` / `selectKey` / events    | ✅                        | n/a — native UI | n/a — native UI | n/a — native UI | n/a — native UI      |

On Linux the plugin is a CTAP2 client for FIDO2 security keys over USB HID only — there is no platform authenticator, and NFC/BLE keys are not used. Credentials it creates report `transports: ["usb"]`.

On macOS below 15 and iOS below 18, an assertion that requests PRF salts is rejected with `unsupported` before any system sheet is shown.

On everything except Linux, the operating system shows its own passkey UI (Touch ID / Face ID / Windows Hello / Android sheet), so PIN entry, device selection, and progress events never reach your app. On Linux the plugin surfaces those interactions as [events](#events-linux-only).

## Install

```bash
cargo add tauri-plugin-passkey       # in src-tauri/
pnpm add tauri-plugin-passkey-api    # in your frontend
```

`@tauri-apps/api` (>= 2.0.0) is a peer dependency of the npm package.

Register the plugin in `src-tauri/src/lib.rs`:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_passkey::init())
    // ...
```

`init()` returns `TauriPlugin<R, Option<Config>>`; `.plugin(init())` needs no type annotations. `Config` is re-exported as `tauri_plugin_passkey::Config`.

Grant the permission in `src-tauri/capabilities/default.json`:

```json
{
  "permissions": ["passkey:default"]
}
```

## Platform setup

Passkeys are bound to a domain, so each platform needs proof that your app owns your relying-party domain:

- **macOS** — Associated Domains entitlement + apple-app-site-association; a signed `.app` bundle is required even in dev. Full walkthrough: [macos/README.md](./macos/README.md).
- **iOS** — Associated Domains entitlement + apple-app-site-association. Full walkthrough: [ios/README.md](./ios/README.md).
- **Android** — Digital Asset Links (`assetlinks.json`) matching your signing cert. Full walkthrough: [android/README.md](./android/README.md).
- **Windows** — nothing beyond Windows 10 1903+. Nothing binds the rpId to your app; see [Security model](#security-model).
- **Linux** — nothing; a USB FIDO2 security key is used directly. Nothing binds the rpId to your app; see [Security model](#security-model).

## Security model

`register` and `authenticate` take an `origin` argument that the webview supplies. The plugin checks that it is `https` (or `http` on a loopback host) and that the options' `rpId` is that origin's host or a registrable suffix of it.

- **Apple and Android** additionally bind the rpId to the app: the OS refuses an rpId that is not listed in the app's associated domains (Apple) or whose `assetlinks.json` does not name the app (Android). Script running in the webview cannot obtain credentials for a site the app is not associated with.
- **Linux and Windows** have no such binding. Whatever origin the webview passes ends up in `clientDataJSON`, so script injected into the webview could request credentials for any site by claiming that site's origin.

Pin the origin your app is allowed to claim in `tauri.conf.json`:

```json
{
  "plugins": {
    "passkey": {
      "allowedOrigins": ["https://example.com"]
    }
  }
}
```

When the list is non-empty, `register` and `authenticate` reject any origin not in it with kind `validation`, on every platform, before the rpId check. Each entry is parsed as a URL and reduced to its origin (`scheme://host[:port]`), so paths and trailing slashes are ignored, but scheme and port must match exactly. Only `http(s)` origins are meaningful: entries that do not parse, or that have an opaque origin (`tauri://localhost` or any other non-http(s) scheme), match nothing. A non-empty list with no usable `http(s)` entry therefore rejects every origin (fail closed) — the plugin logs a warning at startup when that happens. An empty list — or no `plugins.passkey` entry at all — disables the check.

The [example app](#example-app) sets `allowedOrigins: []` on purpose, because its relying-party origin is editable in its UI. A real app should list its origin(s), and on Linux and Windows this is the only thing that stops a compromised webview from claiming another site's origin.

## Usage

```typescript
import {
  register,
  authenticate,
  isPasskeyError,
} from "tauri-plugin-passkey-api";

// `creationOptions` / `requestOptions` come from your RP server and are
// standard WebAuthn JSON (PublicKeyCredentialCreationOptionsJSON etc.).
try {
  const credential = await register("https://example.com", creationOptions);
  // send `credential` back to your server to finish registration
} catch (e) {
  if (isPasskeyError(e) && e.kind === "validation") {
    // e.g. the rp.id in the options does not match the origin
  }
}

const assertion = await authenticate("https://example.com", requestOptions);
// optional third argument: timeout in milliseconds
```

| Function                                  | Returns                    |
| ----------------------------------------- | -------------------------- |
| `register(origin, options, timeout?)`     | `RegistrationResponseJSON` |
| `authenticate(origin, options, timeout?)` | `PublicKeyCredentialJSON`  |
| `cancel()`                                | `void`                     |
| `sendPin(pin)` / `selectKey(index)`       | `void` (Linux only)        |
| `registerListener(callback)`              | `UnlistenFn` (Linux only)  |

`PublicKeyCredentialJSON` is `RegistrationResponseJSON | AuthenticationResponseJSON`; the WebAuthn JSON types are the standard DOM ones.

### Timeout

The ceremony timeout is the `timeout` argument if given, else the options' own `timeout`, else 60000 ms. Every platform enforces it: the Apple handlers dismiss the system sheet, Android bounds the Credential Manager call, and Linux and Windows pass it to the authenticator. A timed-out ceremony fails with kind `authenticator` (on Windows, see the note under [Errors](#errors)).

### Concurrency

One ceremony runs at a time per app. A `register` or `authenticate` call made while another is in flight fails immediately with kind `busy`; the running ceremony is unaffected. `cancel()` is not subject to this and can be called mid-ceremony.

## Options handling

All platforms accept spec-minimal JSON: missing `allowCredentials` defaults to `[]`, missing `userVerification` (on request options and `authenticatorSelection`) to `"preferred"`, and missing `requireResidentKey` to `true` only when `residentKey` is `"required"`.

- **macOS / iOS** — `userVerification`, `authenticatorSelection.authenticatorAttachment` (`"platform"` offers only passkeys, `"cross-platform"` only security keys), `attestation`, and `excludeCredentials` are honoured at registration. Apple authenticators (passkeys and security keys) support ES256 only: if `pubKeyCredParams` is non-empty and lacks ES256 (`-7`), registration fails with `unsupported` before any system UI is shown. Still ignored: `residentKey`, `hints`, credential `transports` (all are allowed), and `authenticatorAttachment` at authentication (passkeys and security keys are always offered). PRF is requested from passkeys only.
- **Android** — the options JSON is handed to Credential Manager, which interprets it. `residentKey: "discouraged"` is rejected with `unsupported` (Credential Manager only creates discoverable credentials); a missing `residentKey` becomes `"preferred"`.
- **Linux** — `userVerification`, `residentKey`, `pubKeyCredParams`, `excludeCredentials` and `allowCredentials` are passed to the CTAP2 authenticator.
- **Windows** — options are passed to the Windows WebAuthn API.

## Errors

Every rejected promise carries a `PasskeyError`:

```typescript
{
  kind: PasskeyErrorKind;
  message: string;
}
```

| Kind            | Meaning                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `io`            | An operating-system I/O error.                                                                                                        |
| `platform`      | The native API or mobile plugin bridge failed.                                                                                        |
| `serialization` | Options or a response could not be (de)serialized — e.g. a required WebAuthn field is missing.                                        |
| `validation`    | A precondition failed: origin not in `allowedOrigins`, insecure origin, rpId not matching the origin, malformed PRF salt.             |
| `authenticator` | The ceremony failed or was declined, including timeouts (the message says the request timed out).                                     |
| `unsupported`   | The platform cannot fulfil the request by design — see [PRF](#prf), [Options handling](#options-handling), and Android `residentKey`. |
| `cancelled`     | The user dismissed the native sheet, or `cancel()` was called.                                                                        |
| `busy`          | Another ceremony is already in flight (see [Concurrency](#concurrency)).                                                              |

The set is non-exhaustive — new kinds may be added in minor releases, so treat unknown kinds as generic failures. `message` is display text; do not parse it. On Windows the underlying library currently reports native failures generically, so a cancelled or timed-out Windows ceremony may surface as `platform`.

## PRF

The PRF contract matches the browser's, on every platform:

- `extensions.prf` is the only accepted spelling on input; results come back in
  `clientExtensionResults.prf` (`prf.enabled` after registration,
  `prf.results.{first,second}` after authentication).
- The CTAP2-level `hmacCreateSecret` / `hmacGetSecret` extensions and
  `prf.evalByCredential` are rejected with kind `unsupported` rather than
  ignored; pass salts in `prf.eval`.
- Salts are base64url, padded or unpadded, of any length, and are used exactly as a browser would use them —
  including on Linux, where the CTAP2 backend derives the hmac-secret salt as
  `SHA-256("WebAuthn PRF" || 0x00 || salt)` to match what the native layers do
  internally. A salt that is not valid base64url fails with `validation`.
- `prf.eval` at registration is rejected with `unsupported`; register
  with `prf: {}` and evaluate salts during authentication.
- **PRF is never silently absent.** If `prf` was requested and the platform
  cannot provide it, registration still succeeds and reports
  `prf.enabled: false` — the same signal a browser gives for an authenticator
  without hmac-secret — while an assertion that requests salts fails with kind
  `unsupported` instead of returning no secret. This applies to
  **Windows** (no PRF support at all), **macOS below 15** and **iOS below 18**
  (checked before the sheet is shown), and any CTAP2 authenticator without
  hmac-secret.

## Events (Linux only)

On Linux the plugin emits interaction events (PIN required, touch required, key selection) that your UI must handle with `registerListener`, `sendPin`, and `selectKey`:

```typescript
import {
  registerListener,
  sendPin,
  selectKey,
  PasskeyEventType,
} from "tauri-plugin-passkey-api";

const unlisten = await registerListener((event) => {
  switch (event.type) {
    case PasskeyEventType.PinEvent:
      /* prompt for PIN, then sendPin(pin) */ break;
    case PasskeyEventType.SelectKey:
      /* show event.keys, then selectKey(i) */ break;
    case PasskeyEventType.PresenceRequired:
      /* "touch your key" */ break;
  }
});
```

These are no-ops on other platforms — safe to wire unconditionally.

## Example app

A complete relying-party + frontend example (including PRF, discoverable and non-discoverable flows) lives in [`test-app/`](https://github.com/dkackman/tauri-plugin-passkey/tree/main/test-app).

## Acknowledgments

This project is a derivative of
[`tauri-plugin-webauthn`](https://github.com/Profiidev/tauri-plugin-webauthn)
by [ProfiiDev](https://github.com/Profiidev), itself originally forked from
[fendent/tauri-plugin-webauthn](https://github.com/fendent/tauri-plugin-webauthn). See the
[repository's NOTICE file](https://github.com/dkackman/tauri-plugin-passkey/blob/main/NOTICE)
for full attribution.

## License

MIT OR Apache-2.0
