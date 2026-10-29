# Tauri Plugin Passkey

A Tauri plugin providing WebAuthn/FIDO2/passkey authentication for Linux, Windows,
macOS, iOS, and Android.

This is a **pnpm workspace monorepo**: the plugin lives in `tauri-plugin-passkey/` and
an example app in `test-app/`.

## Naming: published names vs. native identifiers

The repository, the directory, the crate, the npm package, and the runtime plugin
identity are all named `passkey`:

- Crate: `tauri-plugin-passkey` (`Cargo.toml` in `tauri-plugin-passkey/`; `links`
  matches), Rust path `tauri_plugin_passkey::init()`
- npm package: `tauri-plugin-passkey-api` (`@tauri-apps/api` is a peer dependency)
- Tauri plugin id `Builder::new("passkey")` in `src/lib.rs`, invoked from JS as
  `plugin:passkey|<command>`, permission identifiers `passkey:*`, app config under
  `plugins.passkey` in `tauri.conf.json`

Several native identifiers predate the rename and still use the plugin's historical
`webauthn` name:

- Android plugin class registration: `net.kackman.webauthn` / `WebauthnPlugin`
- iOS: the Swift package (`ios/Package.swift`) is named `tauri-plugin-passkey`, its source
  module/class is `WebauthnPlugin` (`ios/Sources/WebauthnPlugin/`), and its entry point is
  `@_cdecl("init_plugin_passkey")`
- macOS: the Swift package and module are `WebauthnBridge`
- The Linux event name is `tauri-plugin-passkey` (`EVENT_NAME` in `guest-js/index.ts`)

Don't be surprised when the native identifiers say `webauthn` but Cargo.toml,
package.json, and permission strings say `passkey` — that split is intentional
(renaming the native class/package names is a separate, larger change).

## Architecture

- `src/authenticators/mod.rs` — the `Authenticator<R>` trait (`register`, `authenticate`,
  `send_pin`, `select_key`, `cancel`), implemented per-backend and cfg-selected:
  - `ctap2/` — Linux, direct CTAP2 authenticator client
  - `macos.rs` — macOS, FFI into the Swift bridge (`macos/Sources/WebauthnBridge/`)
  - `mobile.rs` — iOS + Android, via the Tauri mobile plugin bridge
  - `windows.rs` — Windows
- `src/lib.rs` — picks the backend via `cfg`, registers the five commands
  (`register`, `authenticate`, `send_pin`, `select_key`, `cancel`) with
  `Builder::new("passkey")`; `init()` returns `TauriPlugin<R, Option<Config>>`
- `src/config.rs` — plugin config (`allowedOrigins`); `src/validation.rs` enforces it and
  the rpId/origin checks
- `src/commands.rs` — the `#[command]` handlers invoked from JS (timeout precedence,
  `busy` guard via `src/inflight.rs`)
- `build.rs` — `COMMANDS` array (must match `invoke_handler` and `commands.rs`) and the
  Swift linker setup for macOS, including a link-search fallback for Xcode 27's
  SwiftPM `Products/<Configuration>` output layout that swift-rs does not search
- Native code:
  - `macos/Sources/WebauthnBridge/` — Swift FFI bridge (Exports.swift, Options.swift,
    PasskeyHandler.swift)
  - `ios/Sources/WebauthnPlugin/` — Tauri mobile plugin (WebauthnPlugin.swift,
    Options.swift, PasskeyHandler.swift). `Options.swift` is duplicated between iOS and
    macOS; keep the copies identical apart from the `#available` check and its message
  - `android/src/main/java/WebauthnPlugin.kt` — Android Credential Manager integration
- `guest-js/index.ts` — the JS/TS API surface

## Development Workflow

### Prerequisites

Beyond Rust/Node/pnpm/Tauri CLI:

- iOS/macOS: Xcode, swiftformat, swiftlint
- Android: Android Studio, Android SDK, ktlint (via `pnpm exec ktlint`, pinned version —
  don't install a separate one from Homebrew/`~/.ktlint`, it can disagree with CI)
- macOS: a provisioning profile with Associated Domains entitlements and
  `com.apple.security.get-task-allow`; ASAuthorizationController requires a real `.app`
  bundle, not a bare signed binary — see `test-app/build-macos-dev.sh`

### `.tauri/tauri-api` materialization

`android/.tauri/tauri-api` and the iOS equivalent are gitignored copies of the Tauri
mobile runtime that the Tauri CLI normally drops in place while building an app for
mobile. Nothing in this repo creates them on a fresh checkout, so Gradle/Xcode builds
and tests fail until you run:

```bash
tauri-plugin-passkey/scripts/materialize-tauri-android.sh
tauri-plugin-passkey/scripts/materialize-tauri-ios.sh
```

Required before any Android Gradle task or iOS Xcode build/test.

### Building and testing

```bash
pnpm install
pnpm build        # pnpm -r build, dependency order (dist-js before test-app)
pnpm test         # pnpm -r test
pnpm test:js      # vitest (guest-js API contract tests; mocks @tauri-apps/api)
pnpm test:rust    # cargo test (macOS: use scripts/test-macos.sh for the right toolchain)
pnpm test:swift   # macOS bridge (swift test) + iOS plugin (materializes iOS deps, xcodebuild test)
pnpm test:swift:macos # just the macOS WebauthnBridge SwiftPM tests (no simulator needed)
pnpm test:swift:ios   # just the iOS plugin tests (needs an iOS simulator)
pnpm test:android # ./gradlew test (Robolectric unit tests; needs materialize-tauri-android.sh first)
```

Environment notes:

- On macOS, run Rust tests with `tauri-plugin-passkey/scripts/test-macos.sh` (passes args
  through to `cargo test`). It puts Xcode's `swift` first on `PATH` and links with
  `/usr/bin/cc`, because a stray swiftly toolchain cannot build `WebauthnBridge` and the
  devenv `cc` cannot see macOS system libraries.
- `build.rs` adds a swift-rs link-path fallback for newer Xcode (27), whose SwiftPM writes
  the static library under `Products/<Configuration>`; no action needed, but it is the
  first place to look if `WebauthnBridge` stops linking after an Xcode upgrade.
- `cargo check` of the test app under devenv needs the system toolchain:
  `CC=/usr/bin/cc CXX=/usr/bin/c++ AR=/usr/bin/ar SDKROOT=$(xcrun --sdk macosx --show-sdk-path) cargo check`
  (from `test-app/src-tauri`).
- Android Gradle tasks need a JDK 17–24 (CI uses 17).

### Running the test app

```bash
cd test-app
pnpm tauri ios dev
pnpm tauri android dev
pnpm tauri dev              # Windows/Linux

# macOS (needs a signed .app bundle, not the raw binary)
./build-macos-dev.sh
open src-tauri/target/debug/bundle/macos/webauthn.app   # productName in src-tauri/tauri.conf.json
```

On NDK r23+ (r29 confirmed) the Android build fails while cross-compiling the test app's
vendored OpenSSL with `aarch64-linux-android-ranlib: command not found` — the NDK dropped
the target-prefixed binutils wrappers and ships only the `llvm-` ones. Point the openssl
build at those:

```bash
NDKBIN="$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin"   # linux-x86_64 on Linux
PATH="$NDKBIN:$PATH" \
  AR_aarch64_linux_android=llvm-ar RANLIB_aarch64_linux_android=llvm-ranlib \
  pnpm tauri android build --debug --target aarch64
```

Substitute the matching `AR_<target>` / `RANLIB_<target>` pair for other ABIs. CI is
unaffected — its Android job runs the plugin's Gradle tests, which never build OpenSSL.

### Before committing

```bash
pnpm format   # Format all code
pnpm lint     # Rust, Swift, Kotlin, JS lints
pnpm build    # Everything builds
```

## Release flow

1. `./bump-version.sh X.Y.Z[-suffix]` — bumps `Cargo.toml` + `package.json` in lockstep
   and regenerates `CHANGELOG.md` from conventional commits (requires `git-cliff` for
   the changelog step)
2. Review the diff, commit
3. `./tag-release.sh vX.Y.Z[-suffix]` — validates the tag matches the bumped versions,
   tags, and pushes, which triggers `.github/workflows/publish.yml` (crates.io + npm)

## Debugging

Android logs: `./adb-logs.sh`.
