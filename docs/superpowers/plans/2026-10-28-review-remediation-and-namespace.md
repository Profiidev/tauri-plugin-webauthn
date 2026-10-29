# Review Remediation and Package Namespace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the correctness, security, and API gaps found in the 2026-10-28 plugin review, and publish the plugin under the `dkackman` namespace.

**Architecture:** The Rust core (`commands.rs`, `normalize.rs`, `prf.rs`, `error.rs`) gains stricter option normalization, two new error kinds, a single-flight guard, and optional origin pinning via plugin config. The three native layers (Kotlin, iOS Swift, macOS Swift) return structured error codes and honour the WebAuthn options they used to ignore; the macOS FFI switches from a wide positional C signature to a single JSON options string so it shares the iOS decoding code. The package rename is the last task because it touches every layer.

**Tech Stack:** Rust 2021 / Tauri 2.5+, webauthn-rs-proto 0.5.5, Swift 5.9/6 (ASAuthorization), Kotlin + androidx.credentials 1.5, TypeScript + vitest.

**Spec:** The review findings in this plan's "Global Constraints" and each task's rationale line. No separate spec document exists; the review text is reproduced where a task depends on it.

## Global Constraints

- Branch: `review-fixes` (already created from `main` at `dbc87f1`). Never commit to `main`.
- Commits end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Stage only the paths your task names (`git add <paths>`); other agents work in the same tree concurrently. If `git commit` fails on `index.lock`, wait a few seconds and retry.
- Rust tests on this machine: Xcode 27's Swift 6.4 puts the macOS static library at `out/Products/Debug/libWebauthnBridge.a`, which swift-rs 1.0.7 does not search. Until Task 1 lands, run tests with `cd tauri-plugin-passkey && PATH="$(dirname "$(xcrun --find swift)"):$PATH" RUSTFLAGS="-C linker=/usr/bin/cc -L native=/private/tmp/claude-501/-Users-don-src-dkackman-tauri-plugin-passkey/48adae75-cbe6-4e39-923e-6fe37659982e/scratchpad/swiftlib" cargo test`. After Task 1, `tauri-plugin-passkey/scripts/test-macos.sh` works.
- Clippy must pass with `-D warnings` on macOS (`scripts/test-macos.sh` env plus `cargo clippy --all-targets -- -D warnings`). Linux/Windows/mobile backends cannot be compiled here; keep their changes minimal and mirror existing patterns exactly. CI (`.github/workflows/ci.yml`) compiles them.
- Error kinds visible to JS are: `io`, `platform`, `serialization`, `validation`, `authenticator`, `unsupported`, `cancelled`, `busy`. `noToken` is removed. These strings appear in `error.rs`, `guest-js/index.ts`, and `README.md` and must agree.
- Native layers reject with Tauri error **codes** (not message prefixes): `cancelled`, `unsupported`, `timeout`. Rust maps `cancelled` → `Error::Cancelled`, `unsupported` → `Error::Unsupported(message)`, `timeout` → `Error::Authenticator(message)`, anything else → `Error::PluginInvoke` as today.
- Formatting: `pnpm format` at the repo root before each commit (prettier, cargo fmt, swiftformat, ktlint). `swiftformat`/`swiftlint` are installed here; `ktlint` runs via `pnpm exec ktlint`.
- README.md and CLAUDE.md are edited only by Task 11. Other tasks record what the docs must say in their commit messages.
- Final names (Task 10): crate `tauri-plugin-dkackman-passkey`, Tauri plugin id `dkackman-passkey` (derived by Tauri from the crate name), npm `@dkackman/tauri-plugin-passkey-api`. Directory stays `tauri-plugin-passkey/`.

## Review Focus

Inputs the review flagged that no existing test exercises; each gets a test in the task named.

1. A request with no `allowCredentials` and no `userVerification` (discoverable login from `@simplewebauthn/server`) must deserialize and run. Task 2.
2. `extensions.hmacGetSecret` / `hmacCreateSecret` (the 0.2.0 spelling) must be rejected with kind `unsupported`, never silently produce no secret. Task 3.
3. A second `register`/`authenticate` while one is in flight must fail fast with kind `busy`, not steal the other's cancel. Task 5.
4. With `allowedOrigins` configured, an `origin` outside the list must fail with kind `validation` before any backend runs. Task 6.
5. On Android, a credential without PRF returning `clientExtensionResults.prf: {}` must surface as kind `unsupported`, not an `authenticator` "bridge bug". Task 7.

---

## Phase 1 (sequential, unblocks everything else)

### Task 1: Build tooling and error-kind foundation

**Files:**
- Modify: `tauri-plugin-passkey/build.rs`
- Modify: `tauri-plugin-passkey/Cargo.toml`
- Modify: `tauri-plugin-passkey/package.json` (scripts only)
- Modify: `tauri-plugin-passkey/src/error.rs`
- Modify: `tauri-plugin-passkey/src/authenticators/mobile.rs`
- Modify: `tauri-plugin-passkey/src/authenticators/macos.rs:216-251`
- Modify: `tauri-plugin-passkey/src/authenticators/ctap2/platform.rs:112-114,206-208`
- Modify: `tauri-plugin-passkey/src/authenticators/windows.rs:60-67,80-85`
- Modify: `tauri-plugin-passkey/guest-js/index.ts:72-89`
- Create: `tauri-plugin-passkey/src/base64url.rs`

**Interfaces:**
- Produces: `Error::Cancelled` (kind `"cancelled"`), `Error::Busy` (kind `"busy"`); `NoToken` removed.
- Produces: `pub(crate) fn base64url::decode(input: &str) -> Result<Vec<u8>, base64::DecodeError>` accepting padded and unpadded input (try `URL_SAFE_NO_PAD`, then `URL_SAFE`), and `pub(crate) fn base64url::encode(input: &[u8]) -> String` (unpadded).
- Produces: `pub(crate) fn mobile::map_invoke_error(e: PluginInvokeError) -> Error` mapping `InvokeRejected(ErrorResponse { code: Some("cancelled"), .. })` → `Cancelled`, `Some("unsupported")` → `Unsupported(message)`, `Some("timeout")` → `Authenticator(message)`, else `PluginInvoke(e)`. Used by `register`/`authenticate`/`cancel` in `mobile.rs` instead of `?` on the raw error.
- Produces: in `macos.rs`, the Swift error string is parsed as JSON `{"code": string, "message": string}` with the same mapping; a non-JSON string stays `Error::Authenticator(string)`. Task 9 makes Swift emit that JSON.

- [ ] **Step 1: build.rs fallback link path.** After `SwiftLinker::link()`, compute `<OUT_DIR>/swift-rs/WebauthnBridge/out/Products/Debug` (and `Release` when `PROFILE=release`) and, if that directory contains `libWebauthnBridge.a`, print `cargo:rustc-link-search=native=<dir>`. Also bump `swift-rs` to `1.0.9` in `Cargo.toml` and check whether that alone fixes it; keep the fallback regardless.
- [ ] **Step 2: Verify** `tauri-plugin-passkey/scripts/test-macos.sh` now links and runs: expect `test result: ok. 61 passed`.
- [ ] **Step 3: Cargo.toml.** `tokio = { version = "1.45.0", features = ["sync", "rt", "rt-multi-thread"] }`; `description = "Tauri plugin for WebAuthn / passkey (FIDO2) authentication on macOS, iOS, Windows, Android, and Linux."`.
- [ ] **Step 4: package.json `test` script.** Replace `(pnpm test:swift || echo '⚠️ ...')` with `pnpm test:swift:macos` so a failing suite fails the script; leave `test:swift:ios` to CI (needs a simulator). Mirror in root `package.json` `test:swift`? No, root delegates with `pnpm -r`; leave root alone.
- [ ] **Step 5: Write failing tests in `error.rs`:** `cancelled_kind` asserts `Error::Cancelled.kind() == "cancelled"` and message `"Operation cancelled by the user"`; `busy_kind` asserts `Error::Busy.kind() == "busy"` and message `"Another passkey operation is already in progress"`; delete `unit_variant_kind_and_message` (NoToken).
- [ ] **Step 6: Implement** the two variants, remove `NoToken`, keep the `Serialize` impl unchanged.
- [ ] **Step 7: Create `src/base64url.rs`** with the two functions and tests: unpadded decode, padded decode (`"AQID"` and `"AQID=="` both → `[1,2,3]`), invalid input errors, encode has no `=`/`+`/`/`. Add `mod base64url;` in `lib.rs`.
- [ ] **Step 8: Replace** `base64_url_decode`/`base64_url_encode` in `mobile.rs` and `macos.rs`, and `decode_salt`/the closure in `prf.rs:70-77,263-275`, with calls to `base64url::decode`/`encode`, keeping each call site's existing error kind. Move the `base64_url_round_trips` and `base64_url_decode_rejects_invalid_input` tests from `macos.rs` into `base64url.rs`. Add test in `prf.rs`: `authentication_input_accepts_padded_salts` (`"c2FsdDE="` decodes to `b"salt1"`).
- [ ] **Step 9: Error mapping.** Implement `map_invoke_error` in `mobile.rs` with unit tests building `ErrorResponse { code: Some("cancelled".into()), message: Some("x".into()), data: () }` (the test module is `#[cfg(all(test, mobile))]`-gated since `PluginInvokeError` is mobile-only; put the pure mapping over `(code: Option<&str>, message: Option<&str>)` in a `cfg`-free helper `error_from_code(code: Option<&str>, message: &str) -> Option<Error>` in `error.rs` so it is testable on every host, and have both `mobile.rs` and `macos.rs` call it). Tests in `error.rs`: `"cancelled"` → `Cancelled`, `"unsupported"` → `Unsupported("x")`, `"timeout"` → `Authenticator("x")`, `None`/other → `None`.
- [ ] **Step 10: macOS error parsing.** In `await_swift_result`, on `Err(s)`: `serde_json::from_str::<BridgeError>(&s)` where `struct BridgeError { code: String, message: String }`; if it parses, `error_from_code(Some(&code), &message).unwrap_or(Error::Authenticator(message))`; else `Error::Authenticator(s)`. Test: `swift_error_json_with_cancelled_code_maps_to_cancelled`, `swift_error_plain_string_stays_authenticator`.
- [ ] **Step 11: Linux and Windows cancel mapping.** In `platform.rs`, after `recv()`, map `Err(authenticator::errors::AuthenticatorError::CancelledByUser)` → `Error::Cancelled` (verify the variant name in `~/.cargo/registry/src/*/authenticator-0.5.*/src/errors.rs`; if the crate is not fetched, run `cargo fetch --target x86_64-unknown-linux-gnu` from `tauri-plugin-passkey/`). In `windows.rs`, map `WebauthnCError::Cancelled`-equivalent the same way after checking `webauthn-authenticator-rs-0.5.*/src/error.rs` (`cargo fetch --target x86_64-pc-windows-msvc`). If a crate has no cancel variant, leave that backend unchanged and say so in the commit message.
- [ ] **Step 12: guest-js.** `PasskeyErrorKind`: remove `"noToken"`, add `"cancelled"` (user dismissed the native sheet or `cancel()` was called) and `"busy"` (another ceremony is in flight). Update `index.test.ts` `accepts a tagged error object` to use `"cancelled"`.
- [ ] **Step 13: Run** `scripts/test-macos.sh`, `cargo clippy --all-targets -- -D warnings` (same env), `pnpm test:js`. All green.
- [ ] **Step 14: Commit** `fix: structured error kinds, shared base64url, swift-rs link fallback`.

## Phase 2 (three streams in parallel; disjoint files)

### Stream A: Rust core (Tasks 2–6)

### Task 2: Serde defaults for spec-optional request fields

**Files:**
- Modify: `tauri-plugin-passkey/src/normalize.rs`
- Modify: `tauri-plugin-passkey/src/commands.rs:50-52`
- Modify: `tauri-plugin-passkey/src/wire_contract.rs`

**Interfaces:**
- Produces: `pub fn normalize::default_request_options(options: &mut Value)` inserting `allowCredentials: []` and `userVerification: "preferred"` when absent; `pub fn normalize::default_creation_options(options: &mut Value)` which calls `default_require_resident_key` and also inserts `authenticatorSelection.userVerification: "preferred"` when `authenticatorSelection` exists without it. `commands::register` calls `default_creation_options`; `commands::authenticate` calls `default_request_options`. The old name `default_require_resident_key` stays as a private helper.

- [ ] **Step 1: Failing wire tests** in `wire_contract.rs`: `request_options_without_allow_credentials_or_user_verification_deserialize_after_normalization` (JSON `{ "challenge": "Y2hhbGxlbmdlLWJ5dGVz", "rpId": "example.com" }` → after `default_request_options`, `from_value::<PublicKeyCredentialRequestOptions>` succeeds with empty `allow_credentials` and `UserVerificationPolicy::Preferred`), and `creation_options_with_selection_missing_user_verification_deserialize_after_normalization`.
- [ ] **Step 2: Run** the two tests; expect FAIL with `missing field`.
- [ ] **Step 3: Implement** the two functions; unit tests in `normalize.rs`: does not clobber explicit `userVerification: "required"`, does not clobber explicit `allowCredentials`, no-op when `authenticatorSelection` absent.
- [ ] **Step 4: Run** `scripts/test-macos.sh`; expect PASS. Commit `fix: default allowCredentials and userVerification like a browser`.

### Task 3: PRF input strictness

**Files:**
- Modify: `tauri-plugin-passkey/src/prf.rs:80-160`

- [ ] **Step 1: Failing tests:** `registration_input_rejects_legacy_hmac_create_secret` (`extensions: { hmacCreateSecret: true }` → `Err`, kind `unsupported`, message contains `hmacCreateSecret`); `authentication_input_rejects_legacy_hmac_get_secret` (`extensions: { hmacGetSecret: {...} }` → kind `unsupported`); `authentication_input_rejects_eval_by_credential` (`prf: { eval: {first}, evalByCredential: {...} }` → kind `unsupported`, message says to use `eval`); `extensions_null_is_replaced_by_object` (`set_registration_prf_input` on `{ "extensions": null }` yields `extensions.prf == {}`).
- [ ] **Step 2: Run**; expect FAIL.
- [ ] **Step 3: Implement.** Reject when `extensions` contains `hmacCreateSecret` (registration) or `hmacGetSecret` (authentication) regardless of `prf`; reject `prf.evalByCredential`; in `extensions_mut`, replace any non-object `extensions` value with an empty object.
- [ ] **Step 4: Run**; PASS. Commit `fix: reject legacy and unsupported PRF spellings instead of ignoring them`.

### Task 4: Timeout fallback and Linux transports

**Files:**
- Modify: `tauri-plugin-passkey/src/commands.rs:11,31,56`
- Modify: `tauri-plugin-passkey/src/authenticators/ctap2/platform.rs:138-143`

**Interfaces:**
- Produces: `pub(crate) fn commands::effective_timeout(arg: Option<u32>, options_timeout: Option<u32>) -> u32` = `arg.or(options_timeout).unwrap_or(DEFAULT_TIMEOUT)`. Both commands use it with `options.timeout` from the proto struct (field exists on both option types as `Option<u32>`).

- [ ] **Step 1: Failing tests** in `commands.rs` `#[cfg(test)]`: explicit arg wins over options; options used when arg absent; default when both absent.
- [ ] **Step 2: Implement**; run; PASS.
- [ ] **Step 3: Linux transports:** change the hardcoded `Some(vec![Usb, Nfc, Internal, Ble])` to `Some(vec![AuthenticatorTransport::Usb])` with a comment that only the USB HID transport is registered in `init_manager`. No test possible on macOS; CI's Linux job compiles it.
- [ ] **Step 4: Commit** `fix: honour options.timeout and report only the usb transport on Linux`.

### Task 5: Single-flight guard

**Files:**
- Modify: `tauri-plugin-passkey/src/commands.rs`
- Modify: `tauri-plugin-passkey/src/lib.rs:55-59`
- Create: `tauri-plugin-passkey/src/inflight.rs`

**Interfaces:**
- Produces: `pub(crate) struct InFlight(AtomicBool)` with `pub fn acquire(&self) -> crate::Result<InFlightGuard<'_>>` returning `Err(Error::Busy)` when already held; the guard clears the flag on drop. `lib.rs` does `app.manage(InFlight::default())`. `register`/`authenticate` acquire it before `block_in_place`; `cancel` does not (it must work while a ceremony runs).

- [ ] **Step 1: Failing tests** in `inflight.rs`: second `acquire` while first guard alive → `Busy`; after drop → `Ok`.
- [ ] **Step 2: Implement**; run; PASS.
- [ ] **Step 3: Wire into commands**; `scripts/test-macos.sh` and clippy green. Commit `feat: reject concurrent ceremonies with kind busy`.

### Task 6: Origin pinning via plugin config

**Files:**
- Modify: `tauri-plugin-passkey/src/lib.rs`
- Modify: `tauri-plugin-passkey/src/commands.rs`
- Modify: `tauri-plugin-passkey/src/validation.rs`
- Create: `tauri-plugin-passkey/src/config.rs`
- Modify: `test-app/src-tauri/tauri.conf.json` (add `"plugins": { "passkey": { "allowedOrigins": [] } }` with a comment-equivalent note in the test-app README that the example leaves it open because the RP origin is user-editable)

**Interfaces:**
- Produces: `#[derive(Deserialize, Default)] #[serde(rename_all = "camelCase")] pub struct Config { pub allowed_origins: Vec<String> }` read via `Builder::<R, Config>::new("passkey")` and `api.config().clone()` in `setup`, stored with `app.manage(Config)`.
- Produces: `pub fn validation::validate_origin_allowed(origin: &Url, allowed: &[String]) -> crate::Result<()>`: empty list → `Ok`; otherwise `origin.origin().ascii_serialization()` must equal one of the entries after parsing each entry as a `Url` and taking its ascii origin (so `"https://example.com/"` and `"https://example.com"` both match). Mismatch → `Error::Validation("origin https://x is not in plugins.passkey.allowedOrigins")`. Called in both commands before `validate_rp_id`.

- [ ] **Step 1: Failing tests** in `validation.rs`: empty list allows anything; exact match ok; trailing-slash entry matches; different host rejected with kind `validation`; different scheme rejected; malformed entry is skipped (does not match) rather than panicking.
- [ ] **Step 2: Implement**; run; PASS.
- [ ] **Step 3: Wire config** into `lib.rs`/`commands.rs`; `scripts/test-macos.sh` and clippy green; `cd test-app/src-tauri && cargo check` compiles (uses the same Swift env vars as `test-macos.sh`).
- [ ] **Step 4: Commit** `feat: optional allowedOrigins plugin config pins the relying-party origin`.

### Stream B: Android (Task 7)

### Task 7: Android error codes, PRF flattening, timeout

**Files:**
- Modify: `tauri-plugin-passkey/android/src/main/java/WebauthnPlugin.kt`
- Modify: `tauri-plugin-passkey/android/src/test/java/net/kackman/webauthn/WebauthnPluginTest.kt`

**Interfaces:**
- Consumes: the error-code contract from Global Constraints (`cancelled`, `timeout`).
- Produces: `flattenPrfOutput` omits the top-level `prf` key when the flattened object would be empty. `register`/`authenticate` accept the timeout: the Rust side (`mobile.rs`) now sends `{"options": <json string>, "timeout": <ms>}`? No — keep the Kotlin arg shape unchanged (a JSON string) and read `timeout` from a top-level `"timeout"` key the Rust side injects into the options JSON before `run_mobile_plugin` (`options["timeout"] = timeout`; both WebAuthn option dictionaries already define a `timeout` member, so this is spec-shaped). Stream A's Task 4 does not touch `mobile.rs`, so this task edits `mobile.rs:48-56,71-78` to insert the timeout.
- Produces: `internal fun errorCode(e: Throwable): String?` → `"cancelled"` for `androidx.credentials.exceptions.CreateCredentialCancellationException`, `GetCredentialCancellationException`, and `kotlinx.coroutines.CancellationException`; `"timeout"` for `kotlinx.coroutines.TimeoutCancellationException` (check before the generic CancellationException, it is a subclass); else `null`. Rejections call `invoke.reject(message, code)`.

- [ ] **Step 1: Prerequisite:** `tauri-plugin-passkey/scripts/materialize-tauri-android.sh`, then `cd tauri-plugin-passkey/android && ./gradlew test` passes as a baseline (5 tests).
- [ ] **Step 2: Failing tests:** `flattenOmitsPrfWhenClientExtensionResultsPrfIsEmpty` (`{"clientExtensionResults":{"prf":{}}}` → no `prf` key); `errorCodeMapsCancellationExceptions` (each of the three → `"cancelled"`); `errorCodeMapsTimeout`; `errorCodeIsNullForOtherExceptions`.
- [ ] **Step 3: Implement** `errorCode`, the `flattenPrfOutput` change, and wrap the credential call in `withTimeout(timeoutMs)` where `timeoutMs` is read from the options JSON `timeout` (default 60000 if absent).
- [ ] **Step 4: Rust side:** in `mobile.rs` insert `"timeout"` into the options `Value` before serialising, for both commands. Unit test in `mobile.rs` (cfg-free helper `fn with_timeout(options: &mut Value, timeout: u32)` so it is testable on macOS).
- [ ] **Step 5: Run** `./gradlew test`, `pnpm lint:kotlin`, `scripts/test-macos.sh`; green. Commit `fix(android): structured error codes, empty-prf handling, timeout`.

### Stream C: Apple (Tasks 8–9)

### Task 8: iOS option mapping, error codes, pre-ceremony PRF check, timeout

**Files:**
- Modify: `tauri-plugin-passkey/ios/Sources/WebauthnPlugin/WebauthnPlugin.swift`
- Modify: `tauri-plugin-passkey/ios/Sources/WebauthnPlugin/PasskeyHandler.swift`
- Modify: `tauri-plugin-passkey/ios/Tests/PluginTests.swift`

**Interfaces:**
- Consumes: error-code contract; `timeout` top-level key in the options JSON (Task 7 adds it on the Rust side; this task must also tolerate its absence, default 60000).
- Produces: `RegistrationOptions` gains `authenticatorSelection: { authenticatorAttachment: String?, userVerification: String? }?`, `attestation: String?`, `pubKeyCredParams: [{ alg: Int }]`, `timeout: Int?`. `AuthenticationOptions` gains `userVerification: String?`, `timeout: Int?`.
- Produces: `struct CeremonyOptions` (pure, testable) with `static func userVerification(_ s: String?) -> ASAuthorizationPublicKeyCredentialUserVerificationPreference?` (`required`/`preferred`/`discouraged`, nil otherwise), `static func attestation(_ s: String?) -> ASAuthorizationPublicKeyCredentialAttestationKind?` (`none`/`indirect`/`direct`/`enterprise`), `static func includesPlatform(attachment: String?) -> Bool` (false only for `"cross-platform"`), `static func includesSecurityKey(attachment: String?) -> Bool` (false only for `"platform"`), `static func securityKeyAlgorithms(_ algs: [Int]) -> [ASAuthorizationPublicKeyCredentialParameters]` (keeps only `-7` → `.ES256`; empty input → `[.ES256]`).
- Produces: `PasskeyHandler.register/authenticate` take a `CeremonyOptions`-derived set of values and build the request list from `includesPlatform`/`includesSecurityKey`; if both false, throw `PasskeyHandlerError.noAuthenticatorMatches` (code `unsupported`).
- Produces: `enum PluginErrorCode { static func from(_ error: Error) -> String? }` → `"cancelled"` for `ASAuthorizationError.canceled` and `CancellationError`; `"timeout"` for a `TimeoutError` the plugin raises; `"unsupported"` for `PasskeyHandlerError.prfUnavailable`/`.noAuthenticatorMatches`.
- Produces: pre-ceremony PRF check: if `prf` salts are present and `#available(iOS 18.0, *)` is false, reject with code `unsupported` and message `"PRF requires iOS 18 or later"` before `performRequests`.
- Produces: timeout via `withThrowingTaskGroup` racing the ceremony against `Task.sleep`; on timeout call `handler.cancel()` and reject with code `timeout`.

- [ ] **Step 1: Failing tests** in `PluginTests.swift` for every `CeremonyOptions` function and for `PluginErrorCode.from` (construct `ASAuthorizationError(.canceled)` via `NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.canceled.rawValue)`), plus decoding tests for the new optional fields (absent → nil, present → value).
- [ ] **Step 2: Run** `pnpm test:swift:ios` (materialises deps, needs the simulator named in `package.json`; if that simulator is missing, run `xcrun simctl list devices available | grep iPhone` and substitute); expect FAIL to compile.
- [ ] **Step 3: Implement**; `swiftformat ios/`, `swiftlint lint`; tests PASS.
- [ ] **Step 4: Commit** `feat(ios): honour userVerification/attachment/attestation, structured errors, timeout`.

### Task 9: macOS bridge switches to JSON options and shares the iOS mapping

**Files:**
- Modify: `tauri-plugin-passkey/macos/Sources/WebauthnBridge/Exports.swift`
- Modify: `tauri-plugin-passkey/macos/Sources/WebauthnBridge/PasskeyHandler.swift`
- Create: `tauri-plugin-passkey/macos/Sources/WebauthnBridge/Options.swift` (copy of the iOS `RegistrationOptions`/`AuthenticationOptions`/`PrfInput`/`CeremonyOptions`/`PluginErrorCode` code; the two SwiftPM packages cannot share a target because the iOS one depends on the Tauri package, so keep the files byte-identical apart from `UIKit`/`AppKit` imports and `#available(macOS 15.0, *)` vs `iOS 18.0`)
- Modify: `tauri-plugin-passkey/macos/Tests/WebauthnBridgeTests/WebauthnBridgeTests.swift`
- Modify: `tauri-plugin-passkey/src/authenticators/macos.rs`

**Interfaces:**
- Consumes: Task 1's `BridgeError { code, message }` JSON parsing in `macos.rs`; `base64url` module.
- Produces: C ABI `webauthn_register(options_json: *const c_char, context: u64, callback)` and `webauthn_authenticate(options_json: *const c_char, context: u64, callback)`; `webauthn_free_string` and `webauthn_cancel` unchanged. `options_json` is the same browser-shaped JSON `mobile.rs` sends (serialised proto options plus `extensions.prf` via `prf::set_registration_prf_input`/`set_authentication_prf_input`, plus top-level `timeout`). Error callback strings become `{"code":"cancelled","message":"..."}` JSON (code omitted when `PluginErrorCode.from` is nil).
- Produces: `macos.rs` builds the JSON exactly as `mobile.rs` does (extract a shared `pub(crate) fn prf::options_json_for_bridge_register(options, prf, timeout) -> Result<String>` and `..._authenticate(...)` in `prf.rs`? No: put them in a new `src/authenticators/bridge_options.rs` used by both `mobile.rs` and `macos.rs`; Task 7 edits `mobile.rs` concurrently, so this task creates the module and switches only `macos.rs` to it; a follow-up commit by the coordinator switches `mobile.rs`). Response parsing (`parse_registration_response`, `parse_authentication_response`) is unchanged.

- [ ] **Step 1: Failing Swift tests** in `WebauthnBridgeTests.swift`: decoding of registration/authentication JSON (port the iOS decoding tests), `CeremonyOptions` and `PluginErrorCode` tests, and `errorJSON(code:message:)` serialisation.
- [ ] **Step 2: Implement** Swift side; `cd tauri-plugin-passkey/macos && swift test` PASS; `swiftformat macos/`; `swiftlint lint`.
- [ ] **Step 3: Failing Rust tests** in `macos.rs`/`bridge_options.rs`: `register_options_json_contains_prf_and_timeout`, `authenticate_options_json_contains_eval_salts`.
- [ ] **Step 4: Implement** the Rust side; `scripts/test-macos.sh` and clippy green.
- [ ] **Step 5: Smoke check** that the test app still builds: `cd test-app && ./build-macos-dev.sh` (needs the signing setup described in CLAUDE.md; if it fails on signing rather than compilation, note that and move on).
- [ ] **Step 6: Commit** `refactor(macos): JSON options over FFI, shared option mapping with iOS, structured errors`.

## Phase 3 (sequential, after Phase 2 merges)

### Task 10: Namespace the packages under dkackman

**Files:**
- Modify: `tauri-plugin-passkey/Cargo.toml` (`name`, `links`), `tauri-plugin-passkey/package.json` (`name`), `tauri-plugin-passkey/src/lib.rs` (`Builder::new("dkackman-passkey")`), `tauri-plugin-passkey/guest-js/index.ts` (`plugin:dkackman-passkey|…`), `tauri-plugin-passkey/guest-js/index.test.ts`, `tauri-plugin-passkey/permissions/autogenerated/**` (regenerated by `cargo build`), `tauri-plugin-passkey/scripts/verify-package.mjs` (if it keys on the name), `tauri-plugin-passkey/src/authenticators/mobile.rs` (`init_plugin_passkey` symbol can stay), `test-app/package.json`, `test-app/src-tauri/Cargo.toml`, `test-app/src-tauri/src/lib.rs` (crate path `tauri_plugin_dkackman_passkey::init()`), `test-app/src-tauri/capabilities/default.json` (`dkackman-passkey:default`), `test-app/src-tauri/tauri.conf.json` (`plugins.dkackman-passkey`), `test-app/src/**` imports, `tag-release.sh` (`NPM_PKG`), `.github/workflows/publish.yml` (npm publish of a scoped package needs `--access public`, already present; first publish of a new scope cannot use OIDC trusted publishing until the package exists, so add a note in the workflow and in Task 11's docs that the first `0.3.0` publish is manual with `npm publish --access public` and the crate with `cargo publish`), `.github/dependabot.yml` (unchanged), `cliff.toml` (check for the name).
- Modify: `tauri-plugin-passkey/android/build.gradle.kts` and `android/src/**` are NOT renamed (class/package names are a separate change, per CLAUDE.md).

- [ ] **Step 1:** `grep -rn "tauri-plugin-passkey-api\|plugin:passkey\|passkey:default\|tauri_plugin_passkey\|\"passkey\"" --include='*.rs' --include='*.ts' --include='*.json' --include='*.toml' --include='*.yml' --include='*.sh' --include='*.mjs' --include='*.svelte' . | grep -v node_modules | grep -v target` and change every hit that is a package name, plugin id, permission namespace, or invoke string. Leave directory names and the `WebauthnPlugin` native class names.
- [ ] **Step 2:** `cargo build` in `tauri-plugin-passkey/` regenerates `permissions/autogenerated/` under the new id; delete stale files there.
- [ ] **Step 3: Verify:** `pnpm install` (lockfile updates for the renamed workspace package), `pnpm build`, `pnpm test:js`, `scripts/test-macos.sh`, `cd test-app/src-tauri && cargo check`, `cd tauri-plugin-passkey && cargo package --allow-dirty`, `pnpm verify:package`.
- [ ] **Step 4: Commit** `chore!: publish as tauri-plugin-dkackman-passkey / @dkackman/tauri-plugin-passkey-api`.

### Task 11: Documentation

**Files:**
- Modify: `tauri-plugin-passkey/README.md`, `CLAUDE.md`, `tauri-plugin-passkey/macos/README.md`, `tauri-plugin-passkey/ios/README.md`, `tauri-plugin-passkey/android/README.md`, `README.md` (root), `test-app/README.md` if present.

- [ ] **Step 1:** Read `git log main..review-fixes` and the current code; then update: install snippets (new names, permission `dkackman-passkey:default`, Rust path); Platform support table (Linux is USB CTAP2 only, not "platform authenticator"; Apple maps userVerification/attachment/attestation, PRF pre-checked on macOS <15 / iOS <18); a new **Security model** section explaining that on Linux/Windows the webview supplies the origin and that `plugins.dkackman-passkey.allowedOrigins` in `tauri.conf.json` pins it, with the JSON snippet; Errors section listing the eight kinds with one line each; PRF section: legacy `hmacGetSecret`/`hmacCreateSecret` and `evalByCredential` are rejected with `unsupported`, padded salts accepted; Timeout paragraph (`timeout` argument, then `options.timeout`, then 60000; enforced on every platform); Concurrency paragraph (`busy`); Release flow note about the first manual publish of the scoped package. CLAUDE.md "Naming" section gets the new crate/npm/plugin-id names and the unchanged native class names; CLAUDE.md "Building and testing" notes the swift-rs link fallback.
- [ ] **Step 2:** `pnpm format`; `git diff --stat` shows only docs. Commit `docs: update for 0.3.0 contract, security model, and new package names`.

## Self-review notes

- Spec coverage: every review finding maps to a task except two deliberately deferred: the public-suffix-list check in `validate_rp_id` (already documented as a trade-off) and the `supports_prf()` trait hook, replaced by native pre-ceremony checks in Tasks 8–9 plus the existing Windows `reject_prf`.
- Type consistency: `Error::Cancelled`/`Error::Busy` (Task 1) are used by Tasks 5, 7, 8, 9; `base64url::{decode,encode}` (Task 1) by Tasks 3, 9; `bridge_options` (Task 9) is adopted by `mobile.rs` in a coordinator follow-up after Task 7 lands.
- Conflict map: Task 7 owns `mobile.rs`; Task 9 owns `macos.rs`; Stream A never touches either. Task 4 and Task 6 both edit `commands.rs`, so Stream A runs its tasks sequentially in one agent.
