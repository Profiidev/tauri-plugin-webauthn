# Tauri Plugin Webauthn

A tauri plugin to interact with the system specific fido2 or webauthn api.
It is a nearly drop-in replacement for the `@simplewebauthn/browser` package with the only additional requirement being the origin url to pass to the register and authenticate methods.

| Platform | Supported |
| -------- | --------- |
| Linux    | ✓         |
| Windows  | ✓         |
| macOS    | x         |
| Android  | ✓         |
| iOS      | x         |

## Requirements

- Android API 28+ (you need to set this in your project in `src-tauri/gen/android/app/build.gradle.kts`):
  ```
  ...
  android {
    ...
    defaultConfig {
      ...
      minSdk = 28
      ...
    }
    ...
  }
  ...
  ```

# Usage

This plugin provides 3 methods and 1 event handler. The `register` and `authenticate` methods can be used nearly identically to the `@simplewebauthn/browser`. The biggest difference is the `sendPint` method and the event handler
which is only required on Linux (Windows and Android handle the pin natively which means no events will be sent on those platforms and the pin method does nothing).
An example can be found in the `examples/webauthn` directory. It works on all supported platforms.
