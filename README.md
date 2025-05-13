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

### Android

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
- A `keystore.properties` file in the `src-tauri/gen/android/app` directory. This is required to sign the app. The documentation for this file can be found [here](https://tauri.app/distribute/sign/android/)
- Additionally you need to define a `assetslink.json` and this needs to be hosted under a domain you own. This is required to verify the app with the webauthn api. The documentation for this file can be found [here](https://developer.android.com/identity/sign-in/credential-manager#add-support-dal) and the file can be generated [here](https://developers.google.com/digital-asset-links/tools/generator). This also needs to be included in you app manifest file at `src-tauri/gen/android/app/src/main/AndroidManifest.xml`:
  ```xml
  ...
  <application>
    ...
    <meta-data android:name="asset_statements" android:resource="@string/asset_statements" />
    ...
  </application>
  ...
  ```
  and the string resource needs to be defined in `src-tauri/gen/android/app/src/main/res/values/strings.xml`:
  ```xml
  <resources>
    ...
    <string name="asset_statements" translatable="false">
    [{
    \"include\": \"https://your.domain.com/.well-known/assetlinks.json\"
    }]
    </string>
    ...
  </resources>
  ```

# Usage

This plugin provides 3 methods and 1 event handler. The `register` and `authenticate` methods can be used nearly identically to the `@simplewebauthn/browser`. The biggest difference is the `sendPint` method and the event handler
which is only required on Linux (Windows and Android handle the pin natively which means no events will be sent on those platforms and the pin method does nothing).
An example can be found in the `examples/webauthn` directory. It works on all supported platforms.
