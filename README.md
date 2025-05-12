# Tauri Plugin Webauthn

A tauri plugin to interact with the system specific fido2 or webauthn api.
It is a nearly drop-in replacement for the `@simplewebauthn/browser` package with the only additional requirement being the origin url to pass to the register and authenticate methods.

| Platform | Supported |
| -------- | --------- |
| Linux    | ✓         |
| Windows  | ✓         |
| macOS    | x         |
| Android  | x         |
| iOS      | x         |
