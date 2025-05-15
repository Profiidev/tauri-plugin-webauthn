const COMMANDS: &[&str] = &[
  "register",
  "authenticate",
  "send_pin",
  "select_key",
  "cancel",
];

fn main() {
  tauri_plugin::Builder::new(COMMANDS)
    .android_path("android")
    .ios_path("ios")
    .build();
}
