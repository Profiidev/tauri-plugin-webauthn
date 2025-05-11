use serde::Serialize;
use tauri_plugin_http::reqwest::Client;
use webauthn_rs_proto::{PublicKeyCredentialCreationOptions, RegisterPublicKeyCredential};

#[derive(Serialize)]
struct RegBody {
  username: String,
  hints: Vec<String>,
  user_verification: String,
  discoverable_credential: String,
  attestation: String,
  attachment: String,
  algorithms: Vec<String>,
}

#[derive(Serialize)]
struct RegFinishBody {
  username: String,
  response: RegisterPublicKeyCredential,
}

#[tauri::command]
async fn reg_start(name: &str) -> Result<PublicKeyCredentialCreationOptions, ()> {
  let client = Client::new();
  Ok(
    client
      .post("https://webauthn.io/registration/options")
      .json(&RegBody {
        username: name.to_string(),
        hints: vec![],
        user_verification: "preferred".into(),
        discoverable_credential: "preferred".into(),
        attestation: "none".into(),
        attachment: "all".into(),
        algorithms: vec!["ed25519".into(), "es256".into(), "rs256".into()],
      })
      .send()
      .await
      .expect("Failed to send request")
      .json()
      .await
      .expect("Failed to parse response"),
  )
}

#[tauri::command]
async fn reg_finish(username: String, response: RegisterPublicKeyCredential) -> Result<(), ()> {
  let client = Client::new();
  client
    .post("https://webauthn.io/registration/verification")
    .json(&RegFinishBody { username, response })
    .send()
    .await
    .expect("Failed to send request");
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_http::init())
    .plugin(tauri_plugin_log::Builder::new().build())
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_webauthn::init())
    .invoke_handler(tauri::generate_handler![reg_start, reg_finish])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
