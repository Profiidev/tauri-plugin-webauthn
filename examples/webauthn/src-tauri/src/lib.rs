use serde::Serialize;
use tauri::{
  async_runtime::{spawn, Mutex},
  Manager, State,
};
use tauri_plugin_http::reqwest::Client;
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

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
async fn reg_start(
  client: State<'_, Mutex<Client>>,
  name: &str,
) -> Result<PublicKeyCredentialCreationOptions, ()> {
  let client = client.lock().await;
  Ok(
    client
      .post("https://webauthn.io/registration/options")
      .json(&RegBody {
        username: name.to_string(),
        hints: vec![],
        user_verification: "preferred".into(),
        discoverable_credential: "discouraged".into(),
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
async fn reg_finish(
  client: State<'_, Mutex<Client>>,
  username: String,
  response: RegisterPublicKeyCredential,
) -> Result<(), ()> {
  let client = client.lock().await;
  client
    .post("https://webauthn.io/registration/verification")
    .json(&RegFinishBody { username, response })
    .send()
    .await
    .expect("Failed to send request");
  Ok(())
}

#[derive(Serialize)]
struct AuthBody {
  hints: Vec<String>,
  user_verification: String,
  username: String,
}

#[derive(Serialize)]
struct AuthFinishBody {
  username: String,
  response: PublicKeyCredential,
}

#[tauri::command]
async fn auth_start(
  client: State<'_, Mutex<Client>>,
  name: &str,
) -> Result<PublicKeyCredentialRequestOptions, ()> {
  let client = client.lock().await;
  Ok(
    client
      .post("https://webauthn.io/authentication/options")
      .json(&AuthBody {
        hints: vec![],
        user_verification: "preferred".into(),
        username: name.to_string(),
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
async fn auth_finish(
  client: State<'_, Mutex<Client>>,
  username: String,
  response: PublicKeyCredential,
) -> Result<(), ()> {
  let client = client.lock().await;
  client
    .post("https://webauthn.io/authentication/verification")
    .json(&AuthFinishBody { username, response })
    .send()
    .await
    .expect("Failed to send request");
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .manage(Mutex::new(
      Client::builder().cookie_store(true).build().unwrap(),
    ))
    .plugin(tauri_plugin_http::init())
    .plugin(tauri_plugin_log::Builder::new().build())
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_webauthn::init())
    .invoke_handler(tauri::generate_handler![
      reg_start,
      reg_finish,
      auth_start,
      auth_finish
    ])
    .setup(|app| {
      let handle = app.handle().clone();
      spawn(async move {
        // get session cookie
        let state = handle.state::<Mutex<Client>>();
        let client = state.lock().await;
        let _ = client.get("https://webauthn.io").send().await;
      });
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
