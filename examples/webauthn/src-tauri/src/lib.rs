use std::{collections::HashMap, vec};

use chrono::Local;
use tauri::{async_runtime::Mutex, State, Url};
use tauri_plugin_log::{RotationStrategy, Target, TargetKind, TimezoneStrategy};
use webauthn_rs::{
  prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration, Uuid},
  Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

#[tauri::command]
async fn reg_start(
  state: State<'_, Mutex<HashMap<String, PasskeyRegistration>>>,
  passkeys: State<'_, Mutex<HashMap<String, Passkey>>>,
  webauthn: State<'_, Webauthn>,
  name: &str,
) -> Result<PublicKeyCredentialCreationOptions, ()> {
  let passkeys = passkeys.lock().await;
  let passkey = passkeys.get(name).map(|p| vec![p.cred_id().clone()]);

  let (challenge, state_val) = webauthn
    .start_passkey_registration(Uuid::new_v4(), name, name, passkey)
    .expect("Failed to start registration");

  let mut state = state.lock().await;
  state.insert(name.to_string(), state_val);

  Ok(challenge.public_key)
}

#[tauri::command]
async fn reg_finish(
  state: State<'_, Mutex<HashMap<String, PasskeyRegistration>>>,
  passkeys: State<'_, Mutex<HashMap<String, Passkey>>>,
  webauthn: State<'_, Webauthn>,
  name: &str,
  response: RegisterPublicKeyCredential,
) -> Result<(), ()> {
  let mut state = state.lock().await;
  let passkey_reg = state
    .remove(name)
    .expect("Failed to get passkey registration state");

  let passkey = webauthn
    .finish_passkey_registration(&response, &passkey_reg)
    .expect("Failed to finish registration");

  let mut passkeys = passkeys.lock().await;
  passkeys.insert(name.to_string(), passkey.clone());

  Ok(())
}

#[tauri::command]
async fn auth_start(
  webauthn: State<'_, Webauthn>,
  state: State<'_, Mutex<HashMap<String, PasskeyAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<String, Passkey>>>,
  name: &str,
) -> Result<PublicKeyCredentialRequestOptions, ()> {
  let passkeys = passkeys.lock().await;
  let passkey = passkeys.get(name).expect("Failed to get passkey").clone();

  let (challenge, state_val) = webauthn
    .start_passkey_authentication(&[passkey])
    .expect("Failed to start authentication");

  let mut state = state.lock().await;
  state.insert(name.to_string(), state_val);

  Ok(challenge.public_key)
}

#[tauri::command]
async fn auth_finish(
  webauthn: State<'_, Webauthn>,
  state: State<'_, Mutex<HashMap<String, PasskeyAuthentication>>>,
  name: &str,
  response: PublicKeyCredential,
) -> Result<(), ()> {
  let mut state = state.lock().await;
  let passkey_auth = state
    .remove(name)
    .expect("Failed to get passkey authentication state");
  webauthn
    .finish_passkey_authentication(&response, &passkey_auth)
    .expect("Failed to finish authentication");
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .manage(
      WebauthnBuilder::new("localhost", &Url::parse("http://localhost:5173/").unwrap())
        .unwrap()
        .build()
        .unwrap(),
    )
    .manage(Mutex::new(HashMap::<String, PasskeyAuthentication>::new()))
    .manage(Mutex::new(HashMap::<String, PasskeyRegistration>::new()))
    .manage(Mutex::new(HashMap::<String, Passkey>::new()))
    .plugin(
      tauri_plugin_log::Builder::new()
        .clear_targets()
        .target(Target::new(TargetKind::Stdout))
        .target(Target::new(TargetKind::LogDir {
          file_name: Some(Local::now().to_rfc3339().replace(":", "-")),
        }))
        .rotation_strategy(RotationStrategy::KeepAll)
        .timezone_strategy(TimezoneStrategy::UseLocal)
        .build(),
    )
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_webauthn::init())
    .invoke_handler(tauri::generate_handler![
      reg_start,
      reg_finish,
      auth_start,
      auth_finish
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
