use std::{collections::HashMap, vec};

use chrono::Local;
use tauri::{async_runtime::Mutex, State, Url};
use tauri_plugin_log::{RotationStrategy, Target, TargetKind, TimezoneStrategy};
use webauthn_rs::{
  prelude::{DiscoverableAuthentication, Passkey, PasskeyRegistration, Uuid},
  Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

#[tauri::command]
async fn reg_start(
  state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  webauthn: State<'_, Webauthn>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  name: &str,
) -> Result<PublicKeyCredentialCreationOptions, ()> {
  let mut users = users.lock().await;
  let uuid = users.entry(name.to_string()).or_insert(Uuid::new_v4());

  let passkeys = passkeys.lock().await;
  let passkey = passkeys
    .get(uuid)
    .map(|p| p.iter().map(|p| p.cred_id().clone()).collect());

  let (challenge, state_val) = webauthn
    .start_passkey_registration(*uuid, name, name, passkey)
    .expect("Failed to start registration");

  let mut state = state.lock().await;
  state.replace((state_val, *uuid));

  Ok(challenge.public_key)
}

#[tauri::command]
async fn reg_finish(
  state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  webauthn: State<'_, Webauthn>,
  response: RegisterPublicKeyCredential,
) -> Result<(), ()> {
  let mut state = state.lock().await;
  let (passkey_reg, uuid) = state
    .take()
    .expect("Failed to get passkey registration state");

  let passkey = webauthn
    .finish_passkey_registration(&response, &passkey_reg)
    .expect("Failed to finish registration");

  let mut passkeys = passkeys.lock().await;
  let passkeys = passkeys.entry(uuid).or_default();
  passkeys.push(passkey);

  Ok(())
}

#[tauri::command]
async fn auth_start(
  webauthn: State<'_, Webauthn>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
) -> Result<PublicKeyCredentialRequestOptions, ()> {
  let (challenge, state_val) = webauthn
    .start_discoverable_authentication()
    .expect("Failed to start authentication");

  let mut state = state.lock().await;
  state.replace(state_val);

  Ok(challenge.public_key)
}

#[tauri::command]
async fn auth_finish(
  webauthn: State<'_, Webauthn>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  response: PublicKeyCredential,
) -> Result<(), ()> {
  let (user, cred_id) = webauthn
    .identify_discoverable_authentication(&response)
    .expect("Failed to identify authentication");

  let passkeys = passkeys.lock().await;
  let passkey = passkeys
    .get(&user)
    .and_then(|p| p.iter().find(|p| p.cred_id() == cred_id))
    .expect("Passkey not found");

  let mut state = state.lock().await;
  let passkey_auth = state
    .take()
    .expect("Failed to get passkey authentication state");
  webauthn
    .finish_discoverable_authentication(&response, passkey_auth, &[passkey.into()])
    .expect("Failed to finish authentication");
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .manage(
      WebauthnBuilder::new(
        "tauri-plugin-webauthn-example.glitch.me",
        &Url::parse("https://tauri-plugin-webauthn-example.glitch.me/").unwrap(),
      )
      .unwrap()
      .append_allowed_origin(
        &Url::parse("android:apk-key-hash:W8LAR3CdJ3CAVCTuv3_J5fF2iKYGYQhYfKq9ANbOzjI").unwrap(),
      )
      .build()
      .unwrap(),
    )
    .manage(Mutex::new(Option::<DiscoverableAuthentication>::None))
    .manage(Mutex::new(Option::<(PasskeyRegistration, Uuid)>::None))
    .manage(Mutex::new(HashMap::<Uuid, Vec<Passkey>>::new()))
    .manage(Mutex::new(HashMap::<String, Uuid>::new()))
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
