use std::{collections::HashMap, env, fmt::Debug, path::PathBuf};

use chrono::Local;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::Mutex, AppHandle, Manager, State, Url};

/// Logs an error and converts it to a String for returning to the frontend.
trait LogErr<T> {
    fn log_err(self, msg: &str) -> Result<T, String>;
}

impl<T, E: Debug> LogErr<T> for Result<T, E> {
    fn log_err(self, msg: &str) -> Result<T, String> {
        self.map_err(|e| {
            let err = format!("{msg}: {e:?}");
            log::error!("{err}");
            err
        })
    }
}

trait LogNone<T> {
    fn log_none(self, msg: &str) -> Result<T, String>;
}

impl<T> LogNone<T> for Option<T> {
    fn log_none(self, msg: &str) -> Result<T, String> {
        self.ok_or_else(|| {
            log::error!("{msg}");
            msg.to_string()
        })
    }
}

const DEFAULT_RP_ID: &str = "webauthn.dkackman.com";
const DEFAULT_RP_ORIGIN: &str = "https://webauthn.dkackman.com/";

fn rp_id() -> String {
    env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| DEFAULT_RP_ID.to_string())
}

fn rp_origin() -> String {
    env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| DEFAULT_RP_ORIGIN.to_string())
}

// On Android, Credential Manager sets clientDataJSON.origin to
// `android:apk-key-hash:<base64url(SHA-256(signing cert DER))>` rather than the web
// origin, so that value has to be an allowed origin here or verification fails with
// InvalidRPOrigin after the biometric prompt has already succeeded. It differs per
// developer keystore — override with PASSKEY_APK_KEY_HASH. The default is the standard
// Android debug keystore (`~/.android/debug.keystore`), which is also the fingerprint
// published in webauthn.dkackman.com's assetlinks.json. Derive your own with
// `keytool -list -v -keystore <keystore> | grep SHA256`, then base64url-encode those
// 32 bytes without padding.
fn apk_key_hash() -> String {
    env::var("PASSKEY_APK_KEY_HASH").unwrap_or_else(|_| {
        "android:apk-key-hash:ACDefg1Oe_Oghhc1udjQbgeC9Za9h_fyf9vjJaBx-VI".to_string()
    })
}

#[derive(Clone, Serialize, Deserialize)]
struct RpConfig {
    rp_id: String,
    rp_origin: String,
}

/// The persisted RP-side state for one RP ID: registered users and their
/// passkeys (public keys + counters only — nothing secret).
#[derive(Default, Serialize, Deserialize)]
struct RpStore {
    users: HashMap<String, Uuid>,
    passkeys: HashMap<Uuid, Vec<Passkey>>,
}

const STORE_FILE: &str = "passkey-store.json";

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .log_err("Failed to resolve app data dir")?;
    std::fs::create_dir_all(&dir).log_err("Failed to create app data dir")?;
    Ok(dir.join(STORE_FILE))
}

/// Passkeys are scoped to an RP, and the app can switch RP config at runtime,
/// so the file holds a store per RP ID.
fn read_all_stores(app: &AppHandle) -> HashMap<String, RpStore> {
    store_path(app)
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn load_rp_store(app: &AppHandle, rp_id: &str) -> RpStore {
    read_all_stores(app).remove(rp_id).unwrap_or_default()
}

fn save_rp_store(
    app: &AppHandle,
    rp_id: &str,
    users: &HashMap<String, Uuid>,
    passkeys: &HashMap<Uuid, Vec<Passkey>>,
) -> Result<(), String> {
    let mut all = read_all_stores(app);
    all.insert(
        rp_id.to_string(),
        RpStore {
            users: users.clone(),
            passkeys: passkeys.clone(),
        },
    );
    let json = serde_json::to_string_pretty(&all).log_err("Failed to serialize passkey store")?;
    std::fs::write(store_path(app)?, json).log_err("Failed to write passkey store")
}

fn build_webauthn(rp_id: &str, rp_origin: &str) -> Result<Webauthn, String> {
    let url = Url::parse(rp_origin).log_err("Invalid RP origin URL")?;
    let mut builder =
        WebauthnBuilder::new(rp_id, &url).log_err("Failed to create WebauthnBuilder")?;
    let android_origin = apk_key_hash();
    builder = builder.append_allowed_origin(
        &Url::parse(&android_origin).log_err("Invalid Android APK key hash URL")?,
    );

    builder.build().log_err("Failed to build Webauthn")
}

use tauri_plugin_log::{RotationStrategy, Target, TargetKind, TimezoneStrategy};
use webauthn_rs::{
    prelude::{
        DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration, Uuid,
    },
    Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
};

#[tauri::command]
async fn reg_start(
    state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
    passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
    webauthn: State<'_, Mutex<Webauthn>>,
    users: State<'_, Mutex<HashMap<String, Uuid>>>,
    name: &str,
    enable_prf: bool,
) -> Result<serde_json::Value, String> {
    let uuid = *users
        .lock()
        .await
        .entry(name.to_string())
        .or_insert(Uuid::new_v4());

    let existing_creds = passkeys
        .lock()
        .await
        .get(&uuid)
        .map(|p| p.iter().map(|p| p.cred_id().clone()).collect());

    let (challenge, state_val) = webauthn
        .lock()
        .await
        .start_passkey_registration(uuid, name, name, existing_creds)
        .log_err("Failed to start registration")?;

    state.lock().await.replace((state_val, uuid));

    let public_key = challenge.public_key;
    let mut options = serde_json::to_value(&public_key).log_err("Failed to serialize options")?;
    if enable_prf {
        options["extensions"] = serde_json::json!({ "prf": {} });
    }

    Ok(options)
}

#[tauri::command]
async fn reg_finish(
    app: AppHandle,
    state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
    passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
    users: State<'_, Mutex<HashMap<String, Uuid>>>,
    webauthn: State<'_, Mutex<Webauthn>>,
    config: State<'_, Mutex<RpConfig>>,
    response: RegisterPublicKeyCredential,
) -> Result<(), String> {
    let (passkey_reg, uuid) = state
        .lock()
        .await
        .take()
        .log_none("No pending registration. Did you call register first?")?;

    let passkey = webauthn
        .lock()
        .await
        .finish_passkey_registration(&response, &passkey_reg)
        .log_err("Failed to verify registration")?;

    let mut passkeys = passkeys.lock().await;
    passkeys.entry(uuid).or_default().push(passkey);

    let rp_id = config.lock().await.rp_id.clone();
    save_rp_store(&app, &rp_id, &*users.lock().await, &passkeys)?;

    Ok(())
}

/// Serializes `public_key` to the browser JSON shape and, if a first salt was
/// provided, attaches `extensions.prf.eval` for the plugin's browser PRF
/// contract. Shared by the discoverable and non-discoverable auth-start
/// commands.
fn options_with_prf_eval(
    public_key: &PublicKeyCredentialRequestOptions,
    salt1: Option<String>,
    salt2: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut options = serde_json::to_value(public_key).log_err("Failed to serialize options")?;
    if let Some(first) = salt1 {
        let mut eval = serde_json::json!({ "first": first });
        if let Some(second) = salt2 {
            eval["second"] = serde_json::json!(second);
        }
        options["extensions"] = serde_json::json!({ "prf": { "eval": eval } });
    }
    Ok(options)
}

#[tauri::command]
async fn auth_start(
    webauthn: State<'_, Mutex<Webauthn>>,
    state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
    salt1: Option<String>,
    salt2: Option<String>,
) -> Result<serde_json::Value, String> {
    let (challenge, state_val) = webauthn
        .lock()
        .await
        .start_discoverable_authentication()
        .log_err("Failed to start authentication")?;

    state.lock().await.replace(state_val);

    options_with_prf_eval(&challenge.public_key, salt1, salt2)
}

#[tauri::command]
async fn auth_start_non_discoverable(
    webauthn: State<'_, Mutex<Webauthn>>,
    users: State<'_, Mutex<HashMap<String, Uuid>>>,
    state: State<'_, Mutex<Option<PasskeyAuthentication>>>,
    passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
    name: &str,
    salt1: Option<String>,
    salt2: Option<String>,
) -> Result<serde_json::Value, String> {
    let uuid = *users
        .lock()
        .await
        .get(name)
        .log_none(&format!("User \"{name}\" not found. Register first."))?;

    let user_passkeys = passkeys
        .lock()
        .await
        .get(&uuid)
        .log_none("No passkey found for this user. Register first.")?
        .clone();

    let (challenge, state_val) = webauthn
        .lock()
        .await
        .start_passkey_authentication(&user_passkeys)
        .log_err("Failed to start authentication")?;

    state.lock().await.replace(state_val);

    options_with_prf_eval(&challenge.public_key, salt1, salt2)
}

#[derive(Serialize, Deserialize)]
struct PrfResults {
    first: String,
    second: Option<String>,
}

/// Pulls the browser PRF results out of `clientExtensionResults.prf.results`
/// before `response` is converted into `PublicKeyCredential` for signature
/// verification. Shared by the discoverable and non-discoverable auth-finish
/// commands.
///
/// Note: this field is NOT covered by the authenticator's signature per the
/// WebAuthn spec. On every backend (macOS/iOS's native bridge, Android's
/// Credential Manager, and Linux's direct CTAP2 authenticator) the plugin
/// constructs this from the platform-verified PRF output, so it is
/// trustworthy in practice. A tampered Tauri frontend could inject arbitrary
/// values here.
fn extract_prf_results(response: &serde_json::Value) -> Option<PrfResults> {
    response
        .get("clientExtensionResults")
        .and_then(|e| e.get("prf"))
        .and_then(|prf| prf.get("results"))
        .map(|results| PrfResults {
            first: results
                .get("first")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            second: results
                .get("second")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
}

#[tauri::command]
async fn auth_finish(
    app: AppHandle,
    webauthn: State<'_, Mutex<Webauthn>>,
    state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
    passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
    users: State<'_, Mutex<HashMap<String, Uuid>>>,
    config: State<'_, Mutex<RpConfig>>,
    response: serde_json::Value,
) -> Result<Option<PrfResults>, String> {
    let prf_results = extract_prf_results(&response);
    let response: PublicKeyCredential =
        serde_json::from_value(response).log_err("Invalid authentication response")?;

    let (user, cred_id) = webauthn
        .lock()
        .await
        .identify_discoverable_authentication(&response)
        .log_err("Failed to identify credential")?;

    let passkey = passkeys
        .lock()
        .await
        .get(&user)
        .and_then(|p| p.iter().find(|p| p.cred_id() == cred_id))
        .log_none("Passkey not found. You may need to register again.")?
        .clone();

    let passkey_auth = state
        .lock()
        .await
        .take()
        .log_none("No pending authentication. Did you call authenticate first?")?;

    let auth_result = webauthn
        .lock()
        .await
        .finish_discoverable_authentication(&response, passkey_auth, &[(&passkey).into()])
        .log_err("Failed to verify authentication")?;

    {
        let mut passkeys = passkeys.lock().await;
        if let Some(user_passkeys) = passkeys.get_mut(&user) {
            for passkey in user_passkeys.iter_mut() {
                passkey.update_credential(&auth_result);
            }
        }
        let rp_id = config.lock().await.rp_id.clone();
        save_rp_store(&app, &rp_id, &*users.lock().await, &passkeys)?;
    }

    Ok(prf_results)
}

#[tauri::command]
async fn auth_finish_non_discoverable(
    app: AppHandle,
    webauthn: State<'_, Mutex<Webauthn>>,
    state: State<'_, Mutex<Option<PasskeyAuthentication>>>,
    passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
    users: State<'_, Mutex<HashMap<String, Uuid>>>,
    config: State<'_, Mutex<RpConfig>>,
    response: serde_json::Value,
) -> Result<Option<PrfResults>, String> {
    let prf_results = extract_prf_results(&response);
    let response: PublicKeyCredential =
        serde_json::from_value(response).log_err("Invalid authentication response")?;

    let passkey_auth = state
        .lock()
        .await
        .take()
        .log_none("No pending authentication. Did you call authenticate first?")?;
    let auth_result = webauthn
        .lock()
        .await
        .finish_passkey_authentication(&response, &passkey_auth)
        .log_err("Failed to verify authentication")?;

    {
        let mut passkeys = passkeys.lock().await;
        for user_passkeys in passkeys.values_mut() {
            for passkey in user_passkeys.iter_mut() {
                passkey.update_credential(&auth_result);
            }
        }
        let rp_id = config.lock().await.rp_id.clone();
        save_rp_store(&app, &rp_id, &*users.lock().await, &passkeys)?;
    }

    Ok(prf_results)
}

#[tauri::command]
async fn get_rp_config(config: State<'_, Mutex<RpConfig>>) -> Result<RpConfig, String> {
    Ok(config.lock().await.clone())
}

#[tauri::command]
async fn set_rp_config(
    app: AppHandle,
    webauthn: State<'_, Mutex<Webauthn>>,
    config: State<'_, Mutex<RpConfig>>,
    passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
    users: State<'_, Mutex<HashMap<String, Uuid>>>,
    rp_id: String,
    rp_origin: String,
) -> Result<(), String> {
    let new_webauthn = build_webauthn(&rp_id, &rp_origin)?;
    *webauthn.lock().await = new_webauthn;

    // The store on disk is written after every mutation, so on an RP switch we
    // only need to swap in the persisted state for the new RP ID.
    let store = load_rp_store(&app, &rp_id);
    *users.lock().await = store.users;
    *passkeys.lock().await = store.passkeys;

    *config.lock().await = RpConfig { rp_id, rp_origin };
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Load .env from the example root (parent of src-tauri)
    let _ = dotenvy::from_filename("../.env");
    let rp_id = rp_id();
    let rp_origin = rp_origin();
    log::info!("Using RP ID: {rp_id}, Origin: {rp_origin}");

    let webauthn = build_webauthn(&rp_id, &rp_origin).expect("Failed to build Webauthn");

    let initial_rp_id = rp_id.clone();
    tauri::Builder::default()
        .manage(Mutex::new(webauthn))
        .manage(Mutex::new(RpConfig { rp_id, rp_origin }))
        .manage(Mutex::new(Option::<DiscoverableAuthentication>::None))
        .manage(Mutex::new(Option::<PasskeyAuthentication>::None))
        .manage(Mutex::new(Option::<(PasskeyRegistration, Uuid)>::None))
        .setup(move |app| {
            let store = load_rp_store(app.handle(), &initial_rp_id);
            app.manage(Mutex::new(store.passkeys));
            app.manage(Mutex::new(store.users));
            Ok(())
        })
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
        .plugin(tauri_plugin_passkey::init())
        .invoke_handler(tauri::generate_handler![
            reg_start,
            reg_finish,
            auth_start,
            auth_finish,
            auth_start_non_discoverable,
            auth_finish_non_discoverable,
            get_rp_config,
            set_rp_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    /// The Android origin the local verifier allows has to be derived from the same
    /// signing cert that webauthn.dkackman.com's assetlinks.json publishes — otherwise
    /// Credential Manager happily creates the credential and `finish_passkey_registration`
    /// then rejects it with `InvalidRPOrigin`.
    #[test]
    fn default_apk_key_hash_matches_published_assetlinks_fingerprint() {
        // 00:20:DE:7E:0D:4E:7B:F3:A0:86:17:35:B9:D8:D0:6E:
        // 07:82:F5:96:BD:87:F7:F2:7F:DB:E3:25:A0:71:F9:52
        const ASSETLINKS_SHA256: [u8; 32] = [
            0x00, 0x20, 0xDE, 0x7E, 0x0D, 0x4E, 0x7B, 0xF3, 0xA0, 0x86, 0x17, 0x35, 0xB9, 0xD8,
            0xD0, 0x6E, 0x07, 0x82, 0xF5, 0x96, 0xBD, 0x87, 0xF7, 0xF2, 0x7F, 0xDB, 0xE3, 0x25,
            0xA0, 0x71, 0xF9, 0x52,
        ];

        // The literal, not apk_key_hash(): tests share a process, so don't mutate the env.
        let default = "android:apk-key-hash:ACDefg1Oe_Oghhc1udjQbgeC9Za9h_fyf9vjJaBx-VI";
        let b64 = default.strip_prefix("android:apk-key-hash:").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(b64).unwrap(), ASSETLINKS_SHA256);
    }

    #[test]
    fn build_webauthn_allows_the_android_apk_origin() {
        let webauthn = build_webauthn(DEFAULT_RP_ID, DEFAULT_RP_ORIGIN).unwrap();
        let android = Url::parse(&apk_key_hash()).unwrap();
        assert!(webauthn.get_allowed_origins().contains(&android));
    }
}
