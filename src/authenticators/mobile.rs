use serde::de::DeserializeOwned;
use tauri::{
  plugin::{PluginApi, PluginHandle},
  AppHandle, Runtime, Url,
};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential, ResidentKeyRequirement,
};

use super::Authenticator;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_webauthn);

/// Access to the webauthn APIs.
pub struct Webauthn<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Authenticator<R> for Webauthn<R> {
  fn init<C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<Self> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("de.plugin.webauthn", "WebauthnPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_webauthn)?;
    Ok(Webauthn(handle))
  }

  fn register(
    &self,
    _origin: Url,
    mut options: PublicKeyCredentialCreationOptions,
    _timeout: u32,
  ) -> crate::Result<RegisterPublicKeyCredential> {
    // This is required to make Android save the passkey
    if let Some(auth) = &mut options.authenticator_selection {
      auth.resident_key = Some(ResidentKeyRequirement::Preferred);
    }
    self
      .0
      .run_mobile_plugin("register", serde_json::to_string(&options)?)
      .map_err(Into::into)
  }

  fn authenticate(
    &self,
    _origin: Url,
    options: PublicKeyCredentialRequestOptions,
    _timeout: u32,
  ) -> crate::Result<PublicKeyCredential> {
    self
      .0
      .run_mobile_plugin("authenticate", serde_json::to_string(&options)?)
      .map_err(Into::into)
  }
}
