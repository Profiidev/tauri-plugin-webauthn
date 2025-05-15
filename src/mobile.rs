use serde::de::DeserializeOwned;
use tauri::{
  plugin::{PluginApi, PluginHandle},
  AppHandle, Runtime, Url,
};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential, ResidentKeyRequirement,
};

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_webauthn);

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
  _app: &AppHandle<R>,
  api: PluginApi<R, C>,
) -> crate::Result<Webauthn<R>> {
  #[cfg(target_os = "android")]
  let handle = api.register_android_plugin("de.plugin.webauthn", "WebauthnPlugin")?;
  #[cfg(target_os = "ios")]
  let handle = api.register_ios_plugin(init_plugin_webauthn)?;
  Ok(Webauthn(handle))
}

/// Access to the webauthn APIs.
pub struct Webauthn<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Webauthn<R> {
  pub fn register(
    &self,
    _: Url,
    mut options: PublicKeyCredentialCreationOptions,
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

  pub fn authenticate(
    &self,
    _: Url,
    options: PublicKeyCredentialRequestOptions,
  ) -> crate::Result<PublicKeyCredential> {
    self
      .0
      .run_mobile_plugin("authenticate", serde_json::to_string(&options)?)
      .map_err(Into::into)
  }

  pub fn send_pin(&self, _: String) {}
}
