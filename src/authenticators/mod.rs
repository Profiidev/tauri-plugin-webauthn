use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, Url};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

#[cfg(all(desktop, target_os = "linux"))]
pub mod ctap2;
#[cfg(all(desktop, windows))]
pub mod windows;

pub trait Authenticator<R: Runtime>: Sized {
  fn init<C: DeserializeOwned>(app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<Self>;
  fn register(
    &self,
    origin: Url,
    options: PublicKeyCredentialCreationOptions,
  ) -> crate::Result<RegisterPublicKeyCredential>;
  fn authenticate(
    &self,
    origin: Url,
    options: PublicKeyCredentialRequestOptions,
  ) -> crate::Result<PublicKeyCredential>;
  fn send_pin(&self, pin: String) {
    #[cfg(feature = "log")]
    log::warn!("send_pin is not implemented/required for this authenticator");
    let _ = pin;
  }
  fn select_key(&self, key: usize) {
    #[cfg(feature = "log")]
    log::warn!("select_key is not implemented/required for this authenticator");
    let _ = key;
  }
  fn cancel(&self) {
    #[cfg(feature = "log")]
    log::warn!("cancel is not implemented/required for this authenticator");
  }
}
