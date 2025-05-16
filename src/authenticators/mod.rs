use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, Url};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "windows")))]
pub mod ctap2;
#[cfg(all(desktop, windows))]
pub mod windows;

pub trait Authenticator<R: Runtime>: Sized {
  fn init<C: DeserializeOwned>(app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<Self>;
  /// Register a new webauthn credential.
  /// This is a blocking call and should be run in a separate thread.
  fn register(
    &self,
    origin: Url,
    options: PublicKeyCredentialCreationOptions,
    timeout: u32,
  ) -> crate::Result<RegisterPublicKeyCredential>;

  /// Authenticate using webauthn.
  /// This is a blocking call and should be run in a separate thread.
  fn authenticate(
    &self,
    origin: Url,
    options: PublicKeyCredentialRequestOptions,
    timeout: u32,
  ) -> crate::Result<PublicKeyCredential>;

  /// Send a PIN to the authenticator.
  /// This is only required for some authenticators.
  fn send_pin(&self, pin: String) {
    #[cfg(feature = "log")]
    log::warn!("send_pin is not implemented/required for this authenticator");
    let _ = pin;
  }

  /// Select a key from the authenticator.
  /// This is only required for some authenticators.
  fn select_key(&self, key: usize) {
    #[cfg(feature = "log")]
    log::warn!("select_key is not implemented/required for this authenticator");
    let _ = key;
  }

  /// Cancel the current operation.
  /// This is only supported by some authenticators.
  fn cancel(&self) {
    #[cfg(feature = "log")]
    log::warn!("cancel is not implemented/required for this authenticator");
  }
}
