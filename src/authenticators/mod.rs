use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, Url};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

#[cfg(desktop)]
pub mod ctap2;

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
  fn send_pin(&self, pin: String);
  fn select_key(&self, key: usize);
  fn cancel(&self);
}
