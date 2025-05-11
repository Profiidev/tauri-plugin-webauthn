use tauri::Url;
use tauri::{command, AppHandle, Runtime};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

use crate::Result;
use crate::WebauthnExt;

#[command]
pub(crate) async fn register<R: Runtime>(
  app: AppHandle<R>,
  origin: Url,
  options: PublicKeyCredentialCreationOptions,
) -> Result<RegisterPublicKeyCredential> {
  app.webauthn().register(origin, options).await.log()
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
  app: AppHandle<R>,
  origin: Url,
  options: PublicKeyCredentialRequestOptions,
) -> Result<PublicKeyCredential> {
  app.webauthn().authenticate(origin, options).await.log()
}

#[command]
pub(crate) fn send_pin<R: Runtime>(app: AppHandle<R>, pin: String) {
  app.webauthn().send_pin(pin);
}

trait ResultExt<T> {
  fn log(self) -> Self;
}

impl<T> ResultExt<T> for Result<T> {
  fn log(self) -> Self {
    if let Err(e) = &self {
      #[cfg(feature = "log")]
      log::error!("Error: {}", e);
    }
    self
  }
}
