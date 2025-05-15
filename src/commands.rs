use tauri::Url;
use tauri::{command, AppHandle, Runtime};
use tokio::task::block_in_place;
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

use crate::authenticators::Authenticator;
use crate::Result;
use crate::WebauthnExt;

const DEFAULT_TIMEOUT: u32 = 60_000;

#[command]
pub(crate) async fn register<R: Runtime>(
  app: AppHandle<R>,
  origin: Url,
  options: PublicKeyCredentialCreationOptions,
  timeout: Option<u32>,
) -> Result<RegisterPublicKeyCredential> {
  block_in_place(|| {
    app
      .webauthn()
      .register(origin, options, timeout.unwrap_or(DEFAULT_TIMEOUT))
      .log()
  })
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
  app: AppHandle<R>,
  origin: Url,
  options: PublicKeyCredentialRequestOptions,
  timeout: Option<u32>,
) -> Result<PublicKeyCredential> {
  block_in_place(|| {
    app
      .webauthn()
      .authenticate(origin, options, timeout.unwrap_or(DEFAULT_TIMEOUT))
      .log()
  })
}

#[command]
pub(crate) async fn send_pin<R: Runtime>(app: AppHandle<R>, pin: String) {
  app.webauthn().send_pin(pin);
}

#[command]
pub(crate) async fn select_key<R: Runtime>(app: AppHandle<R>, key: usize) {
  app.webauthn().select_key(key);
}

#[command]
pub(crate) async fn cancel<R: Runtime>(app: AppHandle<R>) {
  app.webauthn().cancel();
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
