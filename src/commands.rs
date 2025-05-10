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
  app.webauthn().register(origin, options).await
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
  app: AppHandle<R>,
  origin: Url,
  options: PublicKeyCredentialRequestOptions,
) -> Result<PublicKeyCredential> {
  app.webauthn().authenticate(origin, options).await
}
