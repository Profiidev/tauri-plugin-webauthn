use tauri::Url;
use tauri::{command, AppHandle, Runtime};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

use crate::PasskeyExt;
use crate::Result;

#[command]
pub(crate) async fn register<R: Runtime>(
  app: AppHandle<R>,
  origin: Url,
  options: PublicKeyCredentialCreationOptions,
) -> Result<RegisterPublicKeyCredential> {
  app.passkey().register(origin, options).await
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
  app: AppHandle<R>,
  origin: Url,
  options: PublicKeyCredentialRequestOptions,
) -> Result<PublicKeyCredential> {
  app.passkey().authenticate(origin, options).await
}
