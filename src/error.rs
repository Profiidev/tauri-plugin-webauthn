use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error(transparent)]
  Io(#[from] std::io::Error),
  #[cfg(mobile)]
  #[error(transparent)]
  PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
  #[cfg(desktop)]
  #[error("WebAuthn error: {0:?}")]
  WebAuthn(webauthn_authenticator_rs::error::WebauthnCError),
  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),
  #[error("No token found")]
  NoToken,
  #[error("Failed to create authenticator")]
  Authenticator,
  #[cfg(all(desktop, not(all(feature = "win_native", windows))))]
  #[error(transparent)]
  Ctap2(#[from] authenticator::errors::AuthenticatorError),
  #[cfg(all(desktop, not(all(feature = "win_native", windows))))]
  #[error(transparent)]
  Cbor2(#[from] serde_cbor_2::Error),
}

impl Serialize for Error {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(self.to_string().as_ref())
  }
}
