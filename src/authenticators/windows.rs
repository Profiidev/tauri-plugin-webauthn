use std::{fmt::Debug, marker::PhantomData};

use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, Url};
use webauthn_authenticator_rs::{win10::Win10, AuthenticatorBackend};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

use super::Authenticator;

/// Access to the webauthn APIs.
#[derive(Debug)]
pub struct Webauthn<R: Runtime> {
  phantom: PhantomData<AppHandle<R>>,
}

impl<R: Runtime> Authenticator<R> for Webauthn<R> {
  fn init<C: DeserializeOwned>(_app: &AppHandle<R>, _api: PluginApi<R, C>) -> crate::Result<Self> {
    Ok(Webauthn {
      phantom: PhantomData,
    })
  }

  fn register(
    &self,
    origin: Url,
    options: PublicKeyCredentialCreationOptions,
  ) -> crate::Result<RegisterPublicKeyCredential> {
    let mut auth = Win10::default();
    auth.perform_register(origin, options, 1000).map_err(|e| {
      #[cfg(feature = "log")]
      log::error!("Failed to register: {:?}", e);
      crate::Error::WebAuthn(e)
    })
  }

  fn authenticate(
    &self,
    origin: Url,
    options: PublicKeyCredentialRequestOptions,
  ) -> crate::Result<PublicKeyCredential> {
    let mut auth = Win10::default();
    auth.perform_auth(origin, options, 0).map_err(|e| {
      #[cfg(feature = "log")]
      log::error!("Failed to authenticate: {:?}", e);
      crate::Error::WebAuthn(e)
    })
  }
}
