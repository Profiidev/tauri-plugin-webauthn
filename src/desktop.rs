use futures::StreamExt;
use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Emitter, Runtime, Url};
use webauthn_authenticator_rs::{
  ctap2::CtapAuthenticator,
  transport::{AnyTransport, TokenEvent, Transport},
  ui::UiCallback,
  AuthenticatorBackend,
};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

use crate::FingerprintEnrollmentFeedback;

pub fn init<R: Runtime, C: DeserializeOwned>(
  app: &AppHandle<R>,
  _api: PluginApi<R, C>,
) -> crate::Result<Passkey<R>> {
  Ok(Passkey(app.clone()))
}

/// Access to the passkey APIs.
#[derive(Debug)]
pub struct Passkey<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Passkey<R> {
  pub async fn register(
    &self,
    origin: Url,
    options: PublicKeyCredentialCreationOptions,
  ) -> crate::Result<RegisterPublicKeyCredential> {
    let mut auth = select_transport(self).await?;
    auth.perform_register(origin, options, 0).map_err(|e| {
      #[cfg(feature = "log")]
      log::error!("Failed to register: {:?}", e);
      crate::Error::WebAuthn(e)
    })
  }

  pub async fn authenticate(
    &self,
    origin: Url,
    options: PublicKeyCredentialRequestOptions,
  ) -> crate::Result<PublicKeyCredential> {
    let mut auth = select_transport(self).await?;
    auth.perform_auth(origin, options, 0).map_err(|e| {
      #[cfg(feature = "log")]
      log::error!("Failed to authenticate: {:?}", e);
      crate::Error::WebAuthn(e)
    })
  }
}

impl<R: Runtime> UiCallback for Passkey<R> {
  fn fingerprint_enrollment_feedback(
    &self,
    remaining_samples: u32,
    feedback: Option<webauthn_authenticator_rs::types::EnrollSampleStatus>,
  ) {
    #[cfg(feature = "log")]
    log::debug!(
      "Fingerprint enrollment feedback: remaining_samples = {}, feedback = {:?}",
      remaining_samples,
      feedback
    );
    if let Err(err) = self.0.emit(
      "webauthn|fingerprint_enrollment_feedback",
      FingerprintEnrollmentFeedback {
        remaining_samples,
        feedback: feedback.map(|f| f as u8),
      },
    ) {
      #[cfg(feature = "log")]
      log::error!("Failed to emit fingerprint enrollment feedback: {:?}", err);
      #[cfg(not(feature = "log"))]
      let _ = err;
    }
  }

  fn processing(&self) {
    #[cfg(feature = "log")]
    log::debug!("Processing...");
    if let Err(err) = self.0.emit("webauthn|processing", ()) {
      #[cfg(feature = "log")]
      log::error!("Failed to emit processing: {:?}", err);
      #[cfg(not(feature = "log"))]
      let _ = err;
    }
  }

  fn request_pin(&self) -> Option<String> {
    None
  }

  fn request_touch(&self) {
    #[cfg(feature = "log")]
    log::debug!("Requesting touch...");
    if let Err(err) = self.0.emit("webauthn|request_touch", ()) {
      #[cfg(feature = "log")]
      log::error!("Failed to emit request touch: {:?}", err);
      #[cfg(not(feature = "log"))]
      let _ = err;
    }
  }

  fn cable_qr_code(&self, _: webauthn_authenticator_rs::types::CableRequestType, _: String) {}
  fn cable_status_update(&self, _: webauthn_authenticator_rs::types::CableState) {}
  fn dismiss_qr_code(&self) {}
}

async fn select_transport<U: UiCallback>(
  ui: &'_ U,
) -> crate::Result<impl AuthenticatorBackend + '_> {
  let reader = AnyTransport::new().await.map_err(|e| {
    #[cfg(feature = "log")]
    log::error!("Failed to create transport: {:?}", e);
    crate::Error::WebAuthn(e)
  })?;
  let mut tokens = reader.watch().await.map_err(|e| {
    #[cfg(feature = "log")]
    log::error!("Failed to watch tokens: {:?}", e);
    crate::Error::WebAuthn(e)
  })?;

  while let Some(token) = tokens.next().await {
    match token {
      TokenEvent::Added(token) => {
        #[allow(clippy::unnecessary_lazy_evaluations)]
        let auth = CtapAuthenticator::new(token, ui).await.ok_or_else(|| {
          #[cfg(feature = "log")]
          log::error!("Failed to create authenticator");
          crate::Error::Authenticator
        })?;
        return Ok(auth);
      }
      TokenEvent::EnumerationComplete => {
        #[cfg(feature = "log")]
        log::error!("Enumeration complete, no token found");
        break;
      }
      TokenEvent::Removed(_) => {}
    }
  }

  #[cfg(feature = "log")]
  log::error!("No token found");
  Err(crate::Error::NoToken)
}
