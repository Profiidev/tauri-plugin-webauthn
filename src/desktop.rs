use std::{
  fmt::Debug,
  sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex,
  },
};

use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Emitter, Runtime, Url};
use tokio::task::block_in_place;
use webauthn_authenticator_rs::{ui::UiCallback, AuthenticatorBackend};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

use crate::{FingerprintEnrollmentFeedback, WebauthnEvent};

pub const EVENT_NAME: &str = "tauri-plugin-webauthn";

pub fn init<R: Runtime, C: DeserializeOwned>(
  app: &AppHandle<R>,
  _api: PluginApi<R, C>,
) -> crate::Result<Webauthn<R>> {
  let (pin_sender, pin_receiver) = channel();
  Ok(Webauthn {
    app: app.clone(),
    pin_receiver: Mutex::new(pin_receiver),
    pin_sender,
  })
}

/// Access to the webauthn APIs.
#[derive(Debug)]
pub struct Webauthn<R: Runtime> {
  app: AppHandle<R>,
  pin_receiver: Mutex<Receiver<String>>,
  pin_sender: Sender<String>,
}

impl<R: Runtime> Webauthn<R> {
  pub async fn register(
    &self,
    origin: Url,
    options: PublicKeyCredentialCreationOptions,
  ) -> crate::Result<RegisterPublicKeyCredential> {
    let mut auth = select_transport(self).await?;
    auth.perform_register(origin, options, 1000).map_err(|e| {
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

  pub fn send_pin(&self, pin: String) {
    #[cfg(feature = "log")]
    let _ = self.pin_sender.send(pin);
  }
}

impl<R: Runtime> UiCallback for Webauthn<R> {
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
    let _ = self.app.emit(
      EVENT_NAME,
      WebauthnEvent::FingerprintEnrollmentFeedback(FingerprintEnrollmentFeedback {
        remaining_samples,
        feedback: feedback.map(|f| f as u8),
      }),
    );
  }

  fn processing(&self) {
    #[cfg(feature = "log")]
    log::debug!("Processing...");
    let _ = self.app.emit(EVENT_NAME, WebauthnEvent::Processing);
  }

  fn request_pin(&self) -> Option<String> {
    #[cfg(feature = "log")]
    log::debug!("Requesting PIN...");
    let _ = self.app.emit(EVENT_NAME, WebauthnEvent::RequestPin);

    block_in_place(|| {
      let receiver = self.pin_receiver.lock().unwrap();
      receiver.recv().ok()
    })
  }

  fn request_touch(&self) {
    #[cfg(feature = "log")]
    log::debug!("Requesting touch...");
    let _ = self.app.emit(EVENT_NAME, WebauthnEvent::RequestTouch);
  }

  fn cable_qr_code(&self, _: webauthn_authenticator_rs::types::CableRequestType, _: String) {}
  fn cable_status_update(&self, _: webauthn_authenticator_rs::types::CableState) {}
  fn dismiss_qr_code(&self) {}
}

#[cfg(not(windows))]
async fn select_transport<U: UiCallback>(
  ui: &'_ U,
) -> crate::Result<impl AuthenticatorBackend + '_> {
  use futures::StreamExt;
  use webauthn_authenticator_rs::{
    ctap2::CtapAuthenticator,
    transport::{AnyTransport, TokenEvent, Transport},
  };

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

#[cfg(windows)]
async fn select_transport<U: UiCallback>(
  _ui: &'_ U,
) -> crate::Result<impl AuthenticatorBackend + '_> {
  Ok(webauthn_authenticator_rs::win10::Win10::default())
}
