use std::{
  marker::PhantomData,
  sync::{mpsc::Sender, Mutex},
};

use authenticator::{authenticatorservice::AuthenticatorService, Pin, StatusUpdate};
use ctap2::AuthenticatorExt;
use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, Url};
use tokio::sync::mpsc;
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

mod ctap2;

pub const EVENT_NAME: &str = "tauri-plugin-webauthn";

pub fn init<R: Runtime, C: DeserializeOwned>(
  app: &AppHandle<R>,
  _api: PluginApi<R, C>,
) -> crate::Result<Webauthn<R>> {
  let (pin_sender, pin_receiver) = mpsc::channel(100000);
  let (select_sender, select_receiver) = mpsc::channel(100000);
  Ok(Webauthn {
    manager: Mutex::new(ctap2::init_manager()?),
    status_tx: ctap2::status(app.clone(), pin_sender, select_sender),
    pin_receiver: Mutex::new(pin_receiver),
    select_receiver: Mutex::new(select_receiver),
    phantom: PhantomData,
  })
}

/// Access to the webauthn APIs.
pub struct Webauthn<R: Runtime> {
  manager: Mutex<AuthenticatorService>,
  status_tx: Sender<StatusUpdate>,
  pin_receiver: Mutex<mpsc::Receiver<Sender<Pin>>>,
  select_receiver: Mutex<mpsc::Receiver<Sender<Option<usize>>>>,
  phantom: PhantomData<AppHandle<R>>,
}

impl<R: Runtime> Webauthn<R> {
  pub fn register(
    &self,
    origin: Url,
    options: PublicKeyCredentialCreationOptions,
  ) -> crate::Result<RegisterPublicKeyCredential> {
    let mut manager = self.manager.lock().unwrap();
    manager
      .perform_register(self.status_tx.clone(), origin, options, 10000)
      .map_err(|e| {
        #[cfg(feature = "log")]
        log::error!("Failed to register: {:?}", e);
        e
      })
  }

  pub fn authenticate(
    &self,
    origin: Url,
    options: PublicKeyCredentialRequestOptions,
  ) -> crate::Result<PublicKeyCredential> {
    let mut manager = self.manager.lock().unwrap();
    manager
      .perform_authentication(self.status_tx.clone(), origin, options, 10000)
      .map_err(|e| {
        #[cfg(feature = "log")]
        log::error!("Failed to authenticate: {:?}", e);
        e
      })
  }

  pub fn send_pin(&self, pin: String) {
    let mut last_sender = None;
    while let Ok(sender) = self.pin_receiver.lock().unwrap().try_recv() {
      last_sender = Some(sender);
    }
    if let Some(sender) = last_sender {
      let _ = sender.send(Pin::new(&pin));
    }
  }

  pub fn select_key(&self, key: usize) {
    let mut last_sender = None;
    while let Ok(sender) = self.select_receiver.lock().unwrap().try_recv() {
      last_sender = Some(sender);
    }
    if let Some(sender) = last_sender {
      let _ = sender.send(Some(key));
    }
  }

  pub fn cancel(&self) {
    let _ = self.manager.lock().unwrap().cancel();
  }
}

#[cfg(windows)]
async fn select_transport<U: UiCallback>(
  _ui: &'_ U,
) -> crate::Result<impl AuthenticatorBackend + '_> {
  Ok(webauthn_authenticator_rs::win10::Win10::default())
}
