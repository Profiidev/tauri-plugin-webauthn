use authenticators::Authenticator;
use tauri::{
  plugin::{Builder, TauriPlugin},
  Manager, Runtime,
};

pub use models::*;

#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;
mod authenticators;

pub use error::{Error, Result};

#[cfg(mobile)]
use mobile::Webauthn;

type Webauthn<R> = authenticators::ctap2::Webauthn<R>;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the webauthn APIs.
pub trait WebauthnExt<R: Runtime> {
  fn webauthn(&self) -> &Webauthn<R>;
}

impl<R: Runtime, T: Manager<R>> crate::WebauthnExt<R> for T {
  fn webauthn(&self) -> &Webauthn<R> {
    self.state::<Webauthn<R>>().inner()
  }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
  Builder::new("webauthn")
    .invoke_handler(tauri::generate_handler![
      commands::register,
      commands::authenticate,
      commands::send_pin,
      commands::select_key,
      commands::cancel,
    ])
    .setup(|app, api| {
      #[cfg(mobile)]
      let webauthn = mobile::init(app, api)?;
      #[cfg(desktop)]
      let webauthn = Webauthn::init(app, api)?;
      app.manage(webauthn);
      Ok(())
    })
    .build()
}
