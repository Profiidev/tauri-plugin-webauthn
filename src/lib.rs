use tauri::{
  plugin::{Builder, TauriPlugin},
  Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::Webauthn;
#[cfg(mobile)]
use mobile::Webauthn;

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
    ])
    .setup(|app, api| {
      #[cfg(mobile)]
      let webauthn = mobile::init(app, api)?;
      #[cfg(desktop)]
      let webauthn = desktop::init(app, api)?;
      app.manage(webauthn);
      Ok(())
    })
    .build()
}
