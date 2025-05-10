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
use desktop::Passkey;
#[cfg(mobile)]
use mobile::Passkey;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the passkey APIs.
pub trait PasskeyExt<R: Runtime> {
  fn passkey(&self) -> &Passkey<R>;
}

impl<R: Runtime, T: Manager<R>> crate::PasskeyExt<R> for T {
  fn passkey(&self) -> &Passkey<R> {
    self.state::<Passkey<R>>().inner()
  }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
  Builder::new("passkey")
    .invoke_handler(tauri::generate_handler![commands::ping])
    .setup(|app, api| {
      #[cfg(mobile)]
      let passkey = mobile::init(app, api)?;
      #[cfg(desktop)]
      let passkey = desktop::init(app, api)?;
      app.manage(passkey);
      Ok(())
    })
    .build()
}
