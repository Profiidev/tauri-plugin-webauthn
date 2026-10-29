//! Plugin configuration, read from `plugins.passkey` in the app's
//! `tauri.conf.json`.

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Config {
    /// Origins (`scheme://host[:port]`) the webview may claim when calling
    /// `register`/`authenticate`. Empty (the default) allows any origin that
    /// passes the rpId checks; set it to pin the relying-party origin so code
    /// injected into the webview cannot request credentials for another site.
    pub allowed_origins: Vec<String>,
}
