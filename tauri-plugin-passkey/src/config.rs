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
    ///
    /// Only `http`/`https` origins are meaningful: entries with an opaque origin
    /// (e.g. `tauri://localhost` or any other non-special scheme) are ignored.
    pub allowed_origins: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    // Tauri hands an absent `plugins.passkey` entry to the plugin as `null`;
    // the plugin is built with `Option<Config>` so that is not a startup error.
    #[test]
    fn absent_plugin_config_deserializes_to_none() {
        let config: Option<Config> = serde_json::from_value(Value::Null).unwrap();
        assert!(config.is_none());
    }

    #[test]
    fn empty_plugin_config_deserializes_to_default() {
        let config: Option<Config> = serde_json::from_value(json!({})).unwrap();
        assert!(config.unwrap().allowed_origins.is_empty());
    }

    #[test]
    fn allowed_origins_is_camel_case() {
        let config: Option<Config> =
            serde_json::from_value(json!({ "allowedOrigins": ["https://example.com"] })).unwrap();
        assert_eq!(config.unwrap().allowed_origins, ["https://example.com"]);
    }
}
