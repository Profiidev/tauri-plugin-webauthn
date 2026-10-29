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
    ///
    /// A non-empty list in which *no* entry is usable fails closed: every
    /// ceremony is rejected. The plugin logs a warning at startup in that case.
    pub allowed_origins: Vec<String>,
}

impl Config {
    /// Number of `allowed_origins` entries that can ever match a webview origin
    /// (parseable, with an http/https tuple origin).
    pub fn usable_origin_count(&self) -> usize {
        self.allowed_origins
            .iter()
            .filter(|entry| crate::validation::usable_allowed_origin(entry).is_some())
            .count()
    }

    /// True when `allowed_origins` is set but contains no usable entry, so every
    /// `register`/`authenticate` call will be rejected (fail closed).
    pub fn rejects_every_origin(&self) -> bool {
        !self.allowed_origins.is_empty() && self.usable_origin_count() == 0
    }
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

    fn with_origins(entries: &[&str]) -> Config {
        Config {
            allowed_origins: entries.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn opaque_origin_is_not_usable() {
        assert_eq!(
            with_origins(&["tauri://localhost"]).usable_origin_count(),
            0
        );
    }

    #[test]
    fn https_origin_is_usable() {
        assert_eq!(
            with_origins(&["https://a.example"]).usable_origin_count(),
            1
        );
    }

    #[test]
    fn malformed_entries_are_not_usable() {
        let config = with_origins(&["not a url", "tauri://localhost", "http://localhost:1420"]);
        assert_eq!(config.usable_origin_count(), 1);
    }

    #[test]
    fn rejects_every_origin_only_when_non_empty_and_unusable() {
        assert!(!with_origins(&[]).rejects_every_origin());
        assert!(with_origins(&["tauri://localhost"]).rejects_every_origin());
        assert!(!with_origins(&["https://a.example"]).rejects_every_origin());
    }
}
