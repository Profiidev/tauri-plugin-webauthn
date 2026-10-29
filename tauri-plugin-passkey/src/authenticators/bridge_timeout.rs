//! Carries the command `timeout` across the mobile plugin bridge.
//!
//! The native plugins receive the WebAuthn options as one JSON string, so the
//! timeout rides along as the options' top-level `timeout` member — a standard
//! field of both `PublicKeyCredentialCreationOptions` and
//! `PublicKeyCredentialRequestOptions`, in milliseconds.

/// Set `options.timeout` to `timeout` milliseconds, replacing any value the
/// caller's options already carried so the command argument wins.
#[cfg_attr(not(mobile), allow(dead_code))]
pub(crate) fn with_timeout(options: &mut serde_json::Value, timeout: u32) {
    if let Some(map) = options.as_object_mut() {
        map.insert("timeout".into(), timeout.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inserts_timeout_into_options() {
        let mut options = json!({ "challenge": "abc" });
        with_timeout(&mut options, 30_000);
        assert_eq!(options, json!({ "challenge": "abc", "timeout": 30_000 }));
    }

    #[test]
    fn overrides_existing_timeout() {
        let mut options = json!({ "challenge": "abc", "timeout": 1 });
        with_timeout(&mut options, 45_000);
        assert_eq!(options["timeout"], json!(45_000));
    }

    #[test]
    fn leaves_non_object_untouched() {
        let mut options = json!("not an object");
        with_timeout(&mut options, 45_000);
        assert_eq!(options, json!("not an object"));
    }
}
