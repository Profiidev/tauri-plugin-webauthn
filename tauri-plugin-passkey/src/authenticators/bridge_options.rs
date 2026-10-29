//! Options JSON for the native WebAuthn bridges (macOS FFI, iOS, Android).
//!
//! The bridges all take the browser-shaped options `webauthn-rs-proto`
//! serialises, with the PRF extension in its browser spelling and a top-level
//! `timeout` (ms) so the native layer can dismiss its own UI when it elapses.

// Only the macOS backend uses this module so far; mobile.rs switches to it in
// a follow-up.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use serde_json::Value;
use webauthn_rs_proto::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions};

use crate::prf::{self, PrfAuthenticationInput, PrfRegistrationInput};

/// Registration options JSON for a native bridge.
pub(crate) fn register_options_json(
    options: &PublicKeyCredentialCreationOptions,
    prf: Option<PrfRegistrationInput>,
    timeout: u32,
) -> crate::Result<String> {
    let mut value = serde_json::to_value(options)?;
    if prf.is_some() {
        prf::set_registration_prf_input(&mut value);
    }
    set_timeout(&mut value, timeout);
    Ok(serde_json::to_string(&value)?)
}

/// Authentication options JSON for a native bridge.
pub(crate) fn authenticate_options_json(
    options: &PublicKeyCredentialRequestOptions,
    prf: Option<&PrfAuthenticationInput>,
    timeout: u32,
) -> crate::Result<String> {
    let mut value = serde_json::to_value(options)?;
    if let Some(prf) = prf {
        prf::set_authentication_prf_input(&mut value, prf);
    }
    set_timeout(&mut value, timeout);
    Ok(serde_json::to_string(&value)?)
}

/// The effective timeout replaces whatever `timeout` the options carried.
fn set_timeout(value: &mut Value, timeout: u32) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("timeout".into(), Value::from(timeout));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creation_options() -> PublicKeyCredentialCreationOptions {
        serde_json::from_str(
            r#"{
                "rp": { "id": "example.com", "name": "Example" },
                "user": { "id": "dXNlci1pZA", "name": "alice", "displayName": "Alice" },
                "challenge": "Y2hhbGxlbmdl",
                "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
                "timeout": 1000,
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "requireResidentKey": false,
                    "userVerification": "required"
                },
                "attestation": "direct"
            }"#,
        )
        .unwrap()
    }

    fn request_options() -> PublicKeyCredentialRequestOptions {
        serde_json::from_str(
            r#"{
                "challenge": "Y2hhbGxlbmdl",
                "rpId": "example.com",
                "userVerification": "preferred",
                "allowCredentials": [{ "type": "public-key", "id": "Y3JlZA" }]
            }"#,
        )
        .unwrap()
    }

    fn parse(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn register_options_json_contains_prf_and_timeout() {
        let v = parse(
            &register_options_json(&creation_options(), Some(PrfRegistrationInput), 45000).unwrap(),
        );
        assert_eq!(v["extensions"]["prf"], serde_json::json!({}));
        assert_eq!(v["timeout"], 45000);
        // The fields the Swift bridge maps must survive in browser spelling.
        assert_eq!(v["rp"]["id"], "example.com");
        assert_eq!(v["user"]["name"], "alice");
        assert_eq!(v["challenge"], "Y2hhbGxlbmdl");
        assert_eq!(v["pubKeyCredParams"][0]["alg"], -7);
        assert_eq!(
            v["authenticatorSelection"]["authenticatorAttachment"],
            "cross-platform"
        );
        assert_eq!(v["authenticatorSelection"]["userVerification"], "required");
        assert_eq!(v["attestation"], "direct");
    }

    #[test]
    fn register_options_json_without_prf_has_no_prf_extension() {
        let v = parse(&register_options_json(&creation_options(), None, 60000).unwrap());
        assert!(v["extensions"]["prf"].is_null());
        assert_eq!(v["timeout"], 60000);
    }

    #[test]
    fn authenticate_options_json_contains_eval_salts() {
        let prf = PrfAuthenticationInput {
            first: vec![1, 2, 3],
            second: Some(vec![4, 5, 6]),
        };
        let v = parse(&authenticate_options_json(&request_options(), Some(&prf), 30000).unwrap());
        assert_eq!(
            v["extensions"]["prf"]["eval"]["first"],
            crate::base64url::encode(&[1, 2, 3])
        );
        assert_eq!(
            v["extensions"]["prf"]["eval"]["second"],
            crate::base64url::encode(&[4, 5, 6])
        );
        assert_eq!(v["timeout"], 30000);
        assert_eq!(v["rpId"], "example.com");
        assert_eq!(v["userVerification"], "preferred");
        assert_eq!(v["allowCredentials"][0]["id"], "Y3JlZA");
    }

    #[test]
    fn authenticate_options_json_without_prf_has_no_prf_extension() {
        let v = parse(&authenticate_options_json(&request_options(), None, 5000).unwrap());
        assert!(v["extensions"]["prf"].is_null());
        assert_eq!(v["timeout"], 5000);
    }
}
