use std::{
    ffi::{c_char, CStr, CString},
    marker::PhantomData,
    sync::mpsc,
    time::Duration,
};

use base64urlsafedata::Base64UrlSafeData;
use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, Url};
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

use crate::prf::{
    self, PrfAuthenticationInput, PrfAuthenticationOutput, PrfRegistrationInput,
    PrfRegistrationOutput,
};

use super::{bridge_options, Authenticator};

type WebauthnCallback =
    unsafe extern "C" fn(json: *const c_char, error: *const c_char, context: u64);

// `options_json` is browser-shaped WebAuthn options JSON (see
// `bridge_options`). The Swift exports copy it into a Swift `String` before
// returning, so it only has to outlive the call.
extern "C" {
    fn webauthn_register(options_json: *const c_char, context: u64, callback: WebauthnCallback);

    fn webauthn_authenticate(options_json: *const c_char, context: u64, callback: WebauthnCallback);

    fn webauthn_free_string(ptr: *mut c_char);
    fn webauthn_cancel();
}

/// Access to the webauthn APIs.
#[derive(Debug)]
pub struct Webauthn<R: Runtime> {
    phantom: PhantomData<AppHandle<R>>,
}

impl<R: Runtime> Authenticator<R> for Webauthn<R> {
    fn init<C: DeserializeOwned>(
        _app: &AppHandle<R>,
        _api: PluginApi<R, C>,
    ) -> crate::Result<Self> {
        Ok(Webauthn {
            phantom: PhantomData,
        })
    }

    /// Register a new credential using macOS passkeys.
    fn register(
        &self,
        _origin: Url,
        options: PublicKeyCredentialCreationOptions,
        prf: Option<PrfRegistrationInput>,
        timeout: u32,
    ) -> crate::Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)> {
        let options_json = to_cstring(&bridge_options::register_options_json(
            &options, prf, timeout,
        )?)?;

        let (sender, receiver) = mpsc::channel::<Result<String, String>>();
        let context = Box::into_raw(Box::new(sender)) as u64;

        // SAFETY: `options_json` outlives the call; Swift copies it before
        // returning. `context` is reclaimed exactly once by `ffi_callback`.
        unsafe { webauthn_register(options_json.as_ptr(), context, ffi_callback) };

        let json = await_swift_result(receiver, timeout)?;
        let v: serde_json::Value = serde_json::from_str(&json)?;
        Ok((
            parse_registration_response(&v)?,
            prf::registration_output_from_bridge(&v)?,
        ))
    }

    /// Authenticate using macOS passkeys.
    fn authenticate(
        &self,
        _origin: Url,
        options: PublicKeyCredentialRequestOptions,
        prf: Option<PrfAuthenticationInput>,
        timeout: u32,
    ) -> crate::Result<(PublicKeyCredential, Option<PrfAuthenticationOutput>)> {
        // ASAuthorization applies the WebAuthn PRF derivation itself, so the
        // browser-level salts go across the FFI boundary unchanged.
        let options_json = to_cstring(&bridge_options::authenticate_options_json(
            &options,
            prf.as_ref(),
            timeout,
        )?)?;

        let (sender, receiver) = mpsc::channel::<Result<String, String>>();
        let context = Box::into_raw(Box::new(sender)) as u64;

        // SAFETY: as in `register`.
        unsafe { webauthn_authenticate(options_json.as_ptr(), context, ffi_callback) };

        let json = await_swift_result(receiver, timeout)?;
        let v: serde_json::Value = serde_json::from_str(&json)?;
        Ok((
            parse_authentication_response(&v)?,
            prf::authentication_output_from_bridge(&v)?,
        ))
    }

    fn cancel(&self) {
        unsafe { webauthn_cancel() };
    }
}

unsafe extern "C" fn ffi_callback(json: *const c_char, error: *const c_char, context: u64) {
    let sender: Box<mpsc::Sender<Result<String, String>>> = Box::from_raw(context as *mut _);

    let result = if !json.is_null() {
        let json_str = CStr::from_ptr(json).to_string_lossy().into_owned();
        webauthn_free_string(json as *mut c_char);
        Ok(json_str)
    } else if !error.is_null() {
        let err_str = CStr::from_ptr(error).to_string_lossy().into_owned();
        webauthn_free_string(error as *mut c_char);
        Err(err_str)
    } else {
        Err("Unknown error".into())
    };

    let _ = sender.send(result);
}

/// Structured error the Swift bridge reports: `{"code": ..., "message": ...}`,
/// with `code` omitted when Swift has no machine-readable code for it.
#[derive(serde::Deserialize)]
struct BridgeError {
    code: Option<String>,
    message: String,
}

/// Map a Swift bridge error string to a structured error. JSON with a known
/// `code` becomes its matching kind; JSON with an unknown code keeps its
/// message as an authenticator error; a plain string is passed through as one.
fn swift_error(s: String) -> crate::Error {
    match serde_json::from_str::<BridgeError>(&s) {
        Ok(BridgeError { code, message }) => {
            crate::error::error_from_code(code.as_deref(), &message)
                .unwrap_or(crate::Error::Authenticator(message))
        }
        Err(_) => crate::Error::Authenticator(s),
    }
}

/// Grace period past the RP timeout before Rust gives up on Swift. The Swift
/// handler dismisses its own sheet at `timeout` and reports a `timeout` code;
/// this backstop only fires if that callback never arrives.
const SWIFT_TIMEOUT_GRACE_MS: u64 = 2000;

fn await_swift_result(
    receiver: mpsc::Receiver<Result<String, String>>,
    timeout: u32,
) -> crate::Result<String> {
    receiver
        .recv_timeout(Duration::from_millis(
            u64::from(timeout) + SWIFT_TIMEOUT_GRACE_MS,
        ))
        .map_err(|e| {
            // The user never answered the sheet — tear it down so it does not
            // linger after we have already reported failure to the webview.
            unsafe { webauthn_cancel() };
            crate::Error::Authenticator(format!("Timeout waiting for authenticator: {e}"))
        })?
        .map_err(|e| {
            #[cfg(feature = "log")]
            log::error!("Failed to complete passkey operation: {e}");
            swift_error(e)
        })
}

fn to_cstring(s: &str) -> crate::Result<CString> {
    CString::new(s).map_err(|e| crate::Error::Io(e.into()))
}

fn json_str(v: &serde_json::Value, key: &str) -> crate::Result<String> {
    v[key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or(crate::Error::Authenticator(format!(
            "Missing JSON field: {key}"
        )))
}

fn json_bytes(v: &serde_json::Value, key: &str) -> crate::Result<Vec<u8>> {
    let encoded = v[key].as_str().ok_or(crate::Error::Authenticator(format!(
        "Missing JSON field: {key}"
    )))?;
    crate::base64url::decode(encoded)
        .map_err(|e| crate::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

fn parse_registration_response(
    v: &serde_json::Value,
) -> crate::Result<RegisterPublicKeyCredential> {
    let id = json_str(v, "id")?;
    let raw_id = json_bytes(v, "rawId")?;

    let response = &v["response"];
    let attestation_object = json_bytes(response, "attestationObject")?;
    let client_data_json = json_bytes(response, "clientDataJSON")?;

    Ok(RegisterPublicKeyCredential {
        id,
        raw_id: Base64UrlSafeData::from(raw_id),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData::from(attestation_object),
            client_data_json: Base64UrlSafeData::from(client_data_json),
            transports: None,
        },
        type_: "public-key".to_string(),
        extensions: Default::default(),
    })
}

fn parse_authentication_response(v: &serde_json::Value) -> crate::Result<PublicKeyCredential> {
    let id = json_str(v, "id")?;
    let raw_id = json_bytes(v, "rawId")?;

    let response = &v["response"];
    let authenticator_data = json_bytes(response, "authenticatorData")?;
    let client_data_json = json_bytes(response, "clientDataJSON")?;
    let signature = json_bytes(response, "signature")?;
    let user_handle = response["userHandle"]
        .as_str()
        .and_then(|s| crate::base64url::decode(s).ok());

    Ok(PublicKeyCredential {
        id,
        raw_id: Base64UrlSafeData::from(raw_id),
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: Base64UrlSafeData::from(authenticator_data),
            client_data_json: Base64UrlSafeData::from(client_data_json),
            signature: Base64UrlSafeData::from(signature),
            user_handle: user_handle.map(Base64UrlSafeData::from),
        },
        type_: "public-key".to_string(),
        extensions: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // These go through `swift_error` rather than `await_swift_result`: the
    // latter references the Swift FFI, and pulling the Swift runtime into the
    // test binary needs an rpath the test harness does not set.
    fn swift_result(result: Result<String, String>) -> crate::Result<String> {
        result.map_err(swift_error)
    }

    #[test]
    fn swift_error_json_with_cancelled_code_maps_to_cancelled() {
        let err = swift_result(Err(
            r#"{"code":"cancelled","message":"The operation was canceled."}"#.into(),
        ))
        .unwrap_err();
        assert!(matches!(err, crate::Error::Cancelled));
    }

    #[test]
    fn swift_error_json_with_unsupported_code_maps_to_unsupported() {
        let err =
            swift_result(Err(r#"{"code":"unsupported","message":"no PRF"}"#.into())).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(m) if m == "no PRF"));
    }

    #[test]
    fn swift_error_json_with_unknown_code_keeps_message_as_authenticator() {
        let err = swift_result(Err(r#"{"code":"failed","message":"boom"}"#.into())).unwrap_err();
        assert!(matches!(err, crate::Error::Authenticator(m) if m == "boom"));
    }

    #[test]
    fn swift_error_json_without_code_keeps_message_as_authenticator() {
        let err = swift_result(Err(r#"{"message":"boom"}"#.into())).unwrap_err();
        assert!(matches!(err, crate::Error::Authenticator(m) if m == "boom"));
    }

    #[test]
    fn swift_error_json_with_timeout_code_keeps_message() {
        let err =
            swift_result(Err(r#"{"code":"timeout","message":"timed out"}"#.into())).unwrap_err();
        assert!(matches!(err, crate::Error::Authenticator(m) if m == "timed out"));
    }

    #[test]
    fn swift_error_plain_string_stays_authenticator() {
        let err = swift_result(Err("something broke".into())).unwrap_err();
        assert!(matches!(err, crate::Error::Authenticator(m) if m == "something broke"));
    }

    #[test]
    fn json_bytes_reports_the_missing_field_name() {
        let v: serde_json::Value = serde_json::from_str(r#"{"present":"AQID"}"#).unwrap();
        let err = json_bytes(&v, "absent").unwrap_err();
        assert!(err.to_string().contains("Missing JSON field: absent"));
    }

    #[test]
    fn parses_registration_response_with_prf_enabled() {
        let raw_id = [1u8, 2, 3, 4];
        let att = [10u8, 20, 30];
        let cdj = [40u8, 50, 60];
        let json = format!(
            r#"{{"id":"credA","rawId":"{}","response":{{"attestationObject":"{}","clientDataJSON":"{}"}},"prf":{{"enabled":true}}}}"#,
            crate::base64url::encode(&raw_id),
            crate::base64url::encode(&att),
            crate::base64url::encode(&cdj),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let parsed = parse_registration_response(&v).unwrap();

        assert_eq!(parsed.id, "credA");
        assert_eq!(parsed.raw_id.as_slice(), &raw_id);
        assert_eq!(parsed.response.attestation_object.as_slice(), &att);
        assert_eq!(parsed.response.client_data_json.as_slice(), &cdj);
        assert_eq!(parsed.type_, "public-key");
        assert_eq!(
            prf::registration_output_from_bridge(&v).unwrap(),
            Some(PrfRegistrationOutput { enabled: true })
        );
    }

    #[test]
    fn parses_registration_response_without_prf() {
        let json = format!(
            r#"{{"id":"credB","rawId":"{}","response":{{"attestationObject":"{}","clientDataJSON":"{}"}}}}"#,
            crate::base64url::encode(&[1u8]),
            crate::base64url::encode(&[2u8]),
            crate::base64url::encode(&[3u8]),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        parse_registration_response(&v).unwrap();

        assert!(prf::registration_output_from_bridge(&v).unwrap().is_none());
    }

    #[test]
    fn registration_response_missing_id_is_an_error() {
        let json = format!(
            r#"{{"rawId":"{}","response":{{"attestationObject":"{}","clientDataJSON":"{}"}}}}"#,
            crate::base64url::encode(&[1u8]),
            crate::base64url::encode(&[2u8]),
            crate::base64url::encode(&[3u8]),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let err = parse_registration_response(&v).unwrap_err();
        assert!(err.to_string().contains("Missing JSON field: id"));
    }

    #[test]
    fn parses_authentication_response_with_both_prf_outputs() {
        let raw_id = [9u8, 8, 7];
        let auth_data = [1u8, 1, 1];
        let cdj = [2u8, 2, 2];
        let sig = [3u8, 3, 3];
        let user_handle = [4u8, 4, 4];
        let prf_first = [5u8; 32];
        let prf_second = [6u8; 32];
        let json = format!(
            r#"{{"id":"credC","rawId":"{}","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}","userHandle":"{}"}},"prf":{{"first":"{}","second":"{}"}}}}"#,
            crate::base64url::encode(&raw_id),
            crate::base64url::encode(&auth_data),
            crate::base64url::encode(&cdj),
            crate::base64url::encode(&sig),
            crate::base64url::encode(&user_handle),
            crate::base64url::encode(&prf_first),
            crate::base64url::encode(&prf_second),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let parsed = parse_authentication_response(&v).unwrap();

        assert_eq!(parsed.id, "credC");
        assert_eq!(parsed.raw_id.as_slice(), &raw_id);
        assert_eq!(parsed.response.signature.as_slice(), &sig);
        assert_eq!(
            parsed.response.user_handle.as_ref().unwrap().as_slice(),
            &user_handle
        );
        let prf_output = prf::authentication_output_from_bridge(&v).unwrap().unwrap();
        assert_eq!(prf_output.first, prf_first);
        assert_eq!(prf_output.second.as_deref(), Some(&prf_second[..]));
    }

    #[test]
    fn authentication_response_prf_second_is_optional() {
        let prf_first = [7u8; 32];
        let json = format!(
            r#"{{"id":"credD","rawId":"{}","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"}},"prf":{{"first":"{}"}}}}"#,
            crate::base64url::encode(&[1u8]),
            crate::base64url::encode(&[2u8]),
            crate::base64url::encode(&[3u8]),
            crate::base64url::encode(&[4u8]),
            crate::base64url::encode(&prf_first),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let parsed = parse_authentication_response(&v).unwrap();

        // No userHandle in the JSON -> None.
        assert!(parsed.response.user_handle.is_none());
        let prf_output = prf::authentication_output_from_bridge(&v).unwrap().unwrap();
        assert_eq!(prf_output.first, prf_first);
        assert!(prf_output.second.is_none());
    }

    #[test]
    fn authentication_response_without_prf_has_no_hmac_output() {
        let json = format!(
            r#"{{"id":"credE","rawId":"{}","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"}}}}"#,
            crate::base64url::encode(&[1u8]),
            crate::base64url::encode(&[2u8]),
            crate::base64url::encode(&[3u8]),
            crate::base64url::encode(&[4u8]),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        parse_authentication_response(&v).unwrap();

        assert!(prf::authentication_output_from_bridge(&v)
            .unwrap()
            .is_none());
    }

    #[test]
    fn authentication_response_with_malformed_prf_first_errors() {
        let json = format!(
            r#"{{"id":"credF","rawId":"{}","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"}},"prf":{{"first":"!!!"}}}}"#,
            crate::base64url::encode(&[1u8]),
            crate::base64url::encode(&[2u8]),
            crate::base64url::encode(&[3u8]),
            crate::base64url::encode(&[4u8]),
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let err = prf::authentication_output_from_bridge(&v).unwrap_err();
        assert_eq!(err.kind(), "authenticator");
    }
}
