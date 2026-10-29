use std::{
    ffi::{c_char, c_uchar, CStr, CString},
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

use super::Authenticator;

type WebauthnCallback =
    unsafe extern "C" fn(json: *const c_char, error: *const c_char, context: u64);

extern "C" {
    fn webauthn_register(
        domain: *const c_char,
        challenge_ptr: *const c_uchar,
        challenge_len: usize,
        username: *const c_char,
        display_name: *const c_char,
        user_id_ptr: *const c_uchar,
        user_id_len: usize,
        exclude_credentials_json: *const c_char,
        prf_enabled: u8,
        context: u64,
        callback: WebauthnCallback,
    );

    fn webauthn_authenticate(
        domain: *const c_char,
        challenge_ptr: *const c_uchar,
        challenge_len: usize,
        allow_credentials_json: *const c_char,
        prf_salt1_ptr: *const c_uchar,
        prf_salt1_len: usize,
        prf_salt2_ptr: *const c_uchar,
        prf_salt2_len: usize,
        context: u64,
        callback: WebauthnCallback,
    );

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
        let domain = to_cstring(options.rp.id.as_str())?;
        let challenge = options.challenge.as_slice();
        let username = to_cstring(options.user.name.as_str())?;
        let display_name = to_cstring(options.user.display_name.as_str())?;

        let exclude_creds_json = {
            let ids: Vec<String> = options
                .exclude_credentials
                .iter()
                .flatten()
                .map(|c| crate::base64url::encode(c.id.as_slice()))
                .collect();
            if ids.is_empty() {
                None
            } else {
                Some(to_cstring(&serde_json::to_string(&ids)?)?)
            }
        };
        // SAFETY: same invariant as allow_creds_json in `authenticate` — the
        // Swift export copies this into a Swift String before returning.
        let exclude_ptr = exclude_creds_json
            .as_deref()
            .map(|c| c.as_ptr())
            .unwrap_or(std::ptr::null());
        let user_id = options.user.id.as_slice();

        let prf_enabled: u8 = u8::from(prf.is_some());

        let (sender, receiver) = mpsc::channel::<Result<String, String>>();
        let context = Box::into_raw(Box::new(sender)) as u64;

        unsafe {
            webauthn_register(
                domain.as_ptr(),
                challenge.as_ptr(),
                challenge.len(),
                username.as_ptr(),
                display_name.as_ptr(),
                user_id.as_ptr(),
                user_id.len(),
                exclude_ptr,
                prf_enabled,
                context,
                ffi_callback,
            );
        }

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
        let domain = to_cstring(options.rp_id.as_str())?;
        let challenge = options.challenge.as_slice();

        let allow_creds_json = {
            let ids: Vec<String> = options
                .allow_credentials
                .iter()
                .map(|c| crate::base64url::encode(c.id.as_slice()))
                .collect();
            if ids.is_empty() {
                None
            } else {
                Some(to_cstring(&serde_json::to_string(&ids)?)?)
            }
        };

        // SAFETY: `allow_creds_json` outlives the `webauthn_authenticate` call below.
        // The Swift `webauthn_authenticate` export immediately copies this pointer into
        // a Swift `String` before launching its async Task, so the pointer is not used
        // after this function returns. If the Swift implementation ever changes to
        // escape the pointer asynchronously, this becomes unsound.
        let creds_ptr = allow_creds_json
            .as_deref()
            .map(|c| c.as_ptr())
            .unwrap_or(std::ptr::null());

        // ASAuthorization applies the WebAuthn PRF derivation itself, so the
        // browser-level salts go across the FFI boundary unchanged.
        let (salt1_ptr, salt1_len) = prf
            .as_ref()
            .map(|p| (p.first.as_ptr(), p.first.len()))
            .unwrap_or((std::ptr::null(), 0));

        let (salt2_ptr, salt2_len) = prf
            .as_ref()
            .and_then(|p| p.second.as_ref())
            .map(|s| (s.as_ptr(), s.len()))
            .unwrap_or((std::ptr::null(), 0));

        let (sender, receiver) = mpsc::channel::<Result<String, String>>();
        let context = Box::into_raw(Box::new(sender)) as u64;

        unsafe {
            webauthn_authenticate(
                domain.as_ptr(),
                challenge.as_ptr(),
                challenge.len(),
                creds_ptr,
                salt1_ptr,
                salt1_len,
                salt2_ptr,
                salt2_len,
                context,
                ffi_callback,
            );
        }

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

/// Structured error the Swift bridge reports: `{"code": ..., "message": ...}`.
#[derive(serde::Deserialize)]
struct BridgeError {
    code: String,
    message: String,
}

/// Map a Swift bridge error string to a structured error. JSON with a known
/// `code` becomes its matching kind; JSON with an unknown code keeps its
/// message as an authenticator error; a plain string is passed through as one.
fn swift_error(s: String) -> crate::Error {
    match serde_json::from_str::<BridgeError>(&s) {
        Ok(BridgeError { code, message }) => crate::error::error_from_code(Some(&code), &message)
            .unwrap_or(crate::Error::Authenticator(message)),
        Err(_) => crate::Error::Authenticator(s),
    }
}

fn await_swift_result(
    receiver: mpsc::Receiver<Result<String, String>>,
    timeout: u32,
) -> crate::Result<String> {
    receiver
        .recv_timeout(Duration::from_millis(timeout as u64))
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
