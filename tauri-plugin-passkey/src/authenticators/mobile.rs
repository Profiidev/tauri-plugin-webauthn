use base64urlsafedata::Base64UrlSafeData;
use serde::de::DeserializeOwned;
use tauri::{
    plugin::{
        mobile::{ErrorResponse, PluginInvokeError},
        PluginApi, PluginHandle,
    },
    AppHandle, Runtime, Url,
};
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

use crate::prf::{
    PrfAuthenticationInput, PrfAuthenticationOutput, PrfRegistrationInput, PrfRegistrationOutput,
};

use super::Authenticator;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_passkey);

/// Access to the webauthn APIs.
pub struct Webauthn<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Authenticator<R> for Webauthn<R> {
    fn init<C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<Self> {
        #[cfg(target_os = "android")]
        let handle = api.register_android_plugin("net.kackman.webauthn", "WebauthnPlugin")?;
        #[cfg(target_os = "ios")]
        let handle = api.register_ios_plugin(init_plugin_passkey)?;
        Ok(Webauthn(handle))
    }

    fn register(
        &self,
        _origin: Url,
        options: PublicKeyCredentialCreationOptions,
        prf: Option<PrfRegistrationInput>,
        _timeout: u32,
    ) -> crate::Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)> {
        #[cfg(target_os = "android")]
        let options = {
            let mut options = options;
            crate::normalize::apply_android_resident_key(&mut options)?;
            options
        };

        let mut options = serde_json::to_value(&options)?;
        if prf.is_some() {
            // Credential Manager and ASAuthorization both want the browser spelling.
            crate::prf::set_registration_prf_input(&mut options);
        }

        let v: serde_json::Value = self
            .0
            .run_mobile_plugin("register", serde_json::to_string(&options)?)
            .map_err(map_invoke_error)?;

        Ok((
            parse_registration_response(&v)?,
            crate::prf::registration_output_from_bridge(&v)?,
        ))
    }

    fn authenticate(
        &self,
        _origin: Url,
        options: PublicKeyCredentialRequestOptions,
        prf: Option<PrfAuthenticationInput>,
        _timeout: u32,
    ) -> crate::Result<(PublicKeyCredential, Option<PrfAuthenticationOutput>)> {
        let mut options = serde_json::to_value(&options)?;
        if let Some(prf) = &prf {
            crate::prf::set_authentication_prf_input(&mut options, prf);
        }

        let v: serde_json::Value = self
            .0
            .run_mobile_plugin("authenticate", serde_json::to_string(&options)?)
            .map_err(map_invoke_error)?;

        Ok((
            parse_authentication_response(&v)?,
            crate::prf::authentication_output_from_bridge(&v)?,
        ))
    }

    fn cancel(&self) {
        let result: Result<serde_json::Value, _> = self
            .0
            .run_mobile_plugin("cancel", ())
            .map_err(map_invoke_error);
        if let Err(_e) = result {
            #[cfg(feature = "log")]
            log::debug!("cancel was not acknowledged by the native plugin: {_e}");
        }
    }
}

/// Translate a native plugin rejection into a structured error. The Swift and
/// Kotlin bridges reject with a machine-readable `code`; known codes become
/// their matching [`crate::Error`] kind, anything else stays `PluginInvoke`.
pub(crate) fn map_invoke_error(e: PluginInvokeError) -> crate::Error {
    if let PluginInvokeError::InvokeRejected(ErrorResponse { code, message, .. }) = &e {
        let message = message.clone().unwrap_or_else(|| e.to_string());
        if let Some(mapped) = crate::error::error_from_code(code.as_deref(), &message) {
            return mapped;
        }
    }
    crate::Error::PluginInvoke(e)
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

#[cfg(all(test, mobile))]
mod tests {
    use super::*;

    fn rejected(code: Option<&str>) -> PluginInvokeError {
        PluginInvokeError::InvokeRejected(ErrorResponse {
            code: code.map(Into::into),
            message: Some("x".into()),
            data: (),
        })
    }

    #[test]
    fn cancelled_code_maps_to_cancelled() {
        assert!(matches!(
            map_invoke_error(rejected(Some("cancelled"))),
            crate::Error::Cancelled
        ));
    }

    #[test]
    fn unsupported_code_maps_to_unsupported() {
        assert!(matches!(
            map_invoke_error(rejected(Some("unsupported"))),
            crate::Error::Unsupported(m) if m == "x"
        ));
    }

    #[test]
    fn timeout_code_maps_to_authenticator() {
        assert!(matches!(
            map_invoke_error(rejected(Some("timeout"))),
            crate::Error::Authenticator(m) if m == "x"
        ));
    }

    #[test]
    fn unknown_or_missing_code_stays_plugin_invoke() {
        assert!(matches!(
            map_invoke_error(rejected(Some("other"))),
            crate::Error::PluginInvoke(_)
        ));
        assert!(matches!(
            map_invoke_error(rejected(None)),
            crate::Error::PluginInvoke(_)
        ));
        assert!(matches!(
            map_invoke_error(PluginInvokeError::UnreachableWebview),
            crate::Error::PluginInvoke(_)
        ));
    }
}
