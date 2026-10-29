use serde_json::Value;
use tauri::Url;
use tauri::{command, AppHandle, Manager, Runtime};
use tokio::task::block_in_place;
use webauthn_rs_proto::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions};

use crate::authenticators::Authenticator;
use crate::config::Config;
use crate::inflight::InFlight;
use crate::Result;
use crate::WebauthnExt;

const DEFAULT_TIMEOUT: u32 = 60_000;

/// Options and responses cross this boundary as raw JSON so the plugin speaks the
/// browser's WebAuthn shapes. PRF is read from `extensions.prf` and returned in
/// `clientExtensionResults.prf`; it is the only PRF spelling accepted or emitted.
/// See [`crate::prf`].
#[command]
pub(crate) async fn register<R: Runtime>(
    app: AppHandle<R>,
    origin: Url,
    mut options: Value,
    timeout: Option<u32>,
) -> Result<Value> {
    crate::normalize::default_creation_options(&mut options);
    let prf = crate::prf::registration_input_from_options(&options)?;
    let prf_requested = prf.is_some();
    let options: PublicKeyCredentialCreationOptions = serde_json::from_value(options)?;
    crate::validation::validate_origin_allowed(&origin, &app.state::<Config>().allowed_origins)?;
    crate::validation::validate_rp_id(&origin, &options.rp.id)?;
    let timeout = effective_timeout(timeout, options.timeout);
    // Held until the ceremony returns; a concurrent ceremony gets `busy`.
    let inflight = app.state::<InFlight>();
    let _guard = inflight.acquire()?;
    let (credential, prf_output) =
        block_in_place(|| app.webauthn().register(origin, options, prf, timeout).log())?;
    // Unsupported PRF is web-shaped, not silent: if the caller asked for PRF
    // and no backend produced an output, report `prf.enabled = false` rather
    // than omitting `prf` entirely.
    let prf_output = crate::prf::registration_output_or_disabled(prf_requested, prf_output);
    let mut response = serde_json::to_value(credential)?;
    crate::prf::set_registration_prf(&mut response, prf_output);
    Ok(response)
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
    app: AppHandle<R>,
    origin: Url,
    mut options: Value,
    timeout: Option<u32>,
) -> Result<Value> {
    crate::normalize::default_request_options(&mut options);
    let prf = crate::prf::authentication_input_from_options(&options)?;
    let prf_requested = prf.is_some();
    let options: PublicKeyCredentialRequestOptions = serde_json::from_value(options)?;
    crate::validation::validate_origin_allowed(&origin, &app.state::<Config>().allowed_origins)?;
    crate::validation::validate_rp_id(&origin, &options.rp_id)?;
    let timeout = effective_timeout(timeout, options.timeout);
    // Held until the ceremony returns; a concurrent ceremony gets `busy`.
    let inflight = app.state::<InFlight>();
    let _guard = inflight.acquire()?;
    let (credential, prf_output) = block_in_place(|| {
        app.webauthn()
            .authenticate(origin, options, prf, timeout)
            .log()
    })?;
    // Never silently return no secret: if the caller passed salts and no
    // backend produced an output, error rather than succeed with `prf` absent.
    let prf_output = crate::prf::require_authentication_output(prf_requested, prf_output)?;
    let mut response = serde_json::to_value(credential)?;
    crate::prf::set_authentication_prf(&mut response, prf_output);
    Ok(response)
}

#[command]
pub(crate) async fn send_pin<R: Runtime>(app: AppHandle<R>, pin: String) {
    app.webauthn().send_pin(pin);
}

#[command]
pub(crate) async fn select_key<R: Runtime>(app: AppHandle<R>, key: usize) {
    app.webauthn().select_key(key);
}

#[command]
pub(crate) async fn cancel<R: Runtime>(app: AppHandle<R>) {
    app.webauthn().cancel();
}

trait ResultExt<T> {
    fn log(self) -> Self;
}

impl<T> ResultExt<T> for Result<T> {
    fn log(self) -> Self {
        #[cfg(feature = "log")]
        if let Err(e) = &self {
            log::error!("Error: {e}");
        }
        self
    }
}

/// The ceremony timeout in milliseconds: the explicit `timeout` command argument
/// wins, then the WebAuthn options' own `timeout`, then [`DEFAULT_TIMEOUT`].
pub(crate) fn effective_timeout(arg: Option<u32>, options_timeout: Option<u32>) -> u32 {
    arg.or(options_timeout).unwrap_or(DEFAULT_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_timeout_argument_wins_over_options() {
        assert_eq!(effective_timeout(Some(5_000), Some(30_000)), 5_000);
    }

    #[test]
    fn options_timeout_used_when_argument_absent() {
        assert_eq!(effective_timeout(None, Some(30_000)), 30_000);
    }

    #[test]
    fn default_timeout_when_both_absent() {
        assert_eq!(effective_timeout(None, None), DEFAULT_TIMEOUT);
    }
}
