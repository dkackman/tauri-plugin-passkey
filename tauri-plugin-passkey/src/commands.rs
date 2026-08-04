use serde_json::Value;
use tauri::Url;
use tauri::{command, AppHandle, Runtime};
use tokio::task::block_in_place;
use webauthn_rs_proto::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions};

use crate::authenticators::Authenticator;
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
    crate::normalize::default_require_resident_key(&mut options);
    let prf = crate::prf::registration_input_from_options(&options)?;
    let options: PublicKeyCredentialCreationOptions = serde_json::from_value(options)?;
    crate::validation::validate_rp_id(&origin, &options.rp.id)?;
    let (credential, prf_output) = block_in_place(|| {
        app.webauthn()
            .register(origin, options, prf, timeout.unwrap_or(DEFAULT_TIMEOUT))
            .log()
    })?;
    let mut response = serde_json::to_value(credential)?;
    crate::prf::set_registration_prf(&mut response, prf_output);
    Ok(response)
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
    app: AppHandle<R>,
    origin: Url,
    options: Value,
    timeout: Option<u32>,
) -> Result<Value> {
    let prf = crate::prf::authentication_input_from_options(&options)?;
    let options: PublicKeyCredentialRequestOptions = serde_json::from_value(options)?;
    crate::validation::validate_rp_id(&origin, &options.rp_id)?;
    let (credential, prf_output) = block_in_place(|| {
        app.webauthn()
            .authenticate(origin, options, prf, timeout.unwrap_or(DEFAULT_TIMEOUT))
            .log()
    })?;
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
        if let Err(e) = &self {
            #[cfg(feature = "log")]
            log::error!("Error: {e}");
        }
        self
    }
}
