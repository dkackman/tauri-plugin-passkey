use serde_json::Value;
use tauri::Url;
use tauri::{command, AppHandle, Runtime};
use tokio::task::block_in_place;
use webauthn_rs_proto::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions};

use crate::authenticators::Authenticator;
use crate::Result;
use crate::WebauthnExt;

const DEFAULT_TIMEOUT: u32 = 60_000;

/// Options and responses cross this boundary as raw JSON so the plugin can accept
/// browser-standard WebAuthn shapes (including the `prf` extension) and return the
/// browser `prf` results, translating to/from the webauthn-rs-proto shapes the
/// platform authenticators use. See [`crate::normalize`].
#[command]
pub(crate) async fn register<R: Runtime>(
    app: AppHandle<R>,
    origin: Url,
    mut options: Value,
    timeout: Option<u32>,
) -> Result<Value> {
    crate::normalize::normalize_creation_options(&mut options);
    let options: PublicKeyCredentialCreationOptions = serde_json::from_value(options)?;
    crate::validation::validate_rp_id(&origin, &options.rp.id)?;
    let credential = block_in_place(|| {
        app.webauthn()
            .register(origin, options, timeout.unwrap_or(DEFAULT_TIMEOUT))
            .log()
    })?;
    let mut response = serde_json::to_value(credential)?;
    crate::normalize::add_prf_to_registration_response(&mut response);
    Ok(response)
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
    app: AppHandle<R>,
    origin: Url,
    mut options: Value,
    timeout: Option<u32>,
) -> Result<Value> {
    crate::normalize::normalize_request_options(&mut options);
    let options: PublicKeyCredentialRequestOptions = serde_json::from_value(options)?;
    crate::validation::validate_rp_id(&origin, &options.rp_id)?;
    let credential = block_in_place(|| {
        app.webauthn()
            .authenticate(origin, options, timeout.unwrap_or(DEFAULT_TIMEOUT))
            .log()
    })?;
    let mut response = serde_json::to_value(credential)?;
    crate::normalize::add_prf_to_assertion_response(&mut response);
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
