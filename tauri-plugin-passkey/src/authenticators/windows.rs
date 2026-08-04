use std::{fmt::Debug, marker::PhantomData};

use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, Url};
use webauthn_authenticator_rs::{win10::Win10, AuthenticatorBackend};
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

use crate::prf::{
    PrfAuthenticationInput, PrfAuthenticationOutput, PrfRegistrationInput, PrfRegistrationOutput,
};

use super::Authenticator;

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

    /// Register a new credential using native Windows API.
    fn register(
        &self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        prf: Option<PrfRegistrationInput>,
        timeout: u32,
    ) -> crate::Result<(RegisterPublicKeyCredential, Option<PrfRegistrationOutput>)> {
        let _ = prf;
        let mut auth = Win10::default();
        let credential = auth
            .perform_register(origin, options, timeout)
            .map_err(|e| {
                #[cfg(feature = "log")]
                log::error!("Failed to register: {:?}", e);
                crate::Error::WebAuthn(e)
            })?;
        Ok((credential, None))
    }

    /// Authenticate using native Windows API.
    fn authenticate(
        &self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        prf: Option<PrfAuthenticationInput>,
        timeout: u32,
    ) -> crate::Result<(PublicKeyCredential, Option<PrfAuthenticationOutput>)> {
        let _ = prf;
        let mut auth = Win10::default();
        let credential = auth.perform_auth(origin, options, timeout).map_err(|e| {
            #[cfg(feature = "log")]
            log::error!("Failed to authenticate: {:?}", e);
            crate::Error::WebAuthn(e)
        })?;
        Ok((credential, None))
    }
}
