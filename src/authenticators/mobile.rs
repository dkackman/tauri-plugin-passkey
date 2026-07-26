use base64urlsafedata::Base64UrlSafeData;
use serde::de::DeserializeOwned;
use tauri::{
  plugin::{PluginApi, PluginHandle},
  AppHandle, Runtime, Url,
};
use webauthn_rs_proto::{
  AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
  AuthenticatorAttestationResponseRaw, HmacGetSecretOutput, PublicKeyCredential,
  PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs, ResidentKeyRequirement,
};

use super::Authenticator;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_webauthn);

/// Access to the webauthn APIs.
pub struct Webauthn<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Authenticator<R> for Webauthn<R> {
  fn init<C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<Self> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("de.plugin.webauthn", "WebauthnPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_webauthn)?;
    Ok(Webauthn(handle))
  }

  fn register(
    &self,
    _origin: Url,
    mut options: PublicKeyCredentialCreationOptions,
    _timeout: u32,
  ) -> crate::Result<RegisterPublicKeyCredential> {
    // This is required to make Android save the passkey
    if let Some(auth) = &mut options.authenticator_selection {
      auth.resident_key = Some(ResidentKeyRequirement::Preferred);
    }

    // Deserialize to Value first so we can extract PRF data
    let v: serde_json::Value = self
      .0
      .run_mobile_plugin("register", serde_json::to_string(&options)?)?;

    parse_registration_response(&v)
  }

  fn authenticate(
    &self,
    _origin: Url,
    options: PublicKeyCredentialRequestOptions,
    _timeout: u32,
  ) -> crate::Result<PublicKeyCredential> {
    let v: serde_json::Value = self
      .0
      .run_mobile_plugin("authenticate", serde_json::to_string(&options)?)?;

    parse_authentication_response(&v)
  }

  fn cancel(&self) {
    let _: Result<serde_json::Value, _> = self.0.run_mobile_plugin("cancel", ());
  }
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
  base64_url_decode(v[key].as_str().ok_or(crate::Error::Authenticator(format!(
    "Missing JSON field: {key}"
  )))?)
}

fn parse_registration_response(v: &serde_json::Value) -> crate::Result<RegisterPublicKeyCredential> {
  let id = json_str(v, "id")?;
  let raw_id = json_bytes(v, "rawId")?;

  let response = &v["response"];
  let attestation_object = json_bytes(response, "attestationObject")?;
  let client_data_json = json_bytes(response, "clientDataJSON")?;

  // Parse PRF registration result: {"prf": {"enabled": true/false}}
  let mut extensions = RegistrationExtensionsClientOutputs::default();
  if let Some(prf) = v.get("prf") {
    if let Some(enabled) = prf.get("enabled").and_then(|v| v.as_bool()) {
      extensions.hmac_secret = Some(enabled);
    }
  }

  Ok(RegisterPublicKeyCredential {
    id,
    raw_id: Base64UrlSafeData::from(raw_id),
    response: AuthenticatorAttestationResponseRaw {
      attestation_object: Base64UrlSafeData::from(attestation_object),
      client_data_json: Base64UrlSafeData::from(client_data_json),
      transports: None,
    },
    type_: "public-key".to_string(),
    extensions,
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
    .and_then(|s| base64_url_decode(s).ok());

  // Parse PRF assertion result: {"prf": {"first": "base64url", "second": "base64url"}}
  let mut extensions = AuthenticationExtensionsClientOutputs::default();
  if let Some(prf) = v.get("prf") {
    let first = prf
      .get("first")
      .and_then(|v| v.as_str())
      .and_then(|s| base64_url_decode(s).ok());
    let second = prf
      .get("second")
      .and_then(|v| v.as_str())
      .and_then(|s| base64_url_decode(s).ok());

    if let Some(first) = first {
      extensions.hmac_get_secret = Some(HmacGetSecretOutput {
        output1: Base64UrlSafeData::from(first),
        output2: second.map(Base64UrlSafeData::from),
      });
    }
  }

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
    extensions,
  })
}

fn base64_url_decode(input: &str) -> crate::Result<Vec<u8>> {
  use base64::engine::general_purpose::URL_SAFE_NO_PAD;
  use base64::Engine;
  URL_SAFE_NO_PAD
    .decode(input)
    .map_err(|e| crate::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}
