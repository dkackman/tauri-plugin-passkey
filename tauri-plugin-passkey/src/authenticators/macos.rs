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
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, HmacGetSecretOutput,
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
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
        timeout: u32,
    ) -> crate::Result<RegisterPublicKeyCredential> {
        let domain = to_cstring(options.rp.id.as_str())?;
        let challenge = options.challenge.as_slice();
        let username = to_cstring(options.user.name.as_str())?;
        let display_name = to_cstring(options.user.display_name.as_str())?;

        let exclude_creds_json = {
            let ids: Vec<String> = options
                .exclude_credentials
                .iter()
                .flatten()
                .map(|c| base64_url_encode(c.id.as_slice()))
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

        // Check if PRF/hmac-secret was requested
        let prf_enabled: u8 = if options
            .extensions
            .as_ref()
            .and_then(|e| e.hmac_create_secret)
            == Some(true)
        {
            1
        } else {
            0
        };

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
        parse_registration_response(&json)
    }

    /// Authenticate using macOS passkeys.
    fn authenticate(
        &self,
        _origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout: u32,
    ) -> crate::Result<PublicKeyCredential> {
        let domain = to_cstring(options.rp_id.as_str())?;
        let challenge = options.challenge.as_slice();

        let allow_creds_json = {
            let ids: Vec<String> = options
                .allow_credentials
                .iter()
                .map(|c| base64_url_encode(c.id.as_slice()))
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

        // Extract PRF salt from extensions (hmac_get_secret input)
        let prf_salt = options
            .extensions
            .as_ref()
            .and_then(|e| e.hmac_get_secret.as_ref());

        let (salt1_ptr, salt1_len) = prf_salt
            .map(|s| (s.output1.as_slice().as_ptr(), s.output1.len()))
            .unwrap_or((std::ptr::null(), 0));

        let (salt2_ptr, salt2_len) = prf_salt
            .and_then(|s| s.output2.as_ref())
            .map(|s| (s.as_slice().as_ptr(), s.len()))
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
        parse_authentication_response(&json)
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
            crate::Error::Authenticator(e)
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
    base64_url_decode(v[key].as_str().ok_or(crate::Error::Authenticator(format!(
        "Missing JSON field: {key}"
    )))?)
}

fn parse_registration_response(json: &str) -> crate::Result<RegisterPublicKeyCredential> {
    let v: serde_json::Value = serde_json::from_str(json)?;

    let id = json_str(&v, "id")?;
    let raw_id = json_bytes(&v, "rawId")?;

    let response = &v["response"];
    let attestation_object = json_bytes(response, "attestationObject")?;
    let client_data_json = json_bytes(response, "clientDataJSON")?;

    // Parse PRF registration result: {"prf": {"enabled": true/false}}
    let mut extensions = webauthn_rs_proto::RegistrationExtensionsClientOutputs::default();
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

fn parse_authentication_response(json: &str) -> crate::Result<PublicKeyCredential> {
    let v: serde_json::Value = serde_json::from_str(json)?;

    let id = json_str(&v, "id")?;
    let raw_id = json_bytes(&v, "rawId")?;

    let response = &v["response"];
    let authenticator_data = json_bytes(response, "authenticatorData")?;
    let client_data_json = json_bytes(response, "clientDataJSON")?;
    let signature = json_bytes(response, "signature")?;
    let user_handle = response["userHandle"]
        .as_str()
        .and_then(|s| base64_url_decode(s).ok());

    // Parse PRF assertion result: {"prf": {"first": "base64url", "second": "base64url"}}
    let mut extensions = webauthn_rs_proto::AuthenticationExtensionsClientOutputs::default();
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

fn base64_url_encode(input: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_url_round_trips() {
        let bytes = [0u8, 1, 2, 250, 251, 252, 253, 254, 255];
        let encoded = base64_url_encode(&bytes);
        // URL-safe, unpadded: no '+', '/', or '=' may appear.
        assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
        assert_eq!(base64_url_decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn base64_url_decode_rejects_invalid_input() {
        assert!(base64_url_decode("not valid base64!!!").is_err());
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
            base64_url_encode(&raw_id),
            base64_url_encode(&att),
            base64_url_encode(&cdj),
        );

        let parsed = parse_registration_response(&json).unwrap();

        assert_eq!(parsed.id, "credA");
        assert_eq!(parsed.raw_id.as_slice(), &raw_id);
        assert_eq!(parsed.response.attestation_object.as_slice(), &att);
        assert_eq!(parsed.response.client_data_json.as_slice(), &cdj);
        assert_eq!(parsed.type_, "public-key");
        assert_eq!(parsed.extensions.hmac_secret, Some(true));
    }

    #[test]
    fn parses_registration_response_without_prf() {
        let json = format!(
            r#"{{"id":"credB","rawId":"{}","response":{{"attestationObject":"{}","clientDataJSON":"{}"}}}}"#,
            base64_url_encode(&[1u8]),
            base64_url_encode(&[2u8]),
            base64_url_encode(&[3u8]),
        );

        let parsed = parse_registration_response(&json).unwrap();

        assert_eq!(parsed.extensions.hmac_secret, None);
    }

    #[test]
    fn registration_response_missing_id_is_an_error() {
        let json = format!(
            r#"{{"rawId":"{}","response":{{"attestationObject":"{}","clientDataJSON":"{}"}}}}"#,
            base64_url_encode(&[1u8]),
            base64_url_encode(&[2u8]),
            base64_url_encode(&[3u8]),
        );

        let err = parse_registration_response(&json).unwrap_err();
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
            base64_url_encode(&raw_id),
            base64_url_encode(&auth_data),
            base64_url_encode(&cdj),
            base64_url_encode(&sig),
            base64_url_encode(&user_handle),
            base64_url_encode(&prf_first),
            base64_url_encode(&prf_second),
        );

        let parsed = parse_authentication_response(&json).unwrap();

        assert_eq!(parsed.id, "credC");
        assert_eq!(parsed.raw_id.as_slice(), &raw_id);
        assert_eq!(parsed.response.signature.as_slice(), &sig);
        assert_eq!(
            parsed.response.user_handle.as_ref().unwrap().as_slice(),
            &user_handle
        );
        let hmac = parsed.extensions.hmac_get_secret.unwrap();
        assert_eq!(hmac.output1.as_slice(), &prf_first);
        assert_eq!(hmac.output2.unwrap().as_slice(), &prf_second);
    }

    #[test]
    fn authentication_response_prf_second_is_optional() {
        let prf_first = [7u8; 32];
        let json = format!(
            r#"{{"id":"credD","rawId":"{}","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"}},"prf":{{"first":"{}"}}}}"#,
            base64_url_encode(&[1u8]),
            base64_url_encode(&[2u8]),
            base64_url_encode(&[3u8]),
            base64_url_encode(&[4u8]),
            base64_url_encode(&prf_first),
        );

        let parsed = parse_authentication_response(&json).unwrap();

        // No userHandle in the JSON -> None.
        assert!(parsed.response.user_handle.is_none());
        let hmac = parsed.extensions.hmac_get_secret.unwrap();
        assert_eq!(hmac.output1.as_slice(), &prf_first);
        assert!(hmac.output2.is_none());
    }

    #[test]
    fn authentication_response_without_prf_has_no_hmac_output() {
        let json = format!(
            r#"{{"id":"credE","rawId":"{}","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"}}}}"#,
            base64_url_encode(&[1u8]),
            base64_url_encode(&[2u8]),
            base64_url_encode(&[3u8]),
            base64_url_encode(&[4u8]),
        );

        let parsed = parse_authentication_response(&json).unwrap();

        assert!(parsed.extensions.hmac_get_secret.is_none());
    }
}
