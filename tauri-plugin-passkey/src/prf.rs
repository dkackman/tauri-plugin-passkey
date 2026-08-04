//! The browser `prf` extension, which is this plugin's only PRF spelling.
//!
//! PRF does not travel inside the `webauthn-rs-proto` options, because that crate
//! models the extension as CTAP2 `hmac-secret`. It crosses the `Authenticator`
//! trait as its own typed value, and at that boundary it always means *browser*
//! PRF: salts are the caller's raw `prf.eval.{first,second}` bytes, of any length.
//!
//! Backends that hand the salt to a native WebAuthn layer (ASAuthorization on
//! Apple, Credential Manager on Android) pass it through untouched — those layers
//! apply the spec's derivation themselves. A backend speaking raw CTAP2 must call
//! [`ctap_salt`] first.

// `set_registration_prf_input`/`set_authentication_prf_input` (and the
// `extensions_mut` helper behind them) are only called from `mobile.rs`, which is
// `#[cfg(mobile)]` and so does not compile on this desktop target; `ctap_salt` is
// unused until Task 3 wires it into the CTAP2 salt conversion. Kept `pub` for the
// backends/tasks that do use them.
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The caller requested PRF at registration. Carries no salts: evaluating a salt
/// during creation is not supported (see `registration_input_from_options`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrfRegistrationInput;

/// `prf.eval` — browser-level salts, any length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfAuthenticationInput {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

/// `clientExtensionResults.prf.enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrfRegistrationOutput {
    pub enabled: bool,
}

/// `clientExtensionResults.prf.results`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfAuthenticationOutput {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

/// Derive the CTAP2 `hmac-secret` salt from a browser PRF salt:
/// `SHA-256(UTF8("WebAuthn PRF") || 0x00 || salt)`.
///
/// Only raw-CTAP2 backends need this. Native WebAuthn layers do it internally,
/// and applying it twice yields a different — silently wrong — secret.
pub fn ctap_salt(salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"WebAuthn PRF");
    hasher.update([0u8]);
    hasher.update(salt);
    hasher.finalize().into()
}

fn extensions(options: &Value) -> Option<&Map<String, Value>> {
    options.get("extensions").and_then(Value::as_object)
}

fn decode_salt(value: &Value, field: &str) -> crate::Result<Vec<u8>> {
    let encoded = value.as_str().ok_or_else(|| {
        crate::Error::Validation(format!("prf.eval.{field} must be a base64url string"))
    })?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        crate::Error::Validation(format!("prf.eval.{field} is not valid base64url: {e}"))
    })
}

/// Read the `prf` extension from browser creation options.
pub fn registration_input_from_options(
    options: &Value,
) -> crate::Result<Option<PrfRegistrationInput>> {
    let Some(prf) = extensions(options).and_then(|e| e.get("prf")) else {
        return Ok(None);
    };
    if prf.get("eval").is_some() {
        return Err(crate::Error::Unsupported(
            "prf.eval at registration is not supported; register with `prf: {}` and evaluate \
             salts during authentication"
                .into(),
        ));
    }
    Ok(Some(PrfRegistrationInput))
}

/// Read the `prf.eval` salts from browser request options.
pub fn authentication_input_from_options(
    options: &Value,
) -> crate::Result<Option<PrfAuthenticationInput>> {
    let Some(prf) = extensions(options).and_then(|e| e.get("prf")) else {
        return Ok(None);
    };
    let first = prf
        .get("eval")
        .and_then(|e| e.get("first"))
        .ok_or_else(|| {
            crate::Error::Validation("prf.eval.first is required when prf is requested".into())
        })?;
    let second = prf
        .get("eval")
        .and_then(|e| e.get("second"))
        .map(|v| decode_salt(v, "second"))
        .transpose()?;
    Ok(Some(PrfAuthenticationInput {
        first: decode_salt(first, "first")?,
        second,
    }))
}

fn extensions_mut(options: &mut Value) -> Option<&mut Map<String, Value>> {
    let obj = options.as_object_mut()?;
    obj.entry("extensions")
        .or_insert_with(|| Value::Object(Map::new()));
    obj.get_mut("extensions").and_then(Value::as_object_mut)
}

/// Write `extensions.prf = {}` into options bound for a native WebAuthn layer.
pub fn set_registration_prf_input(options: &mut Value) {
    if let Some(extensions) = extensions_mut(options) {
        extensions.insert("prf".into(), json!({}));
    }
}

/// Write `extensions.prf.eval` into options bound for a native WebAuthn layer.
pub fn set_authentication_prf_input(options: &mut Value, prf: &PrfAuthenticationInput) {
    let mut eval = Map::new();
    eval.insert("first".into(), json!(URL_SAFE_NO_PAD.encode(&prf.first)));
    if let Some(second) = &prf.second {
        eval.insert("second".into(), json!(URL_SAFE_NO_PAD.encode(second)));
    }
    if let Some(extensions) = extensions_mut(options) {
        extensions.insert("prf".into(), json!({ "eval": Value::Object(eval) }));
    }
}

/// Move the credential's serialized `extensions` to the browser's
/// `clientExtensionResults` key and insert `prf` if there is one.
fn set_client_extension_results(response: &mut Value, prf: Option<Value>) {
    let Some(obj) = response.as_object_mut() else {
        return;
    };
    let mut results = obj
        .remove("extensions")
        .or_else(|| obj.remove("clientExtensionResults"))
        .and_then(|v| match v {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(prf) = prf {
        results.insert("prf".into(), prf);
    }
    obj.insert("clientExtensionResults".into(), Value::Object(results));
}

/// Publish `clientExtensionResults.prf.enabled`.
pub fn set_registration_prf(response: &mut Value, prf: Option<PrfRegistrationOutput>) {
    set_client_extension_results(response, prf.map(|p| json!({ "enabled": p.enabled })));
}

/// Publish `clientExtensionResults.prf.results`.
pub fn set_authentication_prf(response: &mut Value, prf: Option<PrfAuthenticationOutput>) {
    let prf = prf.map(|p| {
        let mut results = Map::new();
        results.insert("first".into(), json!(URL_SAFE_NO_PAD.encode(&p.first)));
        if let Some(second) = &p.second {
            results.insert("second".into(), json!(URL_SAFE_NO_PAD.encode(second)));
        }
        json!({ "results": Value::Object(results) })
    });
    set_client_extension_results(response, prf);
}

/// Parse the flat top-level `prf` object the Swift and Kotlin bridges resolve.
pub fn registration_output_from_bridge(v: &Value) -> Option<PrfRegistrationOutput> {
    let enabled = v.get("prf")?.get("enabled")?.as_bool()?;
    Some(PrfRegistrationOutput { enabled })
}

/// Parse the flat top-level `prf` object the Swift and Kotlin bridges resolve.
pub fn authentication_output_from_bridge(v: &Value) -> Option<PrfAuthenticationOutput> {
    let prf = v.get("prf")?;
    let decode = |key: &str| {
        prf.get(key)
            .and_then(Value::as_str)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
    };
    Some(PrfAuthenticationOutput {
        first: decode("first")?,
        second: decode("second"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // SHA-256("WebAuthn PRF" || 0x00 || "salt1"), computed from the spec definition.
    const SALT1_DERIVED: &str = "2a1990f9c9bbfe1bbf56abee2b5a0f59be5f633a35c2a5f07d85533eeecbdd3c";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn ctap_salt_matches_the_spec_vector() {
        assert_eq!(hex(&ctap_salt(b"salt1")), SALT1_DERIVED);
    }

    #[test]
    fn ctap_salt_accepts_any_input_length() {
        // Browser PRF salts are arbitrary length; the digest is always 32 bytes.
        assert_eq!(ctap_salt(b"").len(), 32);
        assert_eq!(ctap_salt(&[0u8; 64]).len(), 32);
        assert_ne!(ctap_salt(b"a"), ctap_salt(b"b"));
    }

    #[test]
    fn registration_input_detects_prf() {
        let options = json!({ "extensions": { "prf": {} } });
        assert!(registration_input_from_options(&options).unwrap().is_some());
    }

    #[test]
    fn registration_input_absent_without_prf() {
        assert!(registration_input_from_options(&json!({}))
            .unwrap()
            .is_none());
        assert!(
            registration_input_from_options(&json!({ "extensions": {} }))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn registration_input_rejects_eval() {
        let options = json!({ "extensions": { "prf": { "eval": { "first": "c2FsdDE" } } } });
        let err = registration_input_from_options(&options).unwrap_err();
        assert_eq!(err.kind(), "unsupported");
    }

    #[test]
    fn authentication_input_decodes_both_salts() {
        let options = json!({
            "extensions": { "prf": { "eval": { "first": "c2FsdDE", "second": "c2FsdDI" } } }
        });
        let input = authentication_input_from_options(&options)
            .unwrap()
            .unwrap();
        assert_eq!(input.first, b"salt1");
        assert_eq!(input.second.as_deref(), Some(&b"salt2"[..]));
    }

    #[test]
    fn authentication_input_accepts_non_32_byte_salts() {
        // "eA" is base64url for a single byte; browser PRF puts no length limit on salts.
        let options = json!({ "extensions": { "prf": { "eval": { "first": "eA" } } } });
        let input = authentication_input_from_options(&options)
            .unwrap()
            .unwrap();
        assert_eq!(input.first, b"x");
        assert!(input.second.is_none());
    }

    #[test]
    fn authentication_input_requires_eval_first() {
        let options = json!({ "extensions": { "prf": {} } });
        let err = authentication_input_from_options(&options).unwrap_err();
        assert_eq!(err.kind(), "validation");
    }

    #[test]
    fn authentication_input_rejects_bad_base64() {
        let options = json!({ "extensions": { "prf": { "eval": { "first": "!!!" } } } });
        let err = authentication_input_from_options(&options).unwrap_err();
        assert_eq!(err.kind(), "validation");
    }

    #[test]
    fn prf_inputs_are_written_into_options_json() {
        let mut options = json!({ "rpId": "example.com" });
        set_registration_prf_input(&mut options);
        assert_eq!(options["extensions"]["prf"], json!({}));

        let mut options = json!({ "rpId": "example.com" });
        set_authentication_prf_input(
            &mut options,
            &PrfAuthenticationInput {
                first: b"salt1".to_vec(),
                second: Some(b"salt2".to_vec()),
            },
        );
        assert_eq!(
            options["extensions"]["prf"]["eval"],
            json!({ "first": "c2FsdDE", "second": "c2FsdDI" })
        );
    }

    #[test]
    fn registration_output_becomes_client_extension_results() {
        // webauthn-rs-proto serializes credential extensions under `extensions`;
        // the browser contract is `clientExtensionResults`.
        let mut response = json!({ "id": "cred", "extensions": { "credProps": { "rk": true } } });
        set_registration_prf(&mut response, Some(PrfRegistrationOutput { enabled: true }));
        assert_eq!(
            response["clientExtensionResults"]["prf"],
            json!({ "enabled": true })
        );
        // pre-existing extension outputs survive the move
        assert_eq!(
            response["clientExtensionResults"]["credProps"],
            json!({ "rk": true })
        );
        assert!(response.get("extensions").is_none());
    }

    #[test]
    fn registration_output_absent_leaves_empty_client_extension_results() {
        let mut response = json!({ "id": "cred", "extensions": {} });
        set_registration_prf(&mut response, None);
        assert_eq!(response["clientExtensionResults"], json!({}));
        assert!(response.get("extensions").is_none());
    }

    #[test]
    fn authentication_output_becomes_prf_results() {
        let mut response = json!({ "id": "cred", "extensions": {} });
        set_authentication_prf(
            &mut response,
            Some(PrfAuthenticationOutput {
                first: b"secret".to_vec(),
                second: None,
            }),
        );
        assert_eq!(
            response["clientExtensionResults"]["prf"]["results"]["first"],
            json!("c2VjcmV0")
        );
        assert!(response["clientExtensionResults"]["prf"]["results"]
            .get("second")
            .is_none());
    }

    #[test]
    fn bridge_outputs_are_parsed_from_the_flat_prf_object() {
        // Both Swift bridges and the Kotlin plugin resolve a flat top-level `prf`.
        let v = json!({ "id": "cred", "prf": { "enabled": true } });
        assert_eq!(
            registration_output_from_bridge(&v),
            Some(PrfRegistrationOutput { enabled: true })
        );

        let v = json!({ "id": "cred", "prf": { "first": "c2VjcmV0", "second": "c2Vjb25k" } });
        assert_eq!(
            authentication_output_from_bridge(&v),
            Some(PrfAuthenticationOutput {
                first: b"secret".to_vec(),
                second: Some(b"second".to_vec()),
            })
        );

        assert!(registration_output_from_bridge(&json!({ "id": "cred" })).is_none());
        assert!(authentication_output_from_bridge(&json!({ "id": "cred" })).is_none());
    }
}
