//! Bridges browser-standard WebAuthn JSON (as produced by the DOM and
//! `@simplewebauthn/browser`) to the `webauthn-rs-proto` shapes the platform
//! authenticators consume, and translates the hmac-secret results back into the
//! browser `prf` extension so this plugin is a genuine drop-in.
//!
//! `webauthn-rs-proto` deviates from browser WebAuthn JSON in two ways handled here:
//!  - `authenticatorSelection.requireResidentKey` has no serde default, so a
//!    spec-compliant client that omits it fails to deserialize.
//!  - the PRF extension is modelled as CTAP2 hmac-secret (`hmacCreateSecret` /
//!    `hmacGetSecret`), not the browser `prf` object — and the output casing even
//!    differs between registration (`hmacSecret`) and assertion (`hmac_get_secret`).
//!
//! All translation is additive: callers already using the native hmac-secret shape
//! are left untouched.

use serde_json::{json, Map, Value};

/// Normalize creation (registration) options in place.
pub fn normalize_creation_options(options: &mut Value) {
    if let Some(selection) = options
        .get_mut("authenticatorSelection")
        .and_then(Value::as_object_mut)
    {
        if !selection.contains_key("requireResidentKey") {
            // residentKey "required" implies a resident key; anything else does not.
            let required = selection.get("residentKey").and_then(Value::as_str) == Some("required");
            selection.insert("requireResidentKey".into(), Value::Bool(required));
        }
    }

    if let Some(extensions) = options.get_mut("extensions").and_then(Value::as_object_mut) {
        // A browser `prf` object on registration just requests hmac-secret creation.
        if extensions.contains_key("prf") && !extensions.contains_key("hmacCreateSecret") {
            extensions.insert("hmacCreateSecret".into(), Value::Bool(true));
        }
    }
}

/// Normalize request (authentication) options in place.
pub fn normalize_request_options(options: &mut Value) {
    let Some(extensions) = options.get_mut("extensions").and_then(Value::as_object_mut) else {
        return;
    };
    if extensions.contains_key("hmacGetSecret") {
        return; // caller already used the native shape
    }
    // Browser `prf.eval.{first,second}` -> hmacGetSecret.{output1,output2}.
    let eval = extensions
        .get("prf")
        .and_then(|prf| prf.get("eval"))
        .and_then(Value::as_object)
        .cloned();
    if let Some(eval) = eval {
        if let Some(first) = eval.get("first").cloned() {
            let mut hmac = Map::new();
            hmac.insert("output1".into(), first);
            if let Some(second) = eval.get("second").cloned() {
                hmac.insert("output2".into(), second);
            }
            extensions.insert("hmacGetSecret".into(), Value::Object(hmac));
        }
    }
}

/// Expose a registration response's hmac-secret status as the browser
/// `clientExtensionResults.prf.enabled`.
pub fn add_prf_to_registration_response(response: &mut Value) {
    let enabled =
        extension_field(response, &["hmacSecret", "hmac_secret"]).and_then(Value::as_bool);
    if let Some(enabled) = enabled {
        set_client_extension(response, "prf", json!({ "enabled": enabled }));
    }
}

/// Expose an assertion response's hmac-secret output as the browser
/// `clientExtensionResults.prf.results.{first,second}`.
pub fn add_prf_to_assertion_response(response: &mut Value) {
    let Some(hmac) = extension_field(response, &["hmac_get_secret", "hmacGetSecret"]).cloned()
    else {
        return;
    };
    let Some(first) = hmac.get("output1").cloned() else {
        return;
    };
    let mut results = Map::new();
    results.insert("first".into(), first);
    if let Some(second) = hmac.get("output2").cloned() {
        if !second.is_null() {
            results.insert("second".into(), second);
        }
    }
    set_client_extension(
        response,
        "prf",
        json!({ "results": Value::Object(results) }),
    );
}

/// Read an extension output field, trying both the `extensions` and
/// `clientExtensionResults` containers and several key casings.
fn extension_field<'a>(response: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    for container in ["extensions", "clientExtensionResults"] {
        if let Some(obj) = response.get(container).and_then(Value::as_object) {
            for key in keys {
                if let Some(value) = obj.get(*key) {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Insert `key: value` into the response's `clientExtensionResults`, seeding it
/// from existing extension outputs so native fields (e.g. `hmac_get_secret`) are
/// preserved alongside the browser view.
fn set_client_extension(response: &mut Value, key: &str, value: Value) {
    let Some(obj) = response.as_object_mut() else {
        return;
    };
    let mut client_extension_results = obj
        .get("clientExtensionResults")
        .and_then(Value::as_object)
        .cloned()
        .or_else(|| obj.get("extensions").and_then(Value::as_object).cloned())
        .unwrap_or_default();
    client_extension_results.insert(key.into(), value);
    obj.insert(
        "clientExtensionResults".into(),
        Value::Object(client_extension_results),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_rs_proto::{
        PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    };

    #[test]
    fn creation_defaults_require_resident_key_when_absent() {
        let mut options = json!({
            "authenticatorSelection": { "residentKey": "discouraged", "userVerification": "required" }
        });
        normalize_creation_options(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(false)
        );
    }

    #[test]
    fn creation_require_resident_key_true_when_resident_key_required() {
        let mut options = json!({ "authenticatorSelection": { "residentKey": "required" } });
        normalize_creation_options(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(true)
        );
    }

    #[test]
    fn creation_does_not_clobber_explicit_require_resident_key() {
        let mut options = json!({
            "authenticatorSelection": { "residentKey": "required", "requireResidentKey": false }
        });
        normalize_creation_options(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(false)
        );
    }

    #[test]
    fn creation_prf_enables_hmac_create_secret() {
        let mut options = json!({ "extensions": { "prf": {} } });
        normalize_creation_options(&mut options);
        assert_eq!(options["extensions"]["hmacCreateSecret"], json!(true));
    }

    #[test]
    fn normalized_creation_options_deserialize() {
        // The exact browser JSON that previously failed with
        // "missing field `requireResidentKey`" plus a browser prf extension.
        let mut options = json!({
            "rp": { "id": "example.com", "name": "Example" },
            "user": { "id": "dXNlci1pZA", "name": "alice", "displayName": "Alice" },
            "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "residentKey": "discouraged", "userVerification": "required" },
            "attestation": "none",
            "extensions": { "prf": { "eval": { "first": "c2FsdA" } } }
        });
        normalize_creation_options(&mut options);
        let parsed: PublicKeyCredentialCreationOptions =
            serde_json::from_value(options).expect("normalized options must deserialize");
        assert_eq!(parsed.rp.id, "example.com");
        assert_eq!(
            parsed.extensions.expect("extensions").hmac_create_secret,
            Some(true)
        );
    }

    #[test]
    fn request_prf_eval_becomes_hmac_get_secret() {
        let mut options = json!({
            "challenge": "Y2g",
            "rpId": "example.com",
            "userVerification": "required",
            "allowCredentials": [],
            "extensions": { "prf": { "eval": { "first": "c2FsdDE", "second": "c2FsdDI" } } }
        });
        normalize_request_options(&mut options);
        assert_eq!(
            options["extensions"]["hmacGetSecret"]["output1"],
            json!("c2FsdDE")
        );
        assert_eq!(
            options["extensions"]["hmacGetSecret"]["output2"],
            json!("c2FsdDI")
        );

        let parsed: PublicKeyCredentialRequestOptions =
            serde_json::from_value(options).expect("normalized request options must deserialize");
        let hmac = parsed
            .extensions
            .expect("extensions")
            .hmac_get_secret
            .expect("hmac_get_secret");
        assert_eq!(hmac.output1.as_slice(), b"salt1");
    }

    #[test]
    fn request_native_hmac_get_secret_is_preserved() {
        let mut options = json!({
            "extensions": { "hmacGetSecret": { "output1": "c2FsdA" }, "prf": { "eval": { "first": "b3RoZXI" } } }
        });
        normalize_request_options(&mut options);
        // Existing native shape wins; prf is not used to overwrite it.
        assert_eq!(
            options["extensions"]["hmacGetSecret"]["output1"],
            json!("c2FsdA")
        );
    }

    #[test]
    fn assertion_response_gains_browser_prf_results() {
        // webauthn-rs-proto assertion output uses snake_case hmac_get_secret.
        let mut response = json!({
            "id": "cred",
            "extensions": { "hmac_get_secret": { "output1": "c2VjcmV0", "output2": null } }
        });
        add_prf_to_assertion_response(&mut response);
        assert_eq!(
            response["clientExtensionResults"]["prf"]["results"]["first"],
            json!("c2VjcmV0")
        );
        assert!(response["clientExtensionResults"]["prf"]["results"]
            .get("second")
            .is_none());
        // native field preserved alongside the browser view
        assert_eq!(
            response["clientExtensionResults"]["hmac_get_secret"]["output1"],
            json!("c2VjcmV0")
        );
        assert_eq!(
            response["extensions"]["hmac_get_secret"]["output1"],
            json!("c2VjcmV0")
        );
    }

    #[test]
    fn registration_response_gains_browser_prf_enabled() {
        // webauthn-rs-proto registration output uses camelCase hmacSecret.
        let mut response = json!({ "id": "cred", "extensions": { "hmacSecret": true } });
        add_prf_to_registration_response(&mut response);
        assert_eq!(
            response["clientExtensionResults"]["prf"]["enabled"],
            json!(true)
        );
    }

    #[test]
    fn assertion_response_without_hmac_is_unchanged() {
        let mut response = json!({ "id": "cred", "extensions": {} });
        add_prf_to_assertion_response(&mut response);
        assert!(response.get("clientExtensionResults").is_none());
    }
}
