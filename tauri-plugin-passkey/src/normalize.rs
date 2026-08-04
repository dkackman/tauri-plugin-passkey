//! Reconciles browser WebAuthn JSON with `webauthn-rs-proto`'s deserializer.
//!
//! The one remaining gap: `authenticatorSelection.requireResidentKey` has no serde
//! default in the proto crate, so a spec-compliant client that omits it (the DOM
//! type marks it optional and deprecated) fails to deserialize. PRF is not handled
//! here — see [`crate::prf`].

use serde_json::Value;

/// Fill in `requireResidentKey` from `residentKey` when the caller omitted it.
pub fn default_require_resident_key(options: &mut Value) {
    let Some(selection) = options
        .get_mut("authenticatorSelection")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    if selection.contains_key("requireResidentKey") {
        return;
    }
    // residentKey "required" implies a resident key; anything else does not.
    let required = selection.get("residentKey").and_then(Value::as_str) == Some("required");
    selection.insert("requireResidentKey".into(), Value::Bool(required));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_require_resident_key_when_absent() {
        let mut options = json!({
            "authenticatorSelection": { "residentKey": "discouraged", "userVerification": "required" }
        });
        default_require_resident_key(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(false)
        );
    }

    #[test]
    fn require_resident_key_true_when_resident_key_required() {
        let mut options = json!({ "authenticatorSelection": { "residentKey": "required" } });
        default_require_resident_key(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(true)
        );
    }

    #[test]
    fn does_not_clobber_explicit_require_resident_key() {
        let mut options = json!({
            "authenticatorSelection": { "residentKey": "required", "requireResidentKey": false }
        });
        default_require_resident_key(&mut options);
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            json!(false)
        );
    }
}
