use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(mobile)]
    #[error(transparent)]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
    #[cfg(all(desktop, windows))]
    #[error("WebAuthn error: {0:?}")]
    WebAuthn(webauthn_authenticator_rs::error::WebauthnCError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("No token found")]
    NoToken,
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Authenticator error: {0}")]
    Authenticator(String),
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "windows",
        target_os = "macos"
    )))]
    #[error(transparent)]
    Ctap2(#[from] authenticator::errors::AuthenticatorError),
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "windows",
        target_os = "macos"
    )))]
    #[error(transparent)]
    Cbor2(#[from] serde_cbor_2::Error),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The webview receives errors as a JSON string, not a tagged object: the
    // custom Serialize impl flattens each variant to its Display text. These
    // tests pin that contract (and the Display formats) since the frontend has
    // nothing else to match on.
    #[test]
    fn serializes_to_a_bare_display_string() {
        let json = serde_json::to_string(&Error::Validation("bad rp_id".to_string())).unwrap();
        assert_eq!(json, "\"Validation error: bad rp_id\"");
    }

    #[test]
    fn authenticator_error_uses_its_display_text() {
        let json =
            serde_json::to_string(&Error::Authenticator("no credential id".to_string())).unwrap();
        assert_eq!(json, "\"Authenticator error: no credential id\"");
    }

    #[test]
    fn unit_variant_serializes_to_its_message() {
        let json = serde_json::to_string(&Error::NoToken).unwrap();
        assert_eq!(json, "\"No token found\"");
    }

    #[test]
    fn serialized_error_is_a_json_string_not_an_object() {
        // Regression guard: a derived Serialize would emit {"Validation": ...};
        // the frontend contract depends on it being a plain string.
        let value: serde_json::Value =
            serde_json::to_value(Error::Validation("x".to_string())).unwrap();
        assert!(value.is_string());
    }
}
