use authenticator::{ctap2::server::PublicKeyCredentialUserEntity, StatusPinUv, StatusUpdate};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// Nearly identical to the `StatusUpdate` enum, but serializable
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum WebauthnEvent {
    SelectDevice,
    PresenceRequired,
    PinEvent { event: PinEvent },
    SelectKey { keys: Vec<SelectKeyUser> },
}

/// User entry offered to the frontend for key selection. `id` is the
/// credential user handle, base64url-encoded (unpadded) — the crate's own
/// type would serialize it as a JSON number array, which does not match the
/// TS `AuthKey` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectKeyUser {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl From<PublicKeyCredentialUserEntity> for SelectKeyUser {
    fn from(user: PublicKeyCredentialUserEntity) -> Self {
        SelectKeyUser {
            id: BASE64_URL_SAFE_NO_PAD.encode(&user.id),
            name: user.name,
            display_name: user.display_name,
        }
    }
}

/// Nearly identical to the `StatusPinUv` enum, but serializable
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum PinEvent {
    PinRequired,
    InvalidPin { attempts_remaining: Option<u8> },
    PinAuthBlocked,
    PinBlocked,
    InvalidUv { attempts_remaining: Option<u8> },
    UvBlocked,
    PinIsTooShort,
    PinIsTooLong { max_length: usize },
    PinNotSet,
}

impl WebauthnEvent {
    /// Returns `None` for status updates that have no user-facing equivalent
    /// (interactive token management, which this plugin does not drive).
    pub fn from_status(status: StatusUpdate) -> Option<Self> {
        match status {
            StatusUpdate::SelectDeviceNotice => Some(WebauthnEvent::SelectDevice),
            StatusUpdate::PresenceRequired => Some(WebauthnEvent::PresenceRequired),
            StatusUpdate::PinUvError(event) => Some(WebauthnEvent::PinEvent {
                event: event.into(),
            }),
            StatusUpdate::SelectResultNotice(.., users) => Some(WebauthnEvent::SelectKey {
                keys: users.into_iter().map(Into::into).collect(),
            }),
            StatusUpdate::InteractiveManagement(..) => None,
        }
    }
}

impl From<StatusPinUv> for PinEvent {
    fn from(status: StatusPinUv) -> Self {
        match status {
            StatusPinUv::PinRequired(..) => PinEvent::PinRequired,
            StatusPinUv::InvalidPin(.., attempts) => PinEvent::InvalidPin {
                attempts_remaining: attempts,
            },
            StatusPinUv::PinAuthBlocked => PinEvent::PinAuthBlocked,
            StatusPinUv::PinBlocked => PinEvent::PinBlocked,
            StatusPinUv::InvalidUv(attempts) => PinEvent::InvalidUv {
                attempts_remaining: attempts,
            },
            StatusPinUv::UvBlocked => PinEvent::UvBlocked,
            StatusPinUv::PinIsTooShort => PinEvent::PinIsTooShort,
            StatusPinUv::PinIsTooLong(max_length) => PinEvent::PinIsTooLong { max_length },
            StatusPinUv::PinNotSet => PinEvent::PinNotSet,
        }
    }
}
