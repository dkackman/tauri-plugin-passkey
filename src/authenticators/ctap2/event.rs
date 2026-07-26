use authenticator::{ctap2::server::PublicKeyCredentialUserEntity, StatusPinUv, StatusUpdate};
use serde::{Deserialize, Serialize};

/// Nearly identical to the `StatusUpdate` enum, but serializable
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum WebauthnEvent {
  SelectDevice,
  PresenceRequired,
  PinEvent {
    event: PinEvent,
  },
  SelectKey {
    keys: Vec<PublicKeyCredentialUserEntity>,
  },
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
      StatusUpdate::SelectResultNotice(.., users) => Some(WebauthnEvent::SelectKey { keys: users }),
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
