use authenticator::{ctap2::server::PublicKeyCredentialUserEntity, StatusPinUv, StatusUpdate};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintEnrollmentFeedback {
  pub remaining_samples: u32,
  pub feedback: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum WebauthnEvent {
  SelectDevice,
  PresenceRequired,
  PinError(PinError),
  SelectKey {
    keys: Vec<PublicKeyCredentialUserEntity>,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum PinError {
  PinRequired,
  InvalidPin { attempts_remaining: Option<u8> },
  PinAuthBlocked,
  PinBlocked,
  InvalidUv { attempts_remaining: Option<u8> },
  UvBlocked,
}

impl From<StatusUpdate> for WebauthnEvent {
  fn from(status: StatusUpdate) -> Self {
    match status {
      StatusUpdate::SelectDeviceNotice => WebauthnEvent::SelectDevice,
      StatusUpdate::PresenceRequired => WebauthnEvent::PresenceRequired,
      StatusUpdate::PinUvError(pin_error) => WebauthnEvent::PinError(pin_error.into()),
      StatusUpdate::SelectResultNotice(.., users) => WebauthnEvent::SelectKey { keys: users },
      _ => unreachable!(),
    }
  }
}

impl From<StatusPinUv> for PinError {
  fn from(status: StatusPinUv) -> Self {
    match status {
      StatusPinUv::PinRequired(..) => PinError::PinRequired,
      StatusPinUv::InvalidPin(.., attempts) => PinError::InvalidPin {
        attempts_remaining: attempts,
      },
      StatusPinUv::PinAuthBlocked => PinError::PinAuthBlocked,
      StatusPinUv::PinBlocked => PinError::PinBlocked,
      StatusPinUv::InvalidUv(attempts) => PinError::InvalidUv {
        attempts_remaining: attempts,
      },
      StatusPinUv::UvBlocked => PinError::UvBlocked,
      _ => unreachable!(),
    }
  }
}
