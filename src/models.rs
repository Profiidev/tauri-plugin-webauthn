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
  PinEvent {
    event: PinEvent,
  },
  SelectKey {
    keys: Vec<PublicKeyCredentialUserEntity>,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum PinEvent {
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
      StatusUpdate::PinUvError(event) => WebauthnEvent::PinEvent {
        event: event.into(),
      },
      StatusUpdate::SelectResultNotice(.., users) => WebauthnEvent::SelectKey { keys: users },
      _ => unreachable!(),
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
      _ => unreachable!(),
    }
  }
}
