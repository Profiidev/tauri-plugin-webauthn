use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintEnrollmentFeedback {
  pub remaining_samples: u32,
  pub feedback: Option<u8>,
}
