//! Shared base64url helpers.
//!
//! WebAuthn encodes binary fields as unpadded base64url, but some producers
//! (native bridges, hand-rolled JS) emit padding. Decoding accepts both;
//! encoding always produces the canonical unpadded form.

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};

/// Decode base64url, accepting both unpadded and padded input.
pub(crate) fn decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| URL_SAFE.decode(input))
}

/// Encode as unpadded base64url.
pub(crate) fn encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_unpadded_input() {
        assert_eq!(decode("AQID").unwrap(), [1, 2, 3]);
        assert_eq!(decode("AQI").unwrap(), [1, 2]);
    }

    #[test]
    fn decodes_padded_input() {
        assert_eq!(decode("AQ==").unwrap(), [1]);
        assert_eq!(decode("AQI=").unwrap(), [1, 2]);
        // A full quantum carries no padding, so "AQID" is already canonical.
        assert_eq!(decode("AQID").unwrap(), [1, 2, 3]);
    }

    #[test]
    fn rejects_padding_where_none_belongs() {
        assert!(decode("AQID==").is_err());
    }

    #[test]
    fn base64_url_round_trips() {
        let bytes = [0u8, 1, 2, 250, 251, 252, 253, 254, 255];
        let encoded = encode(&bytes);
        // URL-safe, unpadded: no '+', '/', or '=' may appear.
        assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
        assert_eq!(decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn base64_url_decode_rejects_invalid_input() {
        assert!(decode("not valid base64!!!").is_err());
    }
}
