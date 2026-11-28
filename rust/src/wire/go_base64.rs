//! Base64 read exactly as Go's `base64.StdEncoding.DecodeString` reads it.
//!
//! Go differs from a strict reader in two ways, and a value that one side takes and the
//! other refuses would split the network:
//!
//! - `\r` and `\n` are skipped wherever they stand, even inside the padding;
//! - the bits left over in the last character are not checked, so `...1x=` gives the same
//!   bytes as `...1w=`.
//!
//! Everything else is as strict as the standard alphabet allows: the `=` padding must be
//! there and be right, and spaces, tabs or the URL-safe characters `-` and `_` are errors.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

const GO_STD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Decodes `text` as Go's `base64.StdEncoding.DecodeString` does.
pub fn decode_std(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if text.contains(['\r', '\n']) {
        GO_STD.decode(text.replace(['\r', '\n'], ""))
    } else {
        GO_STD.decode(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Go's `base64.StdEncoding.DecodeString` gives for each text: the bytes in hex,
    /// or `None` for an error.
    #[test]
    fn decodes_as_go_does() {
        let cases: &[(&str, Option<&str>)] = &[
            ("", Some("")),
            ("\n", Some("")),
            ("\r\n\r\n", Some("")),
            ("AA==", Some("00")),
            ("AB==", Some("00")),
            ("AP==", Some("00")),
            ("AQ==", Some("01")),
            ("AAA=", Some("0000")),
            ("AAB=", Some("0000")),
            ("AAAA", Some("000000")),
            ("A\nA==", Some("00")),
            ("AA=\n=", Some("00")),
            ("AA==\n", Some("00")),
            ("\nAA==", Some("00")),
            ("AA\r\n==", Some("00")),
            ("+/+/", Some("fbffbf")),
            ("AA", None),
            ("AAA", None),
            ("A", None),
            ("A===", None),
            ("AA=", None),
            ("AA===", None),
            ("AAA==", None),
            ("=", None),
            ("====", None),
            ("AA==AA==", None),
            ("AAAA=", None),
            ("AA ==", None),
            (" AA==", None),
            ("AA==\t", None),
            ("-_-_", None),
            ("AA\x0b==", None),
            ("AA\n==\r\n", Some("00")),
            ("A A\n==", None),
            ("AA==\n ", None),
            ("\tAA\n==", None),
        ];
        for (text, want) in cases {
            let got = decode_std(text).ok().map(hex::encode);
            assert_eq!(got.as_deref(), *want, "{text:?}");
        }
    }
}
