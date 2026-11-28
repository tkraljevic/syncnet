//! A byte field read exactly as Go's `encoding/json` reads a `[]byte` field.
//!
//! Go takes three shapes for such a field, and a value that one side takes and the other
//! refuses would split the network:
//!
//! - a string, read as `base64.StdEncoding` reads it (see [`crate::wire::go_base64`]): `\r`
//!   and `\n` skipped, leftover bits in the last character not checked, no trimming;
//! - `null`, which gives no bytes;
//! - an array of whole numbers from 0 to 255, where `null` stands for 0.
//!
//! Anything else is an error, as in Go: `1.0`, `1e0`, `-0`, numbers over 255, `true`,
//! strings or arrays inside the array, objects. Writing is unchanged: always a base64
//! string with padding.

use crate::wire::go_base64::decode_std;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serializer;
use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use std::fmt;

pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&STANDARD.encode(bytes))
}

/// Reads a `[]byte` field as Go does; `null` gives no bytes.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(BytesVisitor)
}

/// The same for a field that may be missing; `null` reads as missing.
pub mod opt {
    use super::*;

    pub fn serialize<S>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_option(OptBytesVisitor)
    }

    struct OptBytesVisitor;

    impl<'de> Visitor<'de> for OptBytesVisitor {
        type Value = Option<Vec<u8>>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("base64 niz, null ili niz brojeva od 0 do 255")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            super::deserialize(deserializer).map(Some)
        }
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("base64 niz, null ili niz brojeva od 0 do 255")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        decode_std(v).map_err(E::custom)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
        while let Some(GoByte(b)) = seq.next_element()? {
            out.push(b);
        }
        Ok(out)
    }
}

/// One element of the array form: a whole number from 0 to 255, or `null` for 0.
struct GoByte(u8);

impl<'de> Deserialize<'de> for GoByte {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(GoByteVisitor)
    }
}

struct GoByteVisitor;

impl<'de> Visitor<'de> for GoByteVisitor {
    type Value = GoByte;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cijeli broj od 0 do 255 ili null")
    }

    // serde_json hands a non-negative whole number here; a negative one, `-0`, a fraction
    // or an exponent arrives as i64 or f64 and is refused by the default, as Go refuses it.
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        u8::try_from(v)
            .map(GoByte)
            .map_err(|_| E::custom(format!("broj {v} ne stane u bajt")))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(GoByte(0))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Required {
        #[serde(with = "super")]
        potpis: Vec<u8>,
    }

    #[derive(Deserialize)]
    struct Optional {
        #[serde(default, with = "super::opt")]
        vj: Option<Vec<u8>>,
    }

    /// Each text is the JSON value of the field as it stands on the wire. The second
    /// column is what Go's `json.Unmarshal` puts into a `[]byte` field (`json:"potpis"` and
    /// `json:"vj,omitempty"` give the same, and so does `json.Decoder`): `nil`, `hex:...`
    /// or `GRESKA`. Measured with go1.27.1. The third column is what the old reader
    /// (`STANDARD.decode` of a string) did: `prima` or `odbija`.
    const EDGES: &[(&str, &str, &str)] = &[
        (r#""AA==""#, "hex:00", "prima"),
        (r#""AQ==""#, "hex:01", "prima"),
        (r#""AAAA""#, "hex:000000", "prima"),
        (r#""""#, "hex:", "prima"),
        (r#""\/\/\/\/""#, "hex:ffffff", "prima"),
        (r#""+/+/""#, "hex:fbffbf", "prima"),
        // Go takes these, the old reader did not.
        (r#""AB==""#, "hex:00", "odbija"),
        (r#""AP==""#, "hex:00", "odbija"),
        (r#""AAB=""#, "hex:0000", "odbija"),
        (r#""AA==\n""#, "hex:00", "odbija"),
        (r#""\nAA==""#, "hex:00", "odbija"),
        (r#""A\r\nA==""#, "hex:00", "odbija"),
        (r#""AA=\n=""#, "hex:00", "odbija"),
        (r#""AA\r\n==""#, "hex:00", "odbija"),
        (r#""\r\n""#, "hex:", "odbija"),
        (r#""\n""#, "hex:", "odbija"),
        (r#""AA==\r""#, "hex:00", "odbija"),
        (r#""\u000aAA==""#, "hex:00", "odbija"),
        (r#""AA\u000d\u000a==""#, "hex:00", "odbija"),
        (r#""AA==\r\n\r\n""#, "hex:00", "odbija"),
        (r#""AAAA\nAAAA""#, "hex:000000000000", "odbija"),
        ("null", "nil", "odbija"),
        ("[]", "hex:", "odbija"),
        ("[0,1,255]", "hex:0001ff", "odbija"),
        ("[0]", "hex:00", "odbija"),
        ("[null]", "hex:00", "odbija"),
        ("[null,1]", "hex:0001", "odbija"),
        // Both refuse these.
        (r#""AA""#, "GRESKA", "odbija"),
        (r#""AAA""#, "GRESKA", "odbija"),
        (r#""A""#, "GRESKA", "odbija"),
        (r#""AA=""#, "GRESKA", "odbija"),
        (r#""AA===""#, "GRESKA", "odbija"),
        (r#""AAAA=""#, "GRESKA", "odbija"),
        (r#""AA==AA==""#, "GRESKA", "odbija"),
        (r#""-_-_""#, "GRESKA", "odbija"),
        (r#""AA-=""#, "GRESKA", "odbija"),
        (r#"" AA==""#, "GRESKA", "odbija"),
        (r#""AA== ""#, "GRESKA", "odbija"),
        (r#""AA==\t""#, "GRESKA", "odbija"),
        (r#""AA ==""#, "GRESKA", "odbija"),
        // U+2028 before the text, written out: it looks like a space.
        ("\"\u{2028}AA==\"", "GRESKA", "odbija"),
        (r#""AA\u000b==""#, "GRESKA", "odbija"),
        (r#""AA==\u0000""#, "GRESKA", "odbija"),
        ("\"AA\n==\"", "GRESKA", "odbija"),
        ("[256]", "GRESKA", "odbija"),
        ("[-1]", "GRESKA", "odbija"),
        ("[-0]", "GRESKA", "odbija"),
        ("[1.0]", "GRESKA", "odbija"),
        ("[1e0]", "GRESKA", "odbija"),
        (r#"["A"]"#, "GRESKA", "odbija"),
        ("[true]", "GRESKA", "odbija"),
        ("[[1]]", "GRESKA", "odbija"),
        ("123", "GRESKA", "odbija"),
        ("true", "GRESKA", "odbija"),
        ("{}", "GRESKA", "odbija"),
    ];

    fn old_reader(text: &str) -> &'static str {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let ok = serde_json::from_str::<String>(text)
            .ok()
            .is_some_and(|s| STANDARD.decode(s).is_ok());
        if ok { "prima" } else { "odbija" }
    }

    #[test]
    fn reads_bytes_as_go_does() {
        let mut newly_taken = 0;
        for (text, go, old) in EDGES {
            // A missing `[]byte` and `null` are the same in Go: no bytes.
            let want = match *go {
                "GRESKA" => None,
                "nil" => Some(String::new()),
                hex => Some(hex.strip_prefix("hex:").unwrap().to_owned()),
            };
            let got = serde_json::from_str::<Required>(&format!(r#"{{"potpis":{text}}}"#))
                .ok()
                .map(|r| hex::encode(r.potpis));
            assert_eq!(got, want, "obavezno polje, {text}");

            let want_opt = match *go {
                "GRESKA" => None,
                "nil" => Some(None),
                hex => Some(Some(hex.strip_prefix("hex:").unwrap().to_owned())),
            };
            let got_opt = serde_json::from_str::<Optional>(&format!(r#"{{"vj":{text}}}"#))
                .ok()
                .map(|r| r.vj.map(hex::encode));
            assert_eq!(got_opt, want_opt, "neobavezno polje, {text}");

            assert_eq!(old_reader(text), *old, "stari čitač, {text}");
            if *old == "odbija" && *go != "GRESKA" {
                newly_taken += 1;
            }
        }
        assert!(newly_taken >= 14, "{newly_taken}");
    }

    /// 64 bytes 0x00..0x3f, the size of a signature, written several ways. Go reads the
    /// first five and the array as the same 64 bytes and refuses the rest (go1.27.1).
    #[test]
    fn reads_a_signature_sized_value_as_go_does() {
        let want: Vec<u8> = (0u8..64).collect();
        let std = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
        let arr = format!(
            "[{}]",
            (0..64).map(|i| i.to_string()).collect::<Vec<_>>().join(",")
        );
        let cases: Vec<(String, bool)> = vec![
            (format!("\"{std}\""), true),
            (format!("\"{}x==\"", &std[..85]), true),
            (format!("\"{}/==\"", &std[..85]), true),
            (format!("\"{}\\n{}\"", &std[..76], &std[76..]), true),
            (format!("\"{}\\r\\n{}\"", &std[..76], &std[76..]), true),
            (arr, true),
            (format!("\"{}\"", std.trim_end_matches('=')), false),
            (format!("\"{} {}\"", &std[..76], &std[76..]), false),
        ];
        for (text, go_same) in cases {
            let got = serde_json::from_str::<Required>(&format!(r#"{{"potpis":{text}}}"#))
                .ok()
                .map(|r| r.potpis);
            assert_eq!(got.as_ref() == Some(&want), go_same, "{text}");
            assert_eq!(got.is_some(), go_same, "{text}");
        }
    }
}
