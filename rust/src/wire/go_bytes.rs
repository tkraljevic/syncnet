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
//!
//! When such a field comes more than once in an object, Go reads each value into the bytes
//! the field already holds: a base64 string and an array write over the old
//! bytes from the start, an element `null` leaves the old byte, and bytes past the end of a
//! shorter value come back when a later array is longer. `null` and `[]` start again.

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

/// The bytes Go leaves in a `[]byte` field read from `values`, one after another, each as
/// its JSON text (lone surrogates and bytes that are not UTF-8 already read as Go reads
/// them): `None` when the field ends as Go's nil slice (`null`, or no value at all), else
/// the field as a base64 string. Measured with go1.27.1:
///
/// - a base64 string is decoded into the bytes the field holds, as
///   `base64.StdEncoding.AppendDecode(old[:0], text)` writes them ([`go_decode_into`]); the
///   field is as long as the decoded bytes, and the old bytes past them stay in its buffer;
/// - an array writes element `i` over byte `i`; a `null` element leaves byte `i` as it was in
///   the buffer (0 where nothing was ever written); the field is as long as the array;
/// - `null` and `[]` start a new, empty buffer; `""` keeps the old one.
///
/// Every value has already been checked to read as a `[]byte`.
pub(crate) fn merged(values: &[&str]) -> Result<Option<String>, String> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut len = 0;
    let mut nil = true;
    for text in values {
        let text = text.trim_matches([' ', '\t', '\n', '\r']);
        if text == "null" {
            buffer.clear();
            (len, nil) = (0, true);
        } else if text.starts_with('[') {
            let elements: Vec<Box<serde_json::value::RawValue>> =
                serde_json::from_str(text).map_err(|e| e.to_string())?;
            if elements.is_empty() {
                buffer.clear();
            }
            for (i, element) in elements.iter().enumerate() {
                if i == buffer.len() {
                    buffer.push(0);
                }
                if element.get() != "null" {
                    let GoByte(b) =
                        serde_json::from_str(element.get()).map_err(|e| e.to_string())?;
                    buffer[i] = b;
                }
            }
            (len, nil) = (elements.len(), false);
        } else {
            let s: String = serde_json::from_str(text).map_err(|e| e.to_string())?;
            len = go_decode_into(&mut buffer, s.as_bytes())
                .ok_or_else(|| "base64 koji Go ne čita".to_owned())?;
            nil = false;
        }
    }
    if nil {
        return Ok(values.last().map(|_| "null".to_owned()));
    }
    buffer.resize(buffer.len().max(len), 0);
    Ok(Some(format!("\"{}\"", STANDARD.encode(&buffer[..len]))))
}

/// Go's `base64.StdEncoding.AppendDecode(buffer[:0], src)` on a 64-bit machine: how many
/// bytes it decodes into the start of `buffer`, or `None` for an error. It writes as Go's
/// `Decode` writes: eight characters at a time put eight bytes (six of them decoded, two
/// zero) and four at a time four (three and a zero), and the next step writes over the
/// zeros. Where a line break makes the text decode to fewer bytes than its length
/// promises, the last zeros stay and cover old bytes, as in Go. `buffer` grows with zeros
/// to the length Go reserves.
fn go_decode_into(buffer: &mut Vec<u8>, src: &[u8]) -> Option<usize> {
    let unpadded = src.len() - src.iter().rev().take_while(|&&c| c == b'=').count();
    let room = unpadded / 4 * 3 + unpadded % 4 * 6 / 8;
    if buffer.len() < room {
        buffer.resize(room, 0);
    }
    let dst = &mut buffer[..room];
    let (mut si, mut n) = (0, 0);
    while src.len() - si >= 8 && dst.len() - n >= 8 {
        match assemble(&src[si..si + 8]) {
            Some(v) => {
                dst[n..n + 8].copy_from_slice(&(v << 16).to_be_bytes());
                n += 6;
                si += 8;
            }
            None => {
                let (next, wrote) = quantum(&mut dst[n..], src, si)?;
                (si, n) = (next, n + wrote);
            }
        }
    }
    while src.len() - si >= 4 && dst.len() - n >= 4 {
        match assemble(&src[si..si + 4]) {
            Some(v) => {
                dst[n..n + 4].copy_from_slice(&((v as u32) << 8).to_be_bytes());
                n += 3;
                si += 4;
            }
            None => {
                let (next, wrote) = quantum(&mut dst[n..], src, si)?;
                (si, n) = (next, n + wrote);
            }
        }
    }
    while si < src.len() {
        let (next, wrote) = quantum(&mut dst[n..], src, si)?;
        (si, n) = (next, n + wrote);
    }
    Some(n)
}

/// The value of a character of the standard alphabet.
fn sextet(c: u8) -> Option<u64> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u64::from(v))
}

/// Go's `assemble64` and `assemble32`: the characters as one number, or `None` when one is
/// not in the alphabet.
fn assemble(chars: &[u8]) -> Option<u64> {
    chars
        .iter()
        .try_fold(0, |acc, &c| Some(acc << 6 | sextet(c)?))
}

/// Go's `decodeQuantum`: up to four characters from `src[si..]` (line breaks skipped, and
/// the padding), written into `dst`. Returns where it stopped and how many bytes it wrote.
fn quantum(dst: &mut [u8], src: &[u8], mut si: usize) -> Option<(usize, usize)> {
    let mut dbuf = [0u64; 4];
    let mut dlen = 4;
    let mut j = 0;
    while j < 4 {
        if si == src.len() {
            // A missing `=` is an error for an encoding with padding.
            return (j == 0).then_some((si, 0));
        }
        let c = src[si];
        si += 1;
        if let Some(v) = sextet(c) {
            dbuf[j] = v;
            j += 1;
            continue;
        }
        if c == b'\n' || c == b'\r' {
            continue;
        }
        if c != b'=' || j < 2 {
            return None;
        }
        let skip = |si: &mut usize| {
            while *si < src.len() && matches!(src[*si], b'\n' | b'\r') {
                *si += 1;
            }
        };
        if j == 2 {
            skip(&mut si);
            if src.get(si) != Some(&b'=') {
                return None;
            }
            si += 1;
        }
        skip(&mut si);
        if si < src.len() {
            return None;
        }
        dlen = j;
        break;
    }
    let v = dbuf[0] << 18 | dbuf[1] << 12 | dbuf[2] << 6 | dbuf[3];
    let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
    let wrote = dlen - 1;
    dst.get_mut(..wrote)?.copy_from_slice(&bytes[..wrote]);
    Some((si, wrote))
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

    /// Go's decoder, written out for a repeated field, decodes what `decode_std` decodes and
    /// refuses what it refuses, for texts made of base64, padding and line breaks.
    #[test]
    fn decoding_into_old_bytes_decodes_as_go_does() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let alphabet = b"ABCDQUJx+/09==\n\r!";
        for _ in 0..20_000 {
            let len = next(40) as usize;
            let text: Vec<u8> = (0..len)
                .map(|_| alphabet[next(alphabet.len() as u64) as usize])
                .collect();
            let text = String::from_utf8(text).unwrap();
            let mut buffer = vec![0xaa; next(50) as usize];
            let got =
                super::go_decode_into(&mut buffer, text.as_bytes()).map(|n| buffer[..n].to_vec());
            let want = crate::wire::go_base64::decode_std(&text).ok();
            assert_eq!(got, want, "{text:?}");
        }
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
