//! Go `encoding/json`-compatible serializer (`<`, `>`, `&`, `U+2028`, `U+2029` escaped as `\u003c`, `\u003e`, `\u0026`, `\u2028`, `\u2029`).

use serde::Serialize;
use serde_json::ser::{CompactFormatter, Formatter};
use std::io;

struct GoEscapeFormatter;

fn write_escaped_bytes<W: ?Sized + io::Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let (esc, len): (&[u8], usize) = match bytes[i] {
            b'<' => (b"\\u003c", 1),
            b'>' => (b"\\u003e", 1),
            b'&' => (b"\\u0026", 1),
            0xE2 if i + 2 < bytes.len() && bytes[i + 1] == 0x80 && bytes[i + 2] == 0xA8 => {
                (b"\\u2028", 3)
            }
            0xE2 if i + 2 < bytes.len() && bytes[i + 1] == 0x80 && bytes[i + 2] == 0xA9 => {
                (b"\\u2029", 3)
            }
            _ => {
                i += 1;
                continue;
            }
        };
        if start < i {
            writer.write_all(&bytes[start..i])?;
        }
        writer.write_all(esc)?;
        i += len;
        start = i;
    }
    if start < bytes.len() {
        writer.write_all(&bytes[start..])?;
    }
    Ok(())
}

impl Formatter for GoEscapeFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        write_escaped_bytes(writer, fragment.as_bytes())
    }

    fn write_raw_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        // In valid JSON, `<`, `>`, `&`, `U+2028`, `U+2029` only occur inside string literals,
        // matching Go `encoding/json`'s `compact` behavior on `json.RawMessage`.
        write_escaped_bytes(writer, fragment.as_bytes())
    }
}

/// Serializes `value` as compact JSON with `<`, `>`, `&`, `U+2028`, `U+2029` escaped like Go's `encoding/json`.
pub fn to_go_json_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let _ = CompactFormatter;
    let mut buf = Vec::with_capacity(128);
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscapeFormatter);
    value.serialize(&mut ser)?;
    Ok(buf)
}

/// Serializes `value` as a compact JSON string with `<`, `>`, `&`, `U+2028`, `U+2029` escaped like Go's `encoding/json`.
pub fn to_go_json_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    let bytes = to_go_json_vec(value)?;
    Ok(String::from_utf8(bytes).expect("serde_json emits valid UTF-8"))
}
