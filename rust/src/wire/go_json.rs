//! Go `encoding/json`-compatible serializer (`<`, `>`, `&` escaped as `\u003c`, `\u003e`, `\u0026`).

use serde::Serialize;
use serde_json::ser::{CompactFormatter, Formatter};
use std::io;

struct GoEscapeFormatter;

fn write_escaped_bytes<W: ?Sized + io::Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &[u8] = match b {
            b'<' => b"\\u003c",
            b'>' => b"\\u003e",
            b'&' => b"\\u0026",
            _ => continue,
        };
        if start < i {
            writer.write_all(&bytes[start..i])?;
        }
        writer.write_all(esc)?;
        start = i + 1;
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
        // In valid JSON, `<`, `>`, and `&` only occur inside string literals,
        // matching Go `encoding/json`'s `compact` behavior on `json.RawMessage`.
        write_escaped_bytes(writer, fragment.as_bytes())
    }
}

/// Serializes `value` as compact JSON with `<`, `>`, and `&` escaped like Go's `encoding/json`.
pub fn to_go_json_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let _ = CompactFormatter;
    let mut buf = Vec::with_capacity(128);
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscapeFormatter);
    value.serialize(&mut ser)?;
    Ok(buf)
}

/// Serializes `value` as a compact JSON string with `<`, `>`, and `&` escaped like Go's `encoding/json`.
pub fn to_go_json_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    let bytes = to_go_json_vec(value)?;
    Ok(String::from_utf8(bytes).expect("serde_json emits valid UTF-8"))
}
