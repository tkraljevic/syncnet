//! Go `encoding/json`-compatible serializer (`<`, `>`, `&`, `U+2028`, `U+2029` escaped as `\u003c`, `\u003e`, `\u0026`, `\u2028`, `\u2029`).

use serde::Serialize;
use serde_json::ser::Formatter;
use std::cell::Cell;
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
        if RAW_MARKED.with(Cell::get) == MarkedRaw::Waiting {
            RAW_MARKED.with(|m| m.set(MarkedRaw::Written));
            return write_escaped_bytes(writer, &crate::wire::go_text::unmark_raw(fragment));
        }
        write_escaped_bytes(writer, fragment.as_bytes())
    }
}

/// Raw JSON as Go's `json.Marshal(json.RawMessage(raw))` writes it: checked to be one JSON
/// value, with the spacing between tokens removed and `<`, `>`, `&`, `U+2028`, `U+2029`
/// escaped. Nothing else changes: key order, numbers, existing escapes and bytes that are
/// not UTF-8 inside strings stay as written, as in Go (go1.27.1).
///
/// The check is Go's: a string may hold any byte from `0x20` up, UTF-8 or not, but no
/// control character and no escape other than JSON's; nesting may go
/// [`crate::wire::go_text::MAX_DEPTH`] levels deep. `None` where Go refuses to write it.
pub fn go_raw_json_vec(raw: &[u8]) -> Option<Vec<u8>> {
    let compact = go_compact(raw)?;
    let mut out = Vec::with_capacity(compact.len());
    write_escaped_bytes(&mut out, &compact).expect("writing to a Vec does not fail");
    Some(out)
}

/// One JSON value without the spacing between its tokens, or `None` when it is not one
/// JSON value as Go reads it (see [`go_raw_json_vec`]).
fn go_compact(src: &[u8]) -> Option<Vec<u8>> {
    #[derive(Clone, Copy, PartialEq)]
    enum Want {
        Value,
        ValueOrClose,
        Key,
        KeyOrClose,
        Colon,
        AfterValue,
    }
    let mut out = Vec::with_capacity(src.len());
    let mut open: Vec<u8> = Vec::new();
    let mut want = Want::Value;
    let mut i = 0;
    loop {
        while matches!(src.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            i += 1;
        }
        if want == Want::AfterValue && open.is_empty() {
            return (i == src.len()).then_some(out);
        }
        let c = *src.get(i)?;
        match want {
            Want::AfterValue => {
                let close = if open.last() == Some(&b'[') {
                    b']'
                } else {
                    b'}'
                };
                if c == b',' {
                    want = if close == b']' {
                        Want::Value
                    } else {
                        Want::Key
                    };
                } else if c == close {
                    open.pop();
                } else {
                    return None;
                }
                out.push(c);
                i += 1;
            }
            Want::Colon => {
                if c != b':' {
                    return None;
                }
                out.push(c);
                i += 1;
                want = Want::Value;
            }
            Want::Key | Want::KeyOrClose => {
                if c == b'}' && want == Want::KeyOrClose {
                    open.pop();
                    out.push(c);
                    i += 1;
                    want = Want::AfterValue;
                } else if c == b'"' {
                    i = go_string(src, i, &mut out)?;
                    want = Want::Colon;
                } else {
                    return None;
                }
            }
            Want::Value | Want::ValueOrClose => {
                if c == b']' && want == Want::ValueOrClose {
                    open.pop();
                    out.push(c);
                    i += 1;
                    want = Want::AfterValue;
                    continue;
                }
                match c {
                    b'{' | b'[' => {
                        open.push(c);
                        if open.len() > crate::wire::go_text::MAX_DEPTH {
                            return None;
                        }
                        out.push(c);
                        i += 1;
                        want = if c == b'{' {
                            Want::KeyOrClose
                        } else {
                            Want::ValueOrClose
                        };
                        continue;
                    }
                    b'"' => i = go_string(src, i, &mut out)?,
                    b'-' | b'0'..=b'9' => i = go_number(src, i, &mut out)?,
                    _ => {
                        let word: &[u8] = match c {
                            b't' => b"true",
                            b'f' => b"false",
                            b'n' => b"null",
                            _ => return None,
                        };
                        if !src[i..].starts_with(word) {
                            return None;
                        }
                        out.extend_from_slice(word);
                        i += word.len();
                    }
                }
                want = Want::AfterValue;
            }
        }
    }
}

/// Copies the string that starts at `src[i]` (a `"`) and returns where it ends.
fn go_string(src: &[u8], mut i: usize, out: &mut Vec<u8>) -> Option<usize> {
    let start = i;
    i += 1;
    loop {
        match *src.get(i)? {
            b'"' => {
                i += 1;
                out.extend_from_slice(&src[start..i]);
                return Some(i);
            }
            b'\\' => match *src.get(i + 1)? {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 2,
                b'u' => {
                    let hex = src.get(i + 2..i + 6)?;
                    if !hex.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    i += 6;
                }
                _ => return None,
            },
            c if c < 0x20 => return None,
            _ => i += 1,
        }
    }
}

/// Copies the number that starts at `src[i]` and returns where it ends.
fn go_number(src: &[u8], mut i: usize, out: &mut Vec<u8>) -> Option<usize> {
    let start = i;
    let digits = |i: &mut usize| {
        let from = *i;
        while src.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        *i > from
    };
    if src[i] == b'-' {
        i += 1;
    }
    match src.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            digits(&mut i);
        }
        _ => return None,
    }
    if src.get(i) == Some(&b'.') {
        i += 1;
        if !digits(&mut i) {
            return None;
        }
    }
    if matches!(src.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(src.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !digits(&mut i) {
            return None;
        }
    }
    out.extend_from_slice(&src[start..i]);
    Some(i)
}

/// Where a raw value with marks stands while it is written ([`write_marked_raw`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkedRaw {
    None,
    /// Written next; only the formatter of [`to_go_json_vec`] takes it.
    Waiting,
    /// That formatter wrote it, as bytes.
    Written,
}

thread_local! {
    /// How many [`to_go_json_vec`] calls are writing on this thread.
    static GO_WRITING: Cell<u32> = const { Cell::new(0) };
    static RAW_MARKED: Cell<MarkedRaw> = const { Cell::new(MarkedRaw::None) };
}

/// Counts one [`to_go_json_vec`] while it lives, also when writing panics.
struct GoWriting;

impl GoWriting {
    fn enter() -> Self {
        GO_WRITING.with(|w| w.set(w.get() + 1));
        Self
    }
}

impl Drop for GoWriting {
    fn drop(&mut self) {
        GO_WRITING.with(|w| w.set(w.get() - 1));
    }
}

/// Puts back what [`RAW_MARKED`] was, also when writing panics.
struct RestoreMarked(MarkedRaw);

impl Drop for RestoreMarked {
    fn drop(&mut self) {
        RAW_MARKED.with(|m| m.set(self.0));
    }
}

/// Whether [`to_go_json_vec`] is writing, so a raw value may hold bytes that are not UTF-8.
pub(crate) fn go_writing() -> bool {
    GO_WRITING.with(|w| w.get() > 0)
}

/// Writes raw JSON that is not UTF-8 through `write` (which serializes a raw value whose text
/// is `marked`): the formatter of [`to_go_json_vec`] writes the bytes of its marks
/// ([`crate::wire::go_text::MARK`]) instead of the marks. When something else wrote the value
/// (another serializer inside the value being written), it is an error, as that output has
/// the marks.
pub(crate) fn write_marked_raw<T, E: serde::ser::Error>(
    write: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let _restore = RestoreMarked(RAW_MARKED.with(|m| m.replace(MarkedRaw::Waiting)));
    let out = write()?;
    if RAW_MARKED.with(Cell::get) != MarkedRaw::Written {
        return Err(E::custom(
            "sirovi JSON s bajtovima koji nisu UTF-8 zapisuje samo to_go_json_vec",
        ));
    }
    Ok(out)
}

/// Serializes `value` as compact JSON with `<`, `>`, `&`, `U+2028`, `U+2029` escaped like Go's `encoding/json`.
///
/// A raw value ([`crate::wire::go_raw::RawJson`]) may hold bytes that are not UTF-8; they
/// are written as they are, as Go writes them.
pub fn to_go_json_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(128);
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscapeFormatter);
    let _writing = GoWriting::enter();
    value.serialize(&mut ser)?;
    Ok(buf)
}

/// Serializes `value` as a compact JSON string with `<`, `>`, `&`, `U+2028`, `U+2029` escaped like Go's `encoding/json`.
///
/// An error where [`to_go_json_vec`] writes bytes that are not UTF-8 (from a raw value).
pub fn to_go_json_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    let bytes = to_go_json_vec(value)?;
    String::from_utf8(bytes).map_err(<serde_json::Error as serde::ser::Error>::custom)
}

#[cfg(test)]
mod tests {
    use super::{go_writing, to_go_json_vec};
    use crate::wire::go_raw::RawJson;
    use serde::{Serialize, Serializer};

    /// A value that writes a raw value with another serializer, as a field might.
    struct Inner(RawJson);

    impl Serialize for Inner {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let text = serde_json::to_vec(&self.0).map_err(serde::ser::Error::custom)?;
            s.serialize_bytes(&text)
        }
    }

    struct Panics;

    impl Serialize for Panics {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            panic!("pisanje pada");
        }
    }

    #[test]
    fn raw_bytes_are_written_only_by_the_go_writer() {
        let raw = RawJson::from_bytes(b"\"a\xff\xee\x80\x80\"".to_vec());
        assert_eq!(to_go_json_vec(&raw).unwrap(), b"\"a\xff\xee\x80\x80\"");
        assert!(serde_json::to_vec(&raw).is_err());
        // Inside the Go writer, a plain serializer still may not write the bytes: it would
        // write the marks.
        assert!(to_go_json_vec(&Inner(raw.clone())).is_err());
        assert!(!go_writing());
        let caught = std::panic::catch_unwind(|| to_go_json_vec(&Panics));
        assert!(caught.is_err());
        assert!(!go_writing());
        assert!(serde_json::to_vec(&raw).is_err());
        assert_eq!(to_go_json_vec(&raw).unwrap(), b"\"a\xff\xee\x80\x80\"");
    }
}
