//! Text on the wire read as Go's `encoding/json` reads it.
//!
//! Go takes two kinds of text that serde refuses, and turns each into U+FFFD. Measured
//! with go1.27.1 (`json.Unmarshal` into the Go side's structs):
//!
//! - a lone surrogate escape in a string: `\ud800`, `\udc00`, a low one before a high
//!   one, a high one at the end or before anything but a low one. A high escape followed
//!   at once by a low escape is one character, as in serde. Each lone escape is one
//!   U+FFFD; what follows it is read on its own, so `\ud800\ud83d\ude00` is U+FFFD and
//!   😀;
//! - bytes that are not UTF-8 inside a string: each such byte is one U+FFFD, as
//!   `utf8.DecodeRune` steps over it (`E2 80` is two, a surrogate written as UTF-8 three).
//!   Outside a string such a byte is an error in Go, and it stays one here.
//!
//! Go writes U+FFFD back as its three bytes, as serde does, so the bytes a record signs
//! are the same on both sides.
//!
//! Go also refuses text nested deeper than [`MAX_DEPTH`] arrays and objects, counted from
//! the top of the text it reads, even when the deep part is a value it would skip or keep
//! raw. serde skips and keeps such values at any depth, so the depth is checked here
//! ([`from_slice`], and each field in [`crate::wire::go_object`]).
//!
//! Go keeps a `json.RawMessage` as it came, escapes and all, and bytes that are not
//! UTF-8 as they are. Text is therefore not rewritten as a whole, only where a field reads
//! it as text ([`crate::wire::go_object`]), and a raw field is left as it is
//! ([`crate::wire::go_raw::RawJson`]). For that, [`from_slice`] marks each byte that is not
//! UTF-8 instead of turning it into U+FFFD at once: a field read as text turns the mark into
//! U+FFFD, a raw field back into the byte.

use std::borrow::Cow;
use std::cell::Cell;

/// Bytes from the wire as JSON text, each byte that is not UTF-8 turned into U+FFFD as
/// Go turns it in a text. Text that is UTF-8 comes back as it is.
///
/// A raw field (`json.RawMessage`) keeps such bytes in Go; [`from_slice`] keeps them too.
pub fn utf8(bytes: &[u8]) -> Cow<'_, str> {
    let mut rest = bytes;
    let mut out = String::new();
    loop {
        match std::str::from_utf8(rest) {
            Ok(tail) if out.is_empty() && tail.len() == bytes.len() => {
                return Cow::Borrowed(tail);
            }
            Ok(tail) => {
                out.push_str(tail);
                return Cow::Owned(out);
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).expect("checked up to here"));
                out.push('\u{FFFD}');
                rest = &bad[1..];
            }
        }
    }
}

/// The deepest nesting of arrays and objects Go reads (go1.27.1): ten thousand open `[`
/// or `{` at once, the outermost one counted. One more is an error, for the whole text.
pub const MAX_DEPTH: usize = 10_000;

/// How deeply arrays and objects nest in a JSON text: `1` for `{}` or `[1]`, `0` for a
/// plain value. Brackets inside strings do not count.
pub fn depth(json: &str) -> usize {
    let mut deepest = 0;
    let mut now: usize = 0;
    let mut in_string = false;
    let mut b = json.bytes();
    while let Some(c) = b.next() {
        match c {
            b'"' => in_string = !in_string,
            b'\\' if in_string => {
                b.next();
            }
            b'[' | b'{' if !in_string => {
                now += 1;
                deepest = deepest.max(now);
            }
            b']' | b'}' if !in_string => now = now.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// An error when `json` nests deeper than Go reads, `extra` levels below the top of the
/// text Go reads (0 for the whole text).
pub(crate) fn check_depth(json: &str, extra: usize) -> Result<(), String> {
    if depth(json) + extra > MAX_DEPTH {
        return Err(format!(
            "JSON je ugniježđen dublje od {MAX_DEPTH} razina, a toliko Go ne čita"
        ));
    }
    Ok(())
}

/// Reads `T` from bytes from the wire as Go reads them, and refuses text nested deeper
/// than Go reads ([`MAX_DEPTH`]).
///
/// A byte that is not UTF-8 reads as U+FFFD in a text and stays the byte in a raw field, as
/// in Go. While `T` is read each such byte is a mark (one character of the private use area,
/// see [`MARK`]), and a character of that range in the text is written after [`MARK`]; the
/// readers of [`crate::wire::go_object`] and [`crate::wire::go_raw::RawJson`] turn the
/// marks back. `T` must therefore read its text through them ([`GoRead`]): serde's own
/// derive would see the marks. Text that is UTF-8 has no marks.
pub fn from_slice<T: GoRead>(bytes: &[u8]) -> serde_json::Result<T> {
    let (text, marked) = match std::str::from_utf8(bytes) {
        Ok(text) => (Cow::Borrowed(text), false),
        Err(_) => (Cow::Owned(mark(bytes)), true),
    };
    let _mode = Marking::enter(marked);
    check_depth(&text, 0).map_err(<serde_json::Error as serde::de::Error>::custom)?;
    serde_json::from_str(&text)
}

/// A type that reads its text as Go does, through [`crate::wire::go_object`] or
/// [`crate::wire::go_raw::RawJson`], and so may be read by [`from_slice`]. Every wire struct
/// of this crate is one. A type with serde's own derive is not: where the bytes are not
/// UTF-8 it would see the marks, so read it with `serde_json::from_slice`, which refuses
/// such bytes.
pub trait GoRead: serde::de::DeserializeOwned {}

impl GoRead for crate::wire::go_raw::RawJson {}
impl<T: GoRead> GoRead for Option<T> {}

/// The first character of the marks: a byte `b` that is not UTF-8 is the character
/// `MARK + b` (U+E080 to U+E0FF, three bytes, as long as the U+FFFD Go reads there), and a
/// character from U+E000 to U+E0FF that the text has is written after `MARK`.
pub const MARK: char = '\u{E000}';

/// Whether `c` is one of the characters the marks use (U+E000 to U+E0FF).
fn in_mark_range(c: char) -> bool {
    ('\u{E000}'..='\u{E0FF}').contains(&c)
}

thread_local! {
    static MARKING: Cell<bool> = const { Cell::new(false) };
}

/// While it lives, text being read has marks (`true`) or none; dropping it restores what
/// was before, so a text read inside another keeps its own mode.
struct Marking(bool);

impl Marking {
    fn enter(on: bool) -> Self {
        Self(MARKING.with(|m| m.replace(on)))
    }
}

impl Drop for Marking {
    fn drop(&mut self) {
        MARKING.with(|m| m.set(self.0));
    }
}

/// Whether the text being read has marks ([`from_slice`] of bytes that are not UTF-8).
pub(crate) fn marking() -> bool {
    MARKING.with(Cell::get)
}

/// The good part of `rest` and the byte that is not UTF-8 after it, if any.
fn split_bad(rest: &[u8]) -> (&str, Option<u8>) {
    match std::str::from_utf8(rest) {
        Ok(tail) => (tail, None),
        Err(e) => {
            let (good, bad) = rest.split_at(e.valid_up_to());
            (
                std::str::from_utf8(good).expect("checked up to here"),
                Some(bad[0]),
            )
        }
    }
}

/// Bytes as text with marks, as [`from_slice`] reads them; also for writing raw JSON that
/// is not UTF-8 ([`crate::wire::go_json`]).
pub(crate) fn mark(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(marked_len(bytes));
    let mut rest = bytes;
    loop {
        let (good, bad) = split_bad(rest);
        if good.chars().any(in_mark_range) {
            for c in good.chars() {
                if in_mark_range(c) {
                    out.push(MARK);
                }
                out.push(c);
            }
        } else {
            out.push_str(good);
        }
        let Some(b) = bad else {
            return out;
        };
        out.push(byte_mark(b));
        rest = &rest[good.len() + 1..];
    }
}

/// The mark of a byte that is not UTF-8 (always 0x80 or more).
fn byte_mark(b: u8) -> char {
    char::from_u32(u32::from(MARK) + u32::from(b)).expect("in the private use area")
}

/// How long [`mark`] makes `bytes`.
fn marked_len(bytes: &[u8]) -> usize {
    let mut len = 0;
    let mut rest = bytes;
    loop {
        let (good, bad) = split_bad(rest);
        len += good.len() + good.chars().filter(|&c| in_mark_range(c)).count() * MARK.len_utf8();
        if bad.is_none() {
            return len;
        }
        len += MARK.len_utf8();
        rest = &rest[good.len() + 1..];
    }
}

/// Undoes the marks of text being read: `byte` gives what a mark stands for.
fn unmark<'a>(text: &'a str, byte: impl Fn(u8, &mut Vec<u8>)) -> Cow<'a, [u8]> {
    if !marking() {
        return Cow::Borrowed(text.as_bytes());
    }
    unmark_always(text, byte)
}

fn unmark_always<'a>(text: &'a str, byte: impl Fn(u8, &mut Vec<u8>)) -> Cow<'a, [u8]> {
    let Some(first) = text.find(in_mark_range) else {
        return Cow::Borrowed(text.as_bytes());
    };
    let mut out = Vec::with_capacity(text.len());
    out.extend_from_slice(&text.as_bytes()[..first]);
    let mut chars = text[first..].chars().peekable();
    while let Some(c) = chars.next() {
        if !in_mark_range(c) {
            let mut buf = [0; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let code = u32::from(c) - u32::from(MARK);
        if c == MARK
            && let Some(&next) = chars.peek()
            && in_mark_range(next)
        {
            // A character of the range that the text has.
            chars.next();
            let mut buf = [0; 4];
            out.extend_from_slice(next.encode_utf8(&mut buf).as_bytes());
        } else if code >= 0x80 {
            byte(u8::try_from(code).expect("below 0x100"), &mut out);
        } else {
            // Marks are made only as written in `mark`; anything else stays as it is.
            let mut buf = [0; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Cow::Owned(out)
}

/// Text with marks made by [`mark`], as the bytes it stands for.
pub(crate) fn unmark_raw(text: &str) -> Cow<'_, [u8]> {
    unmark_always(text, |b, out| out.push(b))
}

/// A raw value's text as the bytes that came: each mark is its byte again.
pub(crate) fn raw_bytes(text: &str) -> Cow<'_, [u8]> {
    unmark(text, |b, out| out.push(b))
}

/// One JSON value (its text) as Go reads its strings: each mark is U+FFFD, and so is each
/// lone surrogate escape ([`lone_surrogates`]).
pub(crate) fn as_text(text: &str) -> Cow<'_, str> {
    match unmark(text, |_, out| out.extend_from_slice("\u{FFFD}".as_bytes())) {
        Cow::Borrowed(_) => lone_surrogates(text),
        Cow::Owned(b) => {
            let t = String::from_utf8(b).expect("marks undo to UTF-8");
            let fixed = match lone_surrogates(&t) {
                Cow::Owned(fixed) => Some(fixed),
                Cow::Borrowed(_) => None,
            };
            Cow::Owned(fixed.unwrap_or(t))
        }
    }
}

/// A key or text read from marked text and written again into text that is read on: the
/// characters of the marks' range in it are written as escapes, so they are not taken for
/// marks.
pub(crate) fn escape_mark(json: String) -> String {
    if !marking() || !json.contains(in_mark_range) {
        return json;
    }
    let mut out = String::with_capacity(json.len() + 16);
    for c in json.chars() {
        if in_mark_range(c) {
            out.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

fn hex4(b: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(b.get(..4)?).ok()?;
    u16::from_str_radix(s, 16).ok()
}

/// One JSON value (its text, already read as JSON) with every lone surrogate escape in
/// its strings written as `\ufffd`, which is what Go reads there. Nothing else changes:
/// other escapes, pairs, `\\u…` (an escaped backslash) and text outside strings stay as
/// they are, so a value without a lone surrogate comes back borrowed.
pub(crate) fn lone_surrogates(json: &str) -> Cow<'_, str> {
    let b = json.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut in_string = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                in_string = !in_string;
                i += 1;
            }
            b'\\' if in_string => {
                if b.get(i + 1) != Some(&b'u') {
                    i += 2;
                    continue;
                }
                let Some(n) = hex4(&b[i + 2..]) else {
                    // Not JSON; serde has read it, so this does not happen.
                    i += 2;
                    continue;
                };
                if !(0xD800..=0xDFFF).contains(&n) {
                    i += 6;
                    continue;
                }
                let paired = n <= 0xDBFF
                    && b.get(i + 6..i + 8) == Some(b"\\u")
                    && hex4(&b[i + 8..]).is_some_and(|m| (0xDC00..=0xDFFF).contains(&m));
                if paired {
                    i += 12;
                    continue;
                }
                let o = out.get_or_insert_with(|| String::with_capacity(json.len()));
                o.push_str(&json[copied..i]);
                o.push_str("\\ufffd");
                i += 6;
                copied = i;
            }
            _ => i += 1,
        }
    }
    match out {
        None => Cow::Borrowed(json),
        Some(mut o) => {
            o.push_str(&json[copied..]);
            Cow::Owned(o)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_DEPTH, depth, lone_surrogates, utf8};

    /// (bytes of a JSON string's content, what Go reads, as hex). Go column: go1.27.1,
    /// `json.Unmarshal` of `{"a":"<content>"}` into a `string` field.
    const BYTES: &[(&[u8], &str)] = &[
        (b"abc", "616263"),
        (b"\xff", "efbfbd"),
        (b"\xe2\x80", "efbfbdefbfbd"),
        (b"\xe2\x80x", "efbfbdefbfbd78"),
        (b"\xed\xa0\x80", "efbfbdefbfbdefbfbd"),
        (b"\xf0\x9f\x98", "efbfbdefbfbdefbfbd"),
        (b"\xc0\xaf", "efbfbdefbfbd"),
        (b"\xf4\x90\x80\x80", "efbfbdefbfbdefbfbdefbfbd"),
        (b"\xef\xbf\xbd", "efbfbd"),
        (b"\xf0\x9f\x98\x80", "f09f9880"),
    ];

    #[test]
    fn bytes_read_as_in_go() {
        for (content, go) in BYTES {
            // A struct read as Go reads it (here the NAT report of a signal): its text
            // fields turn the marks into U+FFFD.
            let mut text = b"{\"vrsta\":\"".to_vec();
            text.extend_from_slice(content);
            text.extend_from_slice(b"\"}");
            let a: crate::wire::signal::NatReport = super::from_slice(&text).unwrap();
            assert_eq!(hex::encode(a.vrsta), *go, "{content:?}");
        }
        assert!(matches!(utf8(b"{\"a\":1}"), std::borrow::Cow::Borrowed(_)));
        // Outside a string such a byte stays an error, as in Go.
        for bad in [
            &b"\xff"[..],
            b"{\"a\":\"x\"}\xff",
            b"{\xff}",
            b"{\"a\":\xff}",
        ] {
            assert!(super::from_slice::<crate::wire::signal::NatReport>(bad).is_err());
        }
    }

    /// (escapes in a JSON string, what Go reads, as hex). Go column as for [`BYTES`].
    const ESCAPES: &[(&str, &str)] = &[
        (r"\ud800", "efbfbd"),
        (r"\udc00", "efbfbd"),
        (r"\uDBFF", "efbfbd"),
        (r"\udc00\ud800", "efbfbdefbfbd"),
        (r"x\ud800", "78efbfbd"),
        (r"\ud800\u0041", "efbfbd41"),
        (r"\ud800\ud800\udc00", "efbfbdf0908080"),
        (r"\ud83d\ude00", "f09f9880"),
        (r"\uD83D\uDE00", "f09f9880"),
        (r"\ud800\n", "efbfbd0a"),
        (r"\ud800\\", "efbfbd5c"),
        (r"\ud800A", "efbfbd41"),
        (r"\\ud800", "5c7564383030"),
        (r"\\\ud800", "5cefbfbd"),
        (r"\u0000", "00"),
        (r"\ufffd", "efbfbd"),
        (r"\ud7ff\ue000", "ed9fbfee8080"),
        (r"\udbff\udfff", "f48fbfbf"),
        (r"\ude00\ud83d", "efbfbdefbfbd"),
    ];

    /// Marks are as long as the U+FFFD Go reads for a byte (three bytes), and give the bytes
    /// back, also where the text has characters of the marks' range.
    #[test]
    fn marks_give_the_bytes_back() {
        for bytes in [
            &b"\xff"[..],
            b"a\xffb\xfe",
            "\u{E000}\u{E0FF}\u{E080}\u{E07F}\u{E100}".as_bytes(),
            b"\xee\x80\x80\xff\xee\x83\xbf\x80\xee\x82",
            b"\xed\xa0\x80\xc0\xaf\xf4\x90\x80\x80",
        ] {
            let marked = super::mark(bytes);
            assert_eq!(super::unmark_raw(&marked), bytes, "{bytes:?}");
            assert_eq!(marked.len(), super::marked_len(bytes), "{bytes:?}");
        }
        assert_eq!(super::mark(&[0xff; 100]).len(), 300);
    }

    #[test]
    fn escapes_read_as_in_go() {
        for (escapes, go) in ESCAPES {
            let text = format!("\"{escapes}\"");
            let fixed = lone_surrogates(&text);
            let s: String = serde_json::from_str(&fixed).unwrap();
            assert_eq!(hex::encode(s), *go, "{escapes}");
        }
    }

    #[test]
    fn only_lone_surrogates_change() {
        for same in [
            r#"{"a":"\u0000\u001f\n\"\\\/","b":[1,-0,2.5e3,true,null],"\u0041":{}}"#,
            r#"{"a":"\ud83d\ude00 \\ud800 \\\\ud800"}"#,
            r#"[ "ud800", 5, {"x" : "\uD800\uDC00"} ]"#,
            r#""\\""#,
        ] {
            assert!(
                matches!(lone_surrogates(same), std::borrow::Cow::Borrowed(_)),
                "{same}"
            );
        }
        assert_eq!(
            lone_surrogates(r#"{"\ud800":["\udc00x", "y\ud800\ud800\udc00"], "z": 1}"#),
            r#"{"\ufffd":["\ufffdx", "y\ufffd\ud800\udc00"], "z": 1}"#
        );
    }

    #[test]
    fn depth_counts_brackets_outside_strings() {
        for (text, want) in [
            ("1", 0),
            ("\"[[{\"", 0),
            ("[]", 1),
            ("{\"a\":[1,{\"b\":[]}]}", 4),
            ("[[],[[]]]", 3),
            (r#"["\"[[[", {"a\\":[]}]"#, 3),
            (r#"{"\\\"[":1}"#, 1),
        ] {
            assert_eq!(depth(text), want, "{text}");
        }
    }

    /// (nesting of the whole text, what Go does). Go column: go1.27.1, `json.Unmarshal`
    /// of `{"a":1,"zz":<arrays or objects>}` into the Go side's structs, which skip `zz`.
    const DEPTHS: &[(usize, &str)] = &[(9_999, "OK"), (10_000, "OK"), (10_001, "GRESKA")];

    #[test]
    fn text_nested_deeper_than_go_reads_is_refused() {
        // A struct read as Go reads it, which skips `a` and `zz`.
        type A = crate::wire::signal::NatReport;
        assert_eq!(MAX_DEPTH, 10_000);
        for (whole, go) in DEPTHS {
            let n = whole - 1;
            for deep in [
                format!("{}{}", "[".repeat(n), "]".repeat(n)),
                format!("{}1{}", "{\"b\":".repeat(n), "}".repeat(n)),
            ] {
                let text = format!("{{\"a\":1,\"zz\":{deep}}}");
                let got = super::from_slice::<A>(text.as_bytes()).map_or("GRESKA", |_| "OK");
                assert_eq!(got, *go, "{whole}");
            }
        }
    }
}
