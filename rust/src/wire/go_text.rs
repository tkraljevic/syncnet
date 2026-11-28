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
//! Go keeps a `json.RawMessage` as it came, escapes and all. Text is therefore not
//! rewritten as a whole, only where a field reads it as text
//! ([`crate::wire::go_object`]), and a raw field is left as it is.

use std::borrow::Cow;

/// Bytes from the wire as JSON text, each byte that is not UTF-8 turned into U+FFFD as
/// Go turns it. Text that is UTF-8 comes back as it is.
///
/// A raw field (`json.RawMessage`) is the one place this differs from Go: Go keeps such
/// bytes in it, and a `str` cannot hold them.
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

/// Reads `T` from bytes from the wire, as [`serde_json::from_slice`] would after Go's
/// reading of bytes that are not UTF-8 ([`utf8`]), and refuses text nested deeper than
/// Go reads ([`MAX_DEPTH`]).
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    let text = utf8(bytes);
    check_depth(&text, 0).map_err(<serde_json::Error as serde::de::Error>::custom)?;
    serde_json::from_str(&text)
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
            let mut text = b"{\"a\":\"".to_vec();
            text.extend_from_slice(content);
            text.extend_from_slice(b"\"}");
            #[derive(serde::Deserialize)]
            struct A {
                a: String,
            }
            let a: A = super::from_slice(&text).unwrap();
            assert_eq!(hex::encode(a.a), *go, "{content:?}");
        }
        assert!(matches!(utf8(b"{\"a\":1}"), std::borrow::Cow::Borrowed(_)));
        // Outside a string such a byte stays an error, as in Go.
        for bad in [
            &b"\xff"[..],
            b"{\"a\":\"x\"}\xff",
            b"{\xff}",
            b"{\"a\":\xff}",
        ] {
            assert!(super::from_slice::<serde_json::Value>(bad).is_err());
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
        #[derive(serde::Deserialize)]
        struct A {
            #[allow(dead_code)]
            a: i64,
        }
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
