//! A raw JSON value kept as Go's `json.RawMessage` keeps it.
//!
//! Go keeps such a field exactly as it came: spacing, escapes, a lone surrogate escape and
//! bytes that are not UTF-8 inside its strings (go1.27.1). A signature over a version's
//! payload covers it in that shape, so Rust keeps the bytes too ([`RawJson`]), not a
//! `serde_json::Value` (which would read the text, refuse a lone surrogate and stop at 128
//! levels) nor a `str` (which cannot hold the bytes).

use crate::wire::go_json::{go_raw_json_vec, go_writing, write_marked_raw};
use crate::wire::go_text;
use crate::wire::go_text::GoRead;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{self, Serialize, Serializer};
use serde_json::value::RawValue;
use std::fmt;

/// A JSON value as it came, byte for byte (Go's `json.RawMessage`).
///
/// It is read from any JSON value, `null` too, as it stands in the text. It is written as
/// Go writes a `json.RawMessage` ([`go_raw_json_vec`]): without the spacing between tokens
/// and with `<`, `>`, `&`, U+2028 and U+2029 escaped; bytes that are not UTF-8 are written
/// as they are, which only [`crate::wire::go_json::to_go_json_vec`] can do. A value that is
/// not JSON as Go reads it cannot be written, as in Go.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RawJson(Vec<u8>);

impl RawJson {
    /// The bytes as they are, unchecked (as Go's `json.RawMessage(bytes)`).
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// `null`.
    pub fn null() -> Self {
        Self(b"null".to_vec())
    }

    /// A value written as [`crate::wire::go_json::to_go_json_vec`] writes it.
    pub fn from_value<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Self> {
        crate::wire::go_json::to_go_json_vec(value).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The text, when it is UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Whether the value is `null` (spacing around it aside).
    pub fn is_null(&self) -> bool {
        self.0.trim_ascii() == b"null"
    }

    /// Reads the value as `T`, as Go's `json.Unmarshal` reads it ([`go_text::from_slice`]),
    /// for a type that reads as Go does ([`GoRead`]). A type with serde's own derive is read
    /// with `serde_json::from_slice` of [`RawJson::as_bytes`], which refuses bytes that are
    /// not UTF-8 where Go would read U+FFFD.
    pub fn parse<T: GoRead>(&self) -> serde_json::Result<T> {
        go_text::from_slice(&self.0)
    }
}

impl fmt::Debug for RawJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawJson({:?})", String::from_utf8_lossy(&self.0))
    }
}

impl Serialize for RawJson {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let Some(compact) = go_raw_json_vec(&self.0) else {
            return Err(ser::Error::custom("sirovi JSON nije jedna JSON vrijednost"));
        };
        match String::from_utf8(compact) {
            Ok(text) => RawValue::from_string(text)
                .map_err(ser::Error::custom)?
                .serialize(s),
            Err(e) if go_writing() => {
                let raw = RawValue::from_string(go_text::mark(e.as_bytes()))
                    .map_err(ser::Error::custom)?;
                write_marked_raw(|| raw.serialize(s))
            }
            Err(_) => Err(ser::Error::custom(
                "sirovi JSON s bajtovima koji nisu UTF-8 zapisuje samo to_go_json_vec",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for RawJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(d)?;
        Ok(Self(go_text::raw_bytes(raw.get()).into_owned()))
    }
}

/// For an optional raw field: `null` is kept as `Some` of `null`, as Go keeps it; only a
/// missing field is `None` (with `#[serde(default)]`).
pub fn keep_null<'de, D: Deserializer<'de>>(d: D) -> Result<Option<RawJson>, D::Error> {
    RawJson::deserialize(d).map(Some)
}
