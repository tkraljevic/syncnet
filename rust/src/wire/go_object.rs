//! A JSON object read into a struct the way Go's `encoding/json` reads it.
//!
//! serde matches a field name exactly, refuses a field that comes twice and skips any
//! other spelling of a name. Go does neither, so the same signed message could be taken
//! by one side and refused by the other, or read with a different recipient. What Go
//! does, measured with go1.27.1 on the Go side's message structs:
//!
//! - a key names a field when the two are equal without regard to ASCII case; `K`
//!   (U+212A) also stands for `k` and `ſ` (U+017F) for `s`. Nothing else folds: `ı` and
//!   `İ` are not `i`. A key that names no field is skipped. Go looks for the exact name
//!   first, but both name the same field, so only the order counts: of `pokusaj` and
//!   `POKUSAJ` the later one wins.
//! - when a field comes more than once, the last one counts, and each one must still
//!   read as the field's type;
//! - `null` leaves a number, string or bool as it was, and clears bytes, a pointer or a
//!   slice;
//! - bytes (`[]byte`) given more than once are read into the buffer the field already
//!   holds, as Go reads them ([`crate::wire::go_bytes`]): a `null` element of a later
//!   array leaves the old byte, and old bytes past a shorter value come back when a later
//!   array is longer;
//! - objects for a pointer to a struct are read into the same struct, so their fields
//!   add up; a `null` between them starts again;
//! - `null` in place of the whole object leaves every field as it was.
//!
//! - a slice of structs given more than once is read into the same elements: element `i`
//!   of a later array is read into element `i` as it was, so a field the new element
//!   leaves out keeps its old value, and a `null` element leaves it whole. An element
//!   the later array does not reach stays under the slice and comes back when a still
//!   later array is long enough. `null` or `[]` in place of the array starts again.
//!   The slice is as long as the last array.
//! - a slice of plain values (`[]string`) given more than once is read the same way: a
//!   `null` element leaves the element as it was (an element never set is empty);
//! - a map (`map[string]string`, `map[string]int`, a map of structs) given more than once
//!   adds up: a later object adds its keys to the map and replaces a key it repeats,
//!   `null` starts again. Inside one object a repeated key counts the last time. Keys are
//!   matched exactly, after they are read as text, so `\u0061` and `a` are one key, and so
//!   are two keys with a lone surrogate in the same place. A `null` value is the empty value
//!   (`""`, `0`, a struct with no fields); a struct value is read anew, not added to the
//!   one before;
//! - a `json.RawMessage` keeps the value as it came, `null` too, and the last one counts;
//! - text in a key or a field is read as Go reads it ([`crate::wire::go_text`]): a lone
//!   surrogate escape is U+FFFD, and so is a byte that is not UTF-8. A key with one names
//!   no field, as no field name has U+FFFD. A raw field keeps its escapes and bytes as they
//!   came, as Go keeps them. A control character (U+0000 to U+001F) written as it is, not
//!   as an escape, is an error in a key as in a value;
//! - a value nested deeper than Go reads ([`go_text::MAX_DEPTH`], the object itself
//!   counted) is an error, also in a field Go skips;
//! - `-0` is 0 in a field Go reads as a signed integer (`int`, `int64`), as Go's
//!   `strconv.ParseInt` reads it, also in a slice or a map of them. `-0.0`, `0.0` and
//!   `1e0` are not integers there, in Go as in serde, and an unsigned integer (`uint64`)
//!   refuses `-0`, in Go as in serde.
//! - a field Go reads but this side does not keep ([`Kind::Check`]) must still read as
//!   Go's type, each time it comes.
//!
//! The struct keeps its serde derive under `#[serde(remote = "Self")]`, and `go_struct!`
//! puts this reader in front of it: keys are mapped to field names, repeats are settled,
//! and the derive reads the result.

use crate::wire::{go_text, go_time};
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

/// How a field takes a repeat and `null`, after its Go type.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// `int`, `string`, `bool`: `null` leaves the value as it was.
    Value,
    /// `[]byte`: `null` clears it, and a repeat is read into the bytes the field holds
    /// ([`crate::wire::go_bytes`]).
    Bytes,
    /// A pointer to a struct: objects add up, `null` clears it.
    Struct,
    /// A slice of structs: arrays are read into the same elements, `null` and `[]` clear
    /// it.
    StructSlice,
    /// A `time.Time`: `null` leaves it as it was, and each repeat must read as a time
    /// ([`crate::wire::go_time`]). A rule the struct sets on the value it keeps (as on a
    /// record's `expiresAt`) holds only for the last one.
    Time,
    /// A `json.RawMessage`: the value as it came, `null` too; the last one counts. Its
    /// text is not read, so a lone surrogate in it stays as written, as in Go.
    Raw,
    /// A signed integer (`int`, `int64`): as [`Kind::Value`], and `-0` is 0.
    Int,
    /// A slice of plain values (`[]string`): arrays are read into the same elements, a
    /// `null` element leaves one as it was, `null` and `[]` clear it. Read with [`vec()`].
    Slice,
    /// A map of plain values (`map[string]string`, `map[string]int`): objects add up,
    /// `null` clears it, a `null` value is the empty value. Read with [`map()`].
    Map,
    /// A map of structs: as [`Kind::Map`], and each value is read as its struct reads.
    /// Read with [`map()`].
    StructMap,
    /// A field Go reads and this side does not keep: each value must pass the check (read
    /// as Go's type), and the field is then left out.
    Check(fn(&str) -> Result<(), String>),
}

/// A field as Go names it, with its kind.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
}

impl Field {
    pub const fn new(name: &'static str, kind: Kind) -> Self {
        Self { name, kind }
    }

    pub const fn value(name: &'static str) -> Self {
        Self::new(name, Kind::Value)
    }

    pub const fn bytes(name: &'static str) -> Self {
        Self::new(name, Kind::Bytes)
    }

    pub const fn time(name: &'static str) -> Self {
        Self::new(name, Kind::Time)
    }

    pub const fn int(name: &'static str) -> Self {
        Self::new(name, Kind::Int)
    }
}

/// The fields of a struct, and the smallest object its derive takes (each required field
/// with a plain value). A repeated value is checked by reading it in that object.
#[derive(Debug, Clone, Copy)]
pub struct Schema {
    pub fields: &'static [Field],
    pub baseline: &'static [(&'static str, &'static str)],
}

/// Does `key` name the field `name` (ASCII) the way Go matches them?
pub fn name_matches(key: &str, name: &str) -> bool {
    let mut key = key.chars();
    for n in name.bytes() {
        let c = match key.next() {
            Some('\u{212A}') => b'k',
            Some('\u{17F}') => b's',
            Some(c) if c.is_ascii() => (c as u8).to_ascii_lowercase(),
            _ => return false,
        };
        if c != n.to_ascii_lowercase() {
            return false;
        }
    }
    key.next().is_none()
}

type Entries = Vec<(String, Box<RawValue>)>;

/// A key as Go reads it: a lone surrogate escape in it is not an error but U+FFFD. Such
/// a key names no field. The key is taken as it was written (`serde_json` checks it as it
/// checks a raw value: a control character written as it is fails, escapes need not be
/// characters) and then read as text the way Go reads it.
struct GoKey(String);

impl<'de> Deserialize<'de> for GoKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(d)?;
        serde_json::from_str(&go_text::as_text(raw.get()))
            .map(GoKey)
            .map_err(de::Error::custom)
    }
}

struct EntriesVisitor;

impl<'de> Visitor<'de> for EntriesVisitor {
    type Value = Entries;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON objekt")
    }

    // Go leaves a struct as it was when it reads `null` in its place.
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut out = Vec::new();
        while let Some((GoKey(key), value)) = map.next_entry::<GoKey, Box<RawValue>>()? {
            // The object is one level, so its value may be one less than Go's limit.
            go_text::check_depth(value.get(), 1).map_err(de::Error::custom)?;
            out.push((key, value));
        }
        Ok(out)
    }
}

fn is_null(v: &RawValue) -> bool {
    v.get().trim() == "null"
}

fn entries_of(text: &str) -> Result<Entries, String> {
    let mut de = serde_json::Deserializer::from_str(text);
    de::Deserializer::deserialize_any(&mut de, EntriesVisitor).map_err(|e| e.to_string())
}

fn push_entry(out: &mut String, key: &str, raw: &str) {
    if out.len() > 1 {
        out.push(',');
    }
    out.push_str(&go_text::escape_mark(
        serde_json::to_string(key).expect("a string always serializes"),
    ));
    out.push(':');
    out.push_str(raw);
}

/// Reads an object as Go would: `finish` is the struct's own derive, run on the object
/// with Go's field names, each field once.
pub fn read<'de, D, T>(
    deserializer: D,
    schema: &Schema,
    finish: fn(&str) -> serde_json::Result<T>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let entries = deserializer.deserialize_any(EntriesVisitor)?;
    settle(entries, schema, finish).map_err(de::Error::custom)
}

/// The object with each field once, as Go would leave it, read by `finish`. The entries are
/// dropped before `finish` runs, so a large value is not held twice while it is read.
fn settle<T>(
    entries: Entries,
    schema: &Schema,
    finish: fn(&str) -> serde_json::Result<T>,
) -> Result<T, String> {
    let out = settled(&entries, schema, finish)?;
    drop(entries);
    finish(&out).map_err(|e| e.to_string())
}

fn settled<T>(
    entries: &Entries,
    schema: &Schema,
    finish: fn(&str) -> serde_json::Result<T>,
) -> Result<String, String> {
    let mut seen: Vec<Vec<&RawValue>> = vec![Vec::new(); schema.fields.len()];
    for (key, value) in entries {
        if let Some(i) = schema.fields.iter().position(|f| name_matches(key, f.name)) {
            seen[i].push(value);
        }
    }
    let mut out = String::from("{");
    for (field, values) in schema.fields.iter().zip(&seen) {
        if let Kind::Check(read_as_go) = field.kind {
            for v in values.iter().filter(|v| !is_null(v)) {
                read_as_go(v.get())?;
            }
            continue;
        }
        if values.len() > 1 {
            // Go reads every one of them, so a bad one fails the whole object.
            // A raw value is any JSON, which it already is.
            for v in values
                .iter()
                .filter(|v| !is_null(v) && !matches!(field.kind, Kind::Raw))
            {
                // A map of structs keeps its values for their own reader, but its keys
                // must be read as Go reads text, as for the map it keeps.
                let text = match field.kind {
                    Kind::StructMap => Cow::Owned(merged_map(&[v])?.unwrap_or_default()),
                    _ => as_go_reads(field.kind, v.get()),
                };
                if matches!(field.kind, Kind::Time) {
                    go_time::from_json(&text)?;
                } else {
                    check(schema, field.name, &text, finish)?;
                }
            }
        }
        let last: Option<Cow<'_, str>> = match field.kind {
            Kind::Value | Kind::Int | Kind::Time => values
                .iter()
                .rev()
                .find(|v| !is_null(v))
                .map(|v| v.get().into()),
            Kind::Raw => values.last().map(|v| v.get().into()),
            Kind::Bytes if values.len() > 1 => {
                let texts: Vec<Cow<'_, str>> = values
                    .iter()
                    .map(|v| as_go_reads(field.kind, v.get()))
                    .collect();
                let texts: Vec<&str> = texts.iter().map(|t| t.as_ref()).collect();
                crate::wire::go_bytes::merged(&texts)?.map(Cow::Owned)
            }
            Kind::Bytes => values.last().map(|v| v.get().into()),
            Kind::Struct => merged(values)?,
            Kind::StructSlice => merged_slice(values)?,
            Kind::Slice => merged_plain_slice(values)?,
            Kind::Map | Kind::StructMap => merged_map(values)?.map(Cow::Owned),
            Kind::Check(_) => None,
        };
        if let Some(raw) = last {
            push_entry(&mut out, field.name, &as_go_reads(field.kind, &raw));
        }
    }
    out.push('}');
    Ok(out)
}

/// A field's value as the derive should read it to get what Go reads: a raw value as it
/// came, `-0` as 0 for a signed integer, and text with Go's U+FFFD for a lone surrogate
/// or a byte that is not UTF-8. A struct (or structs in a slice or map) is left as it is:
/// its own reader reads its text, and a raw field in it must keep its own.
fn as_go_reads(kind: Kind, raw: &str) -> Cow<'_, str> {
    match kind {
        Kind::Raw | Kind::Struct | Kind::StructSlice | Kind::StructMap | Kind::Check(_) => {
            raw.into()
        }
        Kind::Int | Kind::Slice | Kind::Map => match go_text::as_text(raw) {
            Cow::Borrowed(t) => minus_zero(t),
            Cow::Owned(t) => Cow::Owned(minus_zero(&t).into_owned()),
        },
        Kind::Value | Kind::Bytes | Kind::Time => go_text::as_text(raw),
    }
}

/// JSON text with each number `-0` (outside strings) written `0`, as Go's
/// `strconv.ParseInt` reads it into an integer.
fn minus_zero(json: &str) -> Cow<'_, str> {
    let b = json.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let (mut in_string, mut escaped) = (false, false);
    for i in 0..b.len() {
        let c = b[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            continue;
        }
        if c == b'"' {
            in_string = true;
            continue;
        }
        let starts = c == b'-' && (i == 0 || !is_number_byte(b[i - 1]));
        if starts
            && b.get(i + 1) == Some(&b'0')
            && !b.get(i + 2).is_some_and(|&n| is_number_byte(n))
        {
            let o = out.get_or_insert_with(|| String::with_capacity(json.len()));
            o.push_str(&json[copied..i]);
            copied = i + 1;
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

fn is_number_byte(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
}

/// The smallest object the struct takes, with `name` set to `raw` when given.
fn baseline_with(schema: &Schema, field: Option<(&str, &str)>) -> String {
    let name = field.map(|(n, _)| n);
    let mut out = String::from("{");
    for (k, v) in schema.baseline.iter().filter(|(k, _)| Some(*k) != name) {
        push_entry(&mut out, k, v);
    }
    if let Some((n, raw)) = field {
        push_entry(&mut out, n, raw);
    }
    out.push('}');
    out
}

/// Reads one value of a repeated field in the smallest object the struct takes.
///
/// While it runs, [`checking_repeat`] is true, also for every struct read inside it: the
/// value is one Go reads and then overwrites, so a rule a struct sets on the value it
/// keeps does not hold for it.
fn check<T>(
    schema: &Schema,
    name: &str,
    raw: &str,
    finish: fn(&str) -> serde_json::Result<T>,
) -> Result<(), String> {
    let _checking = Checking::enter();
    finish(&baseline_with(schema, Some((name, raw))))
        .map(drop)
        .map_err(|e| e.to_string())
}

thread_local! {
    static CHECKING: Cell<u32> = const { Cell::new(0) };
}

struct Checking;

impl Checking {
    fn enter() -> Self {
        CHECKING.with(|c| c.set(c.get() + 1));
        Self
    }
}

impl Drop for Checking {
    fn drop(&mut self) {
        CHECKING.with(|c| c.set(c.get() - 1));
    }
}

/// Whether the value being read is a repeat that Go reads and then overwrites (see
/// `check`). A field's own rule on the value a record keeps, beyond what Go asks of the
/// type, applies only when this is false.
pub fn checking_repeat() -> bool {
    CHECKING.with(|c| c.get() > 0)
}

/// A pointer to a struct: the objects since the last `null` add up into one.
fn merged<'a>(values: &[&'a RawValue]) -> Result<Option<Cow<'a, str>>, String> {
    let start = values.iter().rposition(|v| is_null(v));
    let objects = &values[start.map_or(0, |i| i + 1)..];
    match objects {
        [] => Ok(start.map(|_| "null".into())),
        [one] => Ok(Some(one.get().into())),
        many => {
            let mut out = String::from("{");
            for v in many {
                for (k, raw) in entries_of(v.get())? {
                    push_entry(&mut out, &k, raw.get());
                }
            }
            out.push('}');
            Ok(Some(out.into()))
        }
    }
}

/// A map: the objects since the last `null` add up into one, each key once, the last time
/// it came. Its keys are read as Go reads text (a lone surrogate, a byte that is not UTF-8
/// as U+FFFD), so two keys Go reads the same are one.
fn merged_map(values: &[&RawValue]) -> Result<Option<String>, String> {
    let start = values.iter().rposition(|v| is_null(v));
    let objects = &values[start.map_or(0, |i| i + 1)..];
    if objects.is_empty() {
        return Ok(start.map(|_| "null".to_owned()));
    }
    // A key that comes again is left to the map's reader, which keeps the last one and
    // reads each, as Go does.
    let mut out = String::from("{");
    for v in objects {
        for (k, raw) in entries_of(v.get())? {
            push_entry(&mut out, &k, raw.get());
        }
    }
    out.push('}');
    Ok(Some(out))
}

/// A slice of plain values, read as [`merged_slice`] reads structs: element `i` of each
/// array overwrites element `i`, a `null` element leaves it as it was, and `null` or `[]`
/// starts again.
fn merged_plain_slice<'a>(values: &[&'a RawValue]) -> Result<Option<Cow<'a, str>>, String> {
    // One array is read as it is.
    if let [one] = values
        && !is_null(one)
    {
        return Ok(Some(one.get().into()));
    }
    let mut backing: Vec<Option<Box<RawValue>>> = Vec::new();
    let mut len = 0;
    for v in values {
        let elements: Vec<Box<RawValue>> = if is_null(v) {
            Vec::new()
        } else {
            serde_json::from_str(v.get()).map_err(|e| e.to_string())?
        };
        if elements.is_empty() {
            backing.clear();
        }
        len = elements.len();
        for (i, element) in elements.into_iter().enumerate() {
            if i == backing.len() {
                backing.push(None);
            }
            if !is_null(&element) {
                backing[i] = Some(element);
            }
        }
    }
    if len == 0 {
        return Ok(None);
    }
    let elements: Vec<&str> = backing[..len]
        .iter()
        .map(|e| e.as_ref().map_or("null", |e| e.get()))
        .collect();
    Ok(Some(format!("[{}]", elements.join(",")).into()))
}

/// Reads a map field ([`Kind::Map`], [`Kind::StructMap`]) as Go fills it: `null` is an
/// empty map, a `null` value the empty value, and a key that comes twice the last time.
pub fn map<'de, D, T>(d: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let m = Option::<BTreeMap<String, Option<T>>>::deserialize(d)?;
    Ok(m.unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, v.unwrap_or_default()))
        .collect())
}

/// Reads a slice field ([`Kind::Slice`], [`Kind::StructSlice`]) as Go fills it: `null` is
/// an empty slice and a `null` element the empty value.
pub fn vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let v = Option::<Vec<Option<T>>>::deserialize(d)?;
    Ok(v.unwrap_or_default()
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect())
}

/// A slice of structs, as Go reads one array after another into the same slice: element
/// `i` of each array adds its fields to element `i` (see the module notes). Go keeps the
/// elements past the end of a shorter array in the slice's backing array, and a longer
/// array later reads into them again; the backing array is never shorter than the longest
/// array since the last `null` or `[]`, so here it is that list of elements. The slice is
/// as long as the last array; a last `null` or `[]` leaves the field out, so it reads as
/// empty, as Go's nil or empty slice.
fn merged_slice<'a>(values: &[&'a RawValue]) -> Result<Option<Cow<'a, str>>, String> {
    // One array is read as it is, but a `null` element reads as `{}`: Go leaves the
    // element empty, where a reader of its own may not take `null`.
    if let [one] = values
        && !is_null(one)
    {
        let elements: Vec<&RawValue> =
            serde_json::from_str(one.get()).map_err(|e| e.to_string())?;
        if elements.is_empty() {
            return Ok(None);
        }
        if !elements.iter().any(|e| is_null(e)) {
            return Ok(Some(one.get().into()));
        }
        let elements: Vec<&str> = elements
            .iter()
            .map(|e| if is_null(e) { "{}" } else { e.get() })
            .collect();
        return Ok(Some(format!("[{}]", elements.join(",")).into()));
    }
    let mut backing: Vec<Entries> = Vec::new();
    let mut len = 0;
    for v in values {
        let elements: Vec<Box<RawValue>> = if is_null(v) {
            Vec::new()
        } else {
            serde_json::from_str(v.get()).map_err(|e| e.to_string())?
        };
        if elements.is_empty() {
            backing.clear();
        }
        for (i, element) in elements.iter().enumerate() {
            if i == backing.len() {
                backing.push(Vec::new());
            }
            backing[i].extend(entries_of(element.get())?);
        }
        len = elements.len();
    }
    if len == 0 {
        return Ok(None);
    }
    let elements: Vec<String> = backing[..len]
        .iter()
        .map(|entries| {
            let mut out = String::from("{");
            for (k, raw) in entries {
                push_entry(&mut out, k, raw.get());
            }
            out.push('}');
            out
        })
        .collect();
    Ok(Some(format!("[{}]", elements.join(",")).into()))
}

/// Serialize and Deserialize for a struct derived with `#[serde(remote = "Self")]`:
/// writing is the derive's, reading goes through [`read`] with the given schema.
macro_rules! go_struct {
    ($ty:ty, $schema:expr) => {
        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                <$ty>::serialize(self, s)
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                $crate::wire::go_object::read(d, &$schema, |text| {
                    <$ty>::deserialize(&mut serde_json::Deserializer::from_str(text))
                })
            }
        }

        impl $crate::wire::go_text::GoRead for $ty {}
    };
}
pub(crate) use go_struct;

/// Deserialize only, for a struct this side reads as Go does but never writes (derived
/// with `#[serde(remote = "Self")]`).
macro_rules! go_read_only {
    ($ty:ty, $schema:expr) => {
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                $crate::wire::go_object::read(d, &$schema, |text| {
                    <$ty>::deserialize(&mut serde_json::Deserializer::from_str(text))
                })
            }
        }

        impl $crate::wire::go_text::GoRead for $ty {}
    };
}
pub(crate) use go_read_only;

#[cfg(test)]
mod tests {
    use super::name_matches;
    use crate::pairing::SasWireMessage;
    use crate::wire::signal::{SignalBody, SignedSignalMessage};

    #[test]
    fn names_match_as_in_go() {
        assert!(name_matches("potpis", "potpis"));
        assert!(name_matches("POTPIS", "potpis"));
        assert!(name_matches("potpi\u{17F}", "potpis"));
        assert!(name_matches("po\u{212A}usaj", "pokusaj"));
        assert!(name_matches("RTTMS", "rttMs"));
        assert!(!name_matches("t\u{131}jelo", "tijelo"));
        assert!(!name_matches("t\u{130}jelo", "tijelo"));
        assert!(!name_matches("potpis ", "potpis"));
        assert!(!name_matches("potpi", "potpis"));
        assert!(!name_matches("pot_pis", "potpis"));
    }

    fn bytes(b: &[u8]) -> String {
        format!("hex:{}", hex::encode(b))
    }

    fn opt_bytes(b: &Option<Vec<u8>>) -> String {
        b.as_deref().map_or_else(|| "nil".to_owned(), bytes)
    }

    fn read_pp(text: &str) -> String {
        match serde_json::from_str::<SignedSignalMessage>(text) {
            Ok(m) => format!("t={} p={}", bytes(&m.tijelo), bytes(&m.potpis)),
            Err(_) => "GRESKA".into(),
        }
    }

    fn read_tp(text: &str) -> String {
        let Ok(b) = serde_json::from_str::<SignalBody>(text) else {
            return "GRESKA".into();
        };
        let kand: Vec<String> = b
            .kandidati
            .iter()
            .map(|k| format!("{}/{}", k.vrsta, k.adresa))
            .collect();
        let nat = b.nat.as_ref().map_or_else(
            || "nil".to_owned(),
            |n| format!("{}/{}", n.vrsta, n.udp_blokiran),
        );
        format!(
            "ver={} sesija={} od={} za={} sast={} izdano={} tajna={} kand=[{}] nat={} odluka={} razlog={} obrada={} pokusaj={} rtt={} vj={}",
            b.ver,
            b.sesija,
            b.od,
            b.za,
            b.sastajaliste,
            b.izdano,
            opt_bytes(&b.tajna),
            kand.join(";"),
            nat,
            b.odluka.unwrap_or_default(),
            b.razlog.unwrap_or_default(),
            b.obrada_ms.unwrap_or(0),
            b.pokusaj.unwrap_or(0),
            b.rtt_ms.unwrap_or(0),
            opt_bytes(&b.vj),
        )
    }

    fn read_sas(text: &str) -> String {
        match serde_json::from_str::<SasWireMessage>(text) {
            Ok(m) => format!("o={} b={}", opt_bytes(&m.obveza), opt_bytes(&m.broj)),
            Err(_) => "GRESKA".into(),
        }
    }

    const B: &str = r#""ver":1,"sesija":"s","od":"o","za":"z","sastajaliste":"x","izdano":5"#;

    /// Go's reading of a signal body is long; most rows change one field of this one.
    const BODY: &str = "ver=1 sesija=s od=o za=z sast=x izdano=5 tajna=nil kand=[] nat=nil odluka= razlog= obrada=0 pokusaj=0 rtt=0 vj=nil";

    /// (struct, JSON text, what Go's `encoding/json` reads, what Rust does). The structs
    /// are the Go side's signed message (`pp`), signal body (`tp`) and code-agreement
    /// message (`sas`); a `tp` text starting with `,` is added after [`B`]. The Go column is
    /// go1.27.1 through `json.Unmarshal` (`json.Decoder` for `sas`), written as the test
    /// writes the Rust result; for `tp` a `~` row lists only the fields that differ from
    /// [`BODY`]. Rust: `isto` reads the same (every row), `GRESKA` would refuse where Go
    /// reads. Rust never takes a text that Go refuses, nor reads one differently.
    ///
    /// A `[]byte` that Go leaves nil reads in Rust as an empty `Vec` when the field is
    /// required (`tijelo`, `potpis`): Go's checks look only at the length.
    const EDGES: &[(&str, &str, &str, &str)] = &[
        // Signed message: key spelling.
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"Tijelo":"e30=","Potpis":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"TIJELO":"e30=","POTPIS":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijeLo":"e30=","potpiS":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            "{\"tijelo\":\"e30=\",\"potpi\u{17F}\":\"AQ==\"}",
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpi\u017f":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            "{\"t\u{131}jelo\":\"e30=\",\"potpis\":\"AQ==\"}",
            "t=nil p=hex:01",
            "isto",
        ),
        (
            "pp",
            "{\"t\u{130}jelo\":\"e30=\",\"potpis\":\"AQ==\"}",
            "t=nil p=hex:01",
            "isto",
        ),
        (
            "pp",
            "{\"T\u{130}JELO\":\"e30=\",\"potpis\":\"AQ==\"}",
            "t=nil p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"\u0074ijelo":"e30=","potpis":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo ":"e30=","potpis":"AQ=="}"#,
            "t=nil p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tij_elo":"e30=","potpis":"AQ=="}"#,
            "t=nil p=hex:01",
            "isto",
        ),
        // Signed message: the same field twice, the last one counts.
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","Potpis":"Ag=="}"#,
            "t=hex:7b7d p=hex:02",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","Potpis":"Ag==","potpis":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","Potpis":"!!"}"#,
            "GRESKA",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","Potpis":5}"#,
            "GRESKA",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","potpis":"Ag=="}"#,
            "t=hex:7b7d p=hex:02",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","potpis":null}"#,
            "t=hex:7b7d p=nil",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":null,"potpis":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"!!","potpis":"AQ=="}"#,
            "GRESKA",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","potpis":"!!"}"#,
            "GRESKA",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":5,"potpis":"AQ=="}"#,
            "GRESKA",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","potpis":[2]}"#,
            "t=hex:7b7d p=hex:02",
            "isto",
        ),
        (
            "pp",
            "{\"tijelo\":\"e30=\",\"potpis\":\"AQ==\",\"POTPIS\":\"Ag==\",\"potpi\u{17F}\":\"Aw==\"}",
            "t=hex:7b7d p=hex:03",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","tijelo":"W10=","potpis":"AQ=="}"#,
            "t=hex:5b5d p=hex:01",
            "isto",
        ),
        // Signed message: other keys, missing fields, not an object.
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","vrsta":"x","-":"y","Vrsta":1}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","potpis2":"zz"}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        ("pp", r#"{"tijelo":"e30="}"#, "t=hex:7b7d p=nil", "isto"),
        ("pp", r#"{"potpis":"AQ=="}"#, "t=nil p=hex:01", "isto"),
        ("pp", "{}", "t=nil p=nil", "isto"),
        ("pp", "null", "t=nil p=nil", "isto"),
        ("pp", "[]", "GRESKA", "isto"),
        // Signal body: key spelling.
        ("tp", "", "~", "isto"),
        ("tp", r#","vj":"AA==""#, "~vj=hex:00", "isto"),
        ("tp", r#","VJ":"AA==""#, "~vj=hex:00", "isto"),
        ("tp", r#","Vj":"AA==""#, "~vj=hex:00", "isto"),
        ("tp", r#","vJ":"AA==""#, "~vj=hex:00", "isto"),
        ("tp", r#","Tajna":"AQ==""#, "~tajna=hex:01", "isto"),
        ("tp", r#","ZA":"z2""#, "~za=z2", "isto"),
        ("tp", r#","Sastajaliste":"x2""#, "~sast=x2", "isto"),
        ("tp", r#","SASTAJALISTE":"x2""#, "~sast=x2", "isto"),
        (
            "tp",
            ",\"\u{17F}astajali\u{17F}te\":\"x2\"",
            "~sast=x2",
            "isto",
        ),
        ("tp", ",\"sastajal\u{131}ste\":\"x2\"", "~", "isto"),
        ("tp", ",\"sastajal\u{130}ste\":\"x2\"", "~", "isto"),
        ("tp", r#","Od":"o2""#, "~od=o2", "isto"),
        ("tp", r#","OD":"o2""#, "~od=o2", "isto"),
        ("tp", r#","Ver":2"#, "~ver=2", "isto"),
        ("tp", r#","VER":2"#, "~ver=2", "isto"),
        ("tp", r#","Izdano":7"#, "~izdano=7", "isto"),
        ("tp", r#","Sesija":"s2""#, "~sesija=s2", "isto"),
        ("tp", r#","SESIJA":"s2""#, "~sesija=s2", "isto"),
        ("tp", ",\"\u{17F}e\u{17F}ija\":\"s2\"", "~sesija=s2", "isto"),
        ("tp", ",\"ses\u{131}ja\":\"s2\"", "~", "isto"),
        ("tp", r#","pokusaj":1"#, "~pokusaj=1", "isto"),
        ("tp", r#","Pokusaj":1"#, "~pokusaj=1", "isto"),
        ("tp", r#","POKUSAJ":2"#, "~pokusaj=2", "isto"),
        ("tp", ",\"po\u{212A}usaj\":2", "~pokusaj=2", "isto"),
        ("tp", ",\"PO\u{212A}USAJ\":2", "~pokusaj=2", "isto"),
        ("tp", r#","po\u212Ausaj":2"#, "~pokusaj=2", "isto"),
        ("tp", ",\"poku\u{17F}aj\":3", "~pokusaj=3", "isto"),
        ("tp", r#","rttms":4"#, "~rtt=4", "isto"),
        ("tp", r#","RTTMS":4"#, "~rtt=4", "isto"),
        ("tp", r#","obradams":6"#, "~obrada=6", "isto"),
        ("tp", r#","OBRADAMS":6"#, "~obrada=6", "isto"),
        ("tp", r#","Odluka":"probaj""#, "~odluka=probaj", "isto"),
        ("tp", ",\"o\u{212A}luka\":\"x\"", "~", "isto"),
        (
            "tp",
            ",\"odlu\u{212A}a\":\"probaj\"",
            "~odluka=probaj",
            "isto",
        ),
        ("tp", r#","Razlog":"r""#, "~razlog=r", "isto"),
        ("tp", r#","NAT":{"vrsta":"a"}"#, "~nat=a/false", "isto"),
        (
            "tp",
            r#","Nat":{"Vrsta":"a","UDPBLOKIRAN":true}"#,
            "~nat=a/true",
            "isto",
        ),
        ("tp", r#","nat":{"udpblokiran":true}"#, "~nat=/true", "isto"),
        (
            "tp",
            r#","Kandidati":[{"vrsta":"javna","adresa":"1"}]"#,
            "~kand=[javna/1]",
            "isto",
        ),
        (
            "tp",
            ",\"\u{212A}ANDIDATI\":[{\"VRSTA\":\"javna\",\"Adresa\":\"1\"}]",
            "~kand=[javna/1]",
            "isto",
        ),
        // Signal body: the same field twice. `null` leaves a number or string as it was.
        ("tp", r#","vj":"AA==","VJ":"AQ==""#, "~vj=hex:01", "isto"),
        ("tp", r#","VJ":"AQ==","vj":"AA==""#, "~vj=hex:00", "isto"),
        ("tp", r#","vj":"AA==","vj":null"#, "~", "isto"),
        ("tp", r#","vj":null,"vj":"AA==""#, "~vj=hex:00", "isto"),
        (
            "tp",
            r#","tajna":"AA==","TAJNA":"AQ==""#,
            "~tajna=hex:01",
            "isto",
        ),
        ("tp", r#","za":"z2","ZA":"z3""#, "~za=z3", "isto"),
        ("tp", r#","od":"o2","od":null"#, "~od=o2", "isto"),
        ("tp", r#","od":null"#, "~", "isto"),
        ("tp", r#","ver":2"#, "~ver=2", "isto"),
        ("tp", r#","ver":2,"ver":null"#, "~ver=2", "isto"),
        ("tp", r#","ver":"x""#, "GRESKA", "isto"),
        ("tp", r#","ver":"x","ver":1"#, "GRESKA", "isto"),
        ("tp", r#","izdano":7,"izdano":null"#, "~izdano=7", "isto"),
        ("tp", r#","izdano":null"#, "~", "isto"),
        ("tp", r#","pokusaj":1,"pokusaj":null"#, "~pokusaj=1", "isto"),
        ("tp", r#","pokusaj":1,"pokusaj":2"#, "~pokusaj=2", "isto"),
        ("tp", r#","pokusaj":"x","pokusaj":1"#, "GRESKA", "isto"),
        ("tp", r#","pokusaj":1,"pokusaj":"x""#, "GRESKA", "isto"),
        ("tp", r#","pokusaj":1.5,"pokusaj":1"#, "GRESKA", "isto"),
        ("tp", r#","rttMs":4,"RttMs":5"#, "~rtt=5", "isto"),
        (
            "tp",
            r#","obradaMs":6,"obradaMs":null"#,
            "~obrada=6",
            "isto",
        ),
        (
            "tp",
            r#","odluka":"probaj","odluka":null"#,
            "~odluka=probaj",
            "isto",
        ),
        (
            "tp",
            r#","odluka":"probaj","ODLUKA":"odbij""#,
            "~odluka=odbij",
            "isto",
        ),
        ("tp", r#","razlog":"r","razlog":null"#, "~razlog=r", "isto"),
        // Signal body: `nat` objects add up; `null` starts again.
        ("tp", r#","nat":{"vrsta":"a"}"#, "~nat=a/false", "isto"),
        (
            "tp",
            r#","nat":{"vrsta":"a"},"nat":{"udpBlokiran":true}"#,
            "~nat=a/true",
            "isto",
        ),
        (
            "tp",
            r#","nat":{"vrsta":"a"},"NAT":{"udpBlokiran":true}"#,
            "~nat=a/true",
            "isto",
        ),
        ("tp", r#","nat":{"vrsta":"a"},"nat":null"#, "~", "isto"),
        (
            "tp",
            r#","nat":null,"nat":{"vrsta":"b"}"#,
            "~nat=b/false",
            "isto",
        ),
        (
            "tp",
            r#","nat":{"vrsta":"a"},"nat":null,"nat":{"udpBlokiran":true}"#,
            "~nat=/true",
            "isto",
        ),
        (
            "tp",
            r#","nat":{"vrsta":"a","Vrsta":"b"}"#,
            "~nat=b/false",
            "isto",
        ),
        (
            "tp",
            r#","nat":{"vrsta":"a","vrsta":null}"#,
            "~nat=a/false",
            "isto",
        ),
        (
            "tp",
            r#","nat":{"udpBlokiran":true,"udpBlokiran":null}"#,
            "~nat=/true",
            "isto",
        ),
        (
            "tp",
            r#","nat":{"vrsta":5},"nat":{"vrsta":"a"}"#,
            "GRESKA",
            "isto",
        ),
        (
            "tp",
            r#","nat":{"vrsta":"a"},"nat":{"vrsta":5}"#,
            "GRESKA",
            "isto",
        ),
        ("tp", r#","nat":{"vrsta":"a"},"nat":5"#, "GRESKA", "isto"),
        ("tp", r#","nat":5,"nat":null"#, "GRESKA", "isto"),
        ("tp", r#","nat":null"#, "~", "isto"),
        ("tp", r#","nat":{}"#, "~nat=/false", "isto"),
        // Signal body: candidates. Go reads a second array into the first one's elements,
        // so a field a new element leaves out keeps the old value, and Rust does the same.
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"}]"#,
            "~kand=[javna/1]",
            "isto",
        ),
        ("tp", r#","kandidati":null"#, "~", "isto"),
        ("tp", r#","kandidati":[]"#, "~", "isto"),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"}],"kandidati":[{"adresa":"2"}]"#,
            "~kand=[javna/2]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"},{"vrsta":"lokalna","adresa":"3"}],"kandidati":[{"adresa":"2"}]"#,
            "~kand=[javna/2]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"}],"kandidati":[{"adresa":"2"},{"adresa":"4"}]"#,
            "~kand=[javna/2;/4]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"}],"kandidati":[{"vrsta":"lokalna","adresa":"2"}]"#,
            "~kand=[lokalna/2]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"},{"vrsta":"lokalna","adresa":"3"}],"kandidati":[{"vrsta":"x","adresa":"2"}]"#,
            "~kand=[x/2]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"},{"vrsta":"lokalna","adresa":"3"}],"kandidati":[{"vrsta":"x","adresa":"2"}],"kandidati":[{"vrsta":"y","adresa":"5"},{"vrsta":"z","adresa":"6"}]"#,
            "~kand=[y/5;z/6]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"}],"Kandidati":[{"adresa":"2","vrsta":"lokalna","vrsta":null}]"#,
            "~kand=[lokalna/2]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"}],"kandidati":null"#,
            "~",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"javna","adresa":"1"}],"kandidati":[]"#,
            "~",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"1","VRSTA":"b"}]"#,
            "~kand=[b/1]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"1","vrsta":null}]"#,
            "~kand=[a/1]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":5,"adresa":"1"}],"kandidati":[]"#,
            "GRESKA",
            "isto",
        ),
        ("tp", r#","kandidati":5,"kandidati":null"#, "GRESKA", "isto"),
        ("tp", r#","kandidati":{}"#, "GRESKA", "isto"),
        // A candidate without both fields reads as empty strings, as in Go.
        (
            "tp",
            r#","kandidati":[{"adresa":"1"}]"#,
            "~kand=[/1]",
            "isto",
        ),
        ("tp", r#","kandidati":[null]"#, "~kand=[/]", "isto"),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"1"},null]"#,
            "~kand=[a/1;/]",
            "isto",
        ),
        // Elements a shorter array does not reach come back with a longer one; `null` and
        // `[]` start again.
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"x"},{"vrsta":"c","adresa":"y"}],"kandidati":[{"vrsta":"b"}],"kandidati":[{"vrsta":"d"},{"vrsta":"e"}]"#,
            "~kand=[d/x;e/y]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"x"},{"vrsta":"c","adresa":"y"},{"vrsta":"f","adresa":"z"}],"kandidati":[],"kandidati":[{},{},{},{}]"#,
            "~kand=[/;/;/;/]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"x"}],"kandidati":null,"kandidati":[{"vrsta":"b"}]"#,
            "~kand=[b/]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"x"}],"kandidati":[null]"#,
            "~kand=[a/x]",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"x"}],"KANDIDATI":[{"vrsta":null,"ADRESA":"q"}]"#,
            "~kand=[a/q]",
            "isto",
        ),
        ("tp", r#","kandidati":[{"vrsta":1}]"#, "GRESKA", "isto"),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"x"}],"kandidati":[5]"#,
            "GRESKA",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"a","adresa":"x"}],"kandidati":[{"vrsta":"b","adresa":"y"},{"vrsta":5}],"kandidati":[]"#,
            "GRESKA",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"kind":"javna","addr":"203.0.113.7:4242"}]"#,
            "~kand=[/]",
            "isto",
        ),
        // Signal body: whole texts. A missing or `null` field reads as empty, as in Go; the
        // checks after reading refuse such a body, in Go as in Rust.
        (
            "tp",
            r#"{"vj":"AQ==","ver":1,"sesija":"s","od":"o","za":"z","sastajaliste":"x","izdano":5}"#,
            "~vj=hex:01",
            "isto",
        ),
        (
            "tp",
            r#"{"ver":1,"sesija":"s","od":"o","ZA":"z","sastajaliste":"x","izdano":5}"#,
            "~",
            "isto",
        ),
        (
            "tp",
            r#"{"ver":1,"sesija":null,"od":"o","za":"z","sastajaliste":"x","izdano":5}"#,
            "~sesija=",
            "isto",
        ),
        (
            "tp",
            "null",
            "ver=0 sesija= od= za= sast= izdano=0 tajna=nil kand=[] nat=nil odluka= razlog= obrada=0 pokusaj=0 rtt=0 vj=nil",
            "isto",
        ),
        (
            "tp",
            "{}",
            "ver=0 sesija= od= za= sast= izdano=0 tajna=nil kand=[] nat=nil odluka= razlog= obrada=0 pokusaj=0 rtt=0 vj=nil",
            "isto",
        ),
        // Text Go reads as U+FFFD (`go_text`): a lone surrogate escape in a key names no
        // field, in a text it is U+FFFD, in base64 it is an error, as in Go.
        (
            "pp",
            r#"{"tijelo":"e30=","\ud800":"x","potpis":"AQ=="}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","x":"\udc00"}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==\ud800"}"#,
            "GRESKA",
            "isto",
        ),
        (
            "tp",
            r#","razlog":"a\ud800b""#,
            "~razlog=a\u{FFFD}b",
            "isto",
        ),
        (
            "tp",
            r#","odluka":"\udc00\ud800","sesija":"\ud83d\ude00""#,
            "~odluka=\u{FFFD}\u{FFFD} sesija=\u{1F600}",
            "isto",
        ),
        (
            "tp",
            r#","kandidati":[{"vrsta":"\ud800","adresa":"1"}],"nat":{"vrsta":"\udfff"}"#,
            "~kand=[\u{FFFD}/1] nat=\u{FFFD}/false",
            "isto",
        ),
        ("tp", r#","tajna":"\ud800""#, "GRESKA", "isto"),
        ("tp", r#","po\ud800kusaj":1"#, "~", "isto"),
        // A control character written as it is in a key is an error, as in a value; as an
        // escape it is a key that names no field. U+007F is not a control character here.
        (
            "pp",
            "{\"tijelo\":\"e30=\",\"potpis\":\"AQ==\",\"a\u{1}b\":1}",
            "GRESKA",
            "isto",
        ),
        (
            "pp",
            "{\"tijelo\":\"e30=\",\"potpis\":\"AQ==\",\"a\nb\":1}",
            "GRESKA",
            "isto",
        ),
        ("tp", ",\"\u{1f}\":1", "GRESKA", "isto"),
        ("tp", ",\"\u{0}\":1", "GRESKA", "isto"),
        (
            "tp",
            ",\"kandidati\":[{\"vrsta\":\"a\",\"\u{3}\":1}]",
            "GRESKA",
            "isto",
        ),
        ("sas", "{\"broj\":\"AA==\",\"\u{2}\":1}", "GRESKA", "isto"),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQ==","a\u0001b":1,"\u0000":2}"#,
            "t=hex:7b7d p=hex:01",
            "isto",
        ),
        ("tp", ",\"a\u{7f}b\":1", "~", "isto"),
        ("tp", r#","a\x":1"#, "GRESKA", "isto"),
        // `-0` in an `int` is 0, as Go's `strconv.ParseInt` reads it; other spellings of
        // zero that are not integers stay errors, and so does `-0` in a text or bytes.
        ("tp", r#","ver":-0"#, "~ver=0", "isto"),
        ("tp", r#","izdano": -0 "#, "~izdano=0", "isto"),
        ("tp", r#","pokusaj":-0"#, "~", "isto"),
        ("tp", r#","POKUSAJ":-0"#, "~", "isto"),
        ("tp", r#","obradaMs":-0,"obradaMs":2"#, "~obrada=2", "isto"),
        ("tp", r#","rttMs":2,"rttMs":-0"#, "~", "isto"),
        ("tp", r#","pokusaj":-1"#, "~pokusaj=-1", "isto"),
        ("tp", r#","pokusaj":-0.0"#, "GRESKA", "isto"),
        ("tp", r#","pokusaj":-0e0"#, "GRESKA", "isto"),
        ("tp", r#","pokusaj":-0E+0"#, "GRESKA", "isto"),
        ("tp", r#","rttMs":0.0"#, "GRESKA", "isto"),
        ("tp", r#","rttMs":1e0"#, "GRESKA", "isto"),
        ("tp", r#","sesija":-0"#, "GRESKA", "isto"),
        ("tp", r#","tajna":-0"#, "GRESKA", "isto"),
        ("tp", r#","nat":{"vrsta":-0}"#, "GRESKA", "isto"),
        // Code agreement.
        ("sas", r#"{"broj":"AA=="}"#, "o=nil b=hex:00", "isto"),
        ("sas", r#"{"Broj":"AA=="}"#, "o=nil b=hex:00", "isto"),
        ("sas", r#"{"BROJ":"AA=="}"#, "o=nil b=hex:00", "isto"),
        ("sas", r#"{"OBVEZA":"AA=="}"#, "o=hex:00 b=nil", "isto"),
        (
            "sas",
            r#"{"Obveza":"AA==","obveza":"AQ=="}"#,
            "o=hex:01 b=nil",
            "isto",
        ),
        (
            "sas",
            r#"{"broj":"AA==","broj":null}"#,
            "o=nil b=nil",
            "isto",
        ),
        (
            "sas",
            r#"{"broj":null,"broj":"AA=="}"#,
            "o=nil b=hex:00",
            "isto",
        ),
        (
            "sas",
            r#"{"broj":"AA==","BROJ":"AQ=="}"#,
            "o=nil b=hex:01",
            "isto",
        ),
        ("sas", r#"{"broj":"!!","broj":"AA=="}"#, "GRESKA", "isto"),
        (
            "sas",
            r#"{"obveza":"","broj":"AA=="}"#,
            "o=hex: b=hex:00",
            "isto",
        ),
        (
            "sas",
            r#"{"obveza":[],"broj":"AA=="}"#,
            "o=hex: b=hex:00",
            "isto",
        ),
        ("sas", "{\"bro\u{135}\":\"AA==\"}", "o=nil b=nil", "isto"),
        (
            "sas",
            r#"{"brOJ":"AA==","obveza":"AQ==","OBVEZA":null}"#,
            "o=nil b=hex:00",
            "isto",
        ),
        ("sas", "{}", "o=nil b=nil", "isto"),
        ("sas", "null", "o=nil b=nil", "isto"),
        (
            "sas",
            r#"{"broj":"AA==","\ud800":1}"#,
            "o=nil b=hex:00",
            "isto",
        ),
        ("sas", r#"{"broj":"AA\ud800=="}"#, "GRESKA", "isto"),
    ];

    /// (struct, text with `{}` where the deep value goes, how many levels the text adds
    /// around it, Go). The deep value is arrays, then objects, nested so that the whole
    /// text is 10 000 or 10 001 levels deep. Go column: go1.27.1 through `json.Unmarshal`,
    /// which refuses the whole text past 10 000 levels, also in a field it skips.
    const DEPTHS: &[(&str, &str, usize)] = &[
        ("pp", r#"{"tijelo":"e30=","potpis":"AQ==","zz":{}}"#, 1),
        ("sas", r#"{"broj":"AA==","zz":{}}"#, 1),
        ("tp", r#","zz":{}"#, 1),
        ("tp", r#","kandidati":[{"vrsta":"a","zz":{}}]"#, 3),
        ("tp", r#","nat":{"vrsta":"a","zz":{}}"#, 2),
    ];

    #[test]
    fn values_nested_deeper_than_go_reads_are_refused() {
        for (kind, text, around) in DEPTHS {
            for (whole, go) in [(10_000, "OK"), (10_001, "GRESKA")] {
                let n = whole - around;
                for deep in [
                    format!("{}{}", "[".repeat(n), "]".repeat(n)),
                    format!("{}1{}", "{\"b\":".repeat(n), "}".repeat(n)),
                ] {
                    let text = text.replacen("{}", &deep, 1);
                    let text = if *kind == "tp" {
                        format!("{{{B}{text}}}")
                    } else {
                        text
                    };
                    let got = match *kind {
                        "pp" => read_pp(&text),
                        "sas" => read_sas(&text),
                        _ => read_tp(&text),
                    };
                    let got = if got == "GRESKA" { "GRESKA" } else { "OK" };
                    assert_eq!(got, go, "{kind} {whole} {}", &text[..40]);
                }
            }
        }
    }

    /// Go's reading in full: a `~` row is [`BODY`] with the listed fields changed.
    fn go_reading(kind: &str, go: &str) -> String {
        if kind == "pp" {
            return go.replace("t=nil", "t=hex:").replace("p=nil", "p=hex:");
        }
        let Some(changes) = go.strip_prefix('~') else {
            return go.to_owned();
        };
        let mut fields: Vec<String> = BODY.split(' ').map(str::to_owned).collect();
        for change in changes.split(' ').filter(|c| !c.is_empty()) {
            let name = change.split('=').next().unwrap();
            let slot = fields
                .iter_mut()
                .find(|f| f.split('=').next() == Some(name))
                .unwrap_or_else(|| panic!("no field {name}"));
            *slot = change.to_owned();
        }
        fields.join(" ")
    }

    /// (message, JSON text with a `[]byte` field given more than once, what Go reads: the
    /// bytes, `nil` or `GRESKA`). Go column: go1.27.1, `json.Unmarshal` into the Go side's
    /// structs. Each later value is read into the bytes the field holds: a `null` element
    /// shows the old byte, `null` and `[]` start again, `""` does not, and where a line break
    /// makes base64 decode to fewer bytes than its length promises, the zeros Go's decoder
    /// writes past them stay (`AAAAAAAA\n\n\n\n`).
    const REPEATED_BYTES: &[(&str, &str, &str)] = &[
        (
            "sas",
            r#"{"broj":"QUJD","broj":[null,null]}"#,
            "o=nil b=hex:4142",
        ),
        ("sas", r#"{"broj":[1,2],"broj":[null]}"#, "o=nil b=hex:01"),
        (
            "sas",
            r#"{"broj":"QUJD","broj":"QQ==","broj":[null,null,null]}"#,
            "o=nil b=hex:414243",
        ),
        (
            "sas",
            r#"{"broj":"QUJD","broj":"QQ==","broj":[null,null,null,null]}"#,
            "o=nil b=hex:41424300",
        ),
        (
            "sas",
            r#"{"broj":"QUJD","broj":"","broj":[null,null]}"#,
            "o=nil b=hex:4142",
        ),
        (
            "sas",
            r#"{"broj":"QUJD","broj":null,"broj":[null,null]}"#,
            "o=nil b=hex:0000",
        ),
        (
            "sas",
            r#"{"broj":"QUJD","broj":[],"broj":[null,null]}"#,
            "o=nil b=hex:0000",
        ),
        ("sas", r#"{"broj":"QUJD","broj":null}"#, "o=nil b=nil"),
        ("sas", r#"{"broj":"QUJD","broj":[]}"#, "o=nil b=hex:"),
        ("sas", r#"{"broj":"QUJD","broj":""}"#, "o=nil b=hex:"),
        (
            "sas",
            r#"{"broj":[1,2,3,4,5,6,7,8,9,10],"broj":"AAAAAAAA\n\n\n\n","broj":[null,null,null,null,null,null,null,null,null,null]}"#,
            "o=nil b=hex:0000000000000000090a",
        ),
        (
            "sas",
            r#"{"broj":[1,2,3,4,5,6,7,8,9,10],"broj":"AAAAAAAA","broj":[null,null,null,null,null,null,null,null,null,null]}"#,
            "o=nil b=hex:0000000000000708090a",
        ),
        (
            "sas",
            r#"{"broj":[1,2,3,4,5,6,7],"broj":"AAAA\n\n\n\n","broj":[null,null,null,null,null,null,null]}"#,
            "o=nil b=hex:00000000050607",
        ),
        (
            "sas",
            r#"{"broj":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18],"broj":"QUJD\nRA==","broj":[null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null]}"#,
            "o=nil b=hex:4142434405060708090a0b0c0d0e0f101112",
        ),
        (
            "sas",
            r#"{"obveza":"QUJDREVG","obveza":"QQ==","obveza":[null,null,null,null,null,null]}"#,
            "o=hex:414243444546 b=nil",
        ),
        (
            "sas",
            r#"{"obveza":"QUJD","obveza":"QUJDREVGR0g=","obveza":[null,null,null,null,null,null,null,null,null,null]}"#,
            "o=hex:41424344454647480000 b=nil",
        ),
        (
            "sas",
            r#"{"obveza":[1],"obveza":[null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null]}"#,
            "o=hex:0100000000000000000000000000000000 b=nil",
        ),
        (
            "sas",
            r#"{"obveza":"QUJD","obveza":"QQ","broj":"AA=="}"#,
            "GRESKA",
        ),
        ("sas", r#"{"obveza":"QUJD","obveza":[256]}"#, "GRESKA"),
        (
            "sas",
            r#"{"OBVEZA":"QUJD","obveza":[null,7]}"#,
            "o=hex:4107 b=nil",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","tijelo":[null],"potpis":"AQ=="}"#,
            "t=hex:7b p=hex:01",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQID","potpis":[null,null]}"#,
            "t=hex:7b7d p=hex:0102",
        ),
        (
            "pp",
            r#"{"tijelo":"e30=","potpis":"AQID","potpis":null}"#,
            "t=hex:7b7d p=hex:",
        ),
        (
            "tp",
            r#"{"ver":1,"tajna":"QUJD","tajna":[null]}"#,
            "tajna=hex:41 vj=nil",
        ),
        (
            "tp",
            r#"{"ver":1,"vj":[9,8,7],"vj":"AQ==","vj":[null,null,null]}"#,
            "tajna=nil vj=hex:010807",
        ),
        (
            "tp",
            r#"{"ver":1,"tajna":"QUJD","tajna":null}"#,
            "tajna=nil vj=nil",
        ),
    ];

    #[test]
    fn repeated_bytes_read_as_in_go() {
        for (kind, text, go) in REPEATED_BYTES {
            let got = match *kind {
                "sas" => read_sas(text),
                "pp" => read_pp(text),
                _ => serde_json::from_str::<SignalBody>(text).map_or("GRESKA".into(), |b| {
                    format!("tajna={} vj={}", opt_bytes(&b.tajna), opt_bytes(&b.vj))
                }),
            };
            assert_eq!(got, *go, "{kind} {text}");
        }
    }

    #[test]
    fn objects_read_as_go_reads_them() {
        let mut refused = 0;
        for (kind, text, go, rust) in EDGES {
            let text = if *kind == "tp" && (text.is_empty() || text.starts_with(',')) {
                format!("{{{B}{text}}}")
            } else {
                (*text).to_owned()
            };
            let got = match *kind {
                "pp" => read_pp(&text),
                "tp" => read_tp(&text),
                "sas" => read_sas(&text),
                _ => unreachable!(),
            };
            let want = match *rust {
                "isto" => go_reading(kind, go),
                "GRESKA" => {
                    // Rust may only refuse where Go reads, never read differently.
                    assert_ne!(*go, "GRESKA", "{text}");
                    refused += 1;
                    "GRESKA".to_owned()
                }
                other => panic!("{other}"),
            };
            assert_eq!(got, want, "{kind} {text}");
        }
        assert_eq!(refused, 0);
    }

    /// The smallest object of each schema must read, or a repeated value would be
    /// refused for the wrong reason.
    #[test]
    fn baselines_read() {
        use super::baseline_with;
        use crate::pairing::SAS_SCHEMA;
        use crate::wire::signal::{
            BODY_SCHEMA, CANDIDATE_SCHEMA, CandidateAddr, NAT_SCHEMA, NatReport, SIGNED_SCHEMA,
        };
        let b = |s| baseline_with(s, None);
        serde_json::from_str::<SignalBody>(&b(&BODY_SCHEMA)).unwrap();
        serde_json::from_str::<SignedSignalMessage>(&b(&SIGNED_SCHEMA)).unwrap();
        serde_json::from_str::<SasWireMessage>(&b(&SAS_SCHEMA)).unwrap();
        serde_json::from_str::<NatReport>(&b(&NAT_SCHEMA)).unwrap();
        serde_json::from_str::<CandidateAddr>(&b(&CANDIDATE_SCHEMA)).unwrap();
    }
}
