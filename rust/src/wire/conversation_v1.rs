//! Version 1 line-delimited JSON conversation codec and message types (`docs/PROTOKOL.md`).
//!
//! This module provides only the wire codec and message structs verified against
//! `vektori/vektori-razgovora.json`; conversation session logic is kept out until
//! the general ledger abstraction is designed.
//!
//! Messages are read as Go reads them. Written again, they differ from what Go writes for
//! the same message in a few places, none of them in the bytes a version signs: Rust does
//! not tell a missing list or map from an empty one, so `versions`, `otisci`, `stavke`,
//! `frontier`, `granica` and `trazim` are written as `[]` or `{}` where Go writes `null` for
//! one that never came, and `podaci` as `""` where Go writes `null`; `wants.rules` and
//! `karta` are checked but not kept, so they are not written.

use crate::wire::go_json::to_go_json_vec;
use crate::wire::go_object::{self, Field, Kind, Schema, go_read_only, go_struct};
use crate::wire::go_raw::{RawJson, keep_null};
use crate::wire::{go_bytes, go_text, go_time};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const KIND_V1_FRONTIER: &str = "frontier";
pub const KIND_V1_GRANICA_ODBIJENIH: &str = "granica-odbijenih";
pub const KIND_V1_RUPE: &str = "rupe";
pub const KIND_V1_DELTA: &str = "delta";
pub const KIND_V1_ZELJE: &str = "zelje";
pub const KIND_V1_SADRZAJ: &str = "sadrzaj";
pub const KIND_V1_DONE: &str = "done";
pub const KIND_V1_ODBIJENO: &str = "odbijeno";

pub const MAX_V1_CONTROL_LINE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_V1_RUPE_LINE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_V1_DELTA_LINE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_V1_ZELJE_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_V1_SADRZAJ_LINE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_V1_SADRZAJ_UNREQUESTED_LINE_BYTES: usize = 64 * 1024;
pub const MAX_V1_DONE_LINE_BYTES: usize = 64 * 1024;

pub fn max_line_bytes_for_kind(kind: &str) -> usize {
    match kind {
        KIND_V1_FRONTIER | KIND_V1_GRANICA_ODBIJENIH => MAX_V1_CONTROL_LINE_BYTES,
        KIND_V1_RUPE => MAX_V1_RUPE_LINE_BYTES,
        KIND_V1_DELTA => MAX_V1_DELTA_LINE_BYTES,
        KIND_V1_ZELJE => MAX_V1_ZELJE_LINE_BYTES,
        KIND_V1_SADRZAJ => MAX_V1_SADRZAJ_LINE_BYTES,
        KIND_V1_DONE | KIND_V1_ODBIJENO => MAX_V1_DONE_LINE_BYTES,
        _ => MAX_V1_CONTROL_LINE_BYTES,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationV1Error {
    TooLarge { limit: usize },
    UnexpectedEof,
    Io(String),
    Json(String),
}

impl fmt::Display for ConversationV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { limit } => write!(f, "v1 message exceeds limit of {limit} bytes"),
            Self::UnexpectedEof => write!(f, "unexpected EOF while reading v1 line"),
            Self::Io(m) => write!(f, "v1 I/O error: {m}"),
            Self::Json(m) => write!(f, "v1 JSON error: {m}"),
        }
    }
}

impl std::error::Error for ConversationV1Error {}

fn is_false(v: &bool) -> bool {
    !*v
}

fn is_none_or_empty(v: &Option<String>) -> bool {
    v.as_deref().is_none_or(str::is_empty)
}

fn is_none_or_zero(v: &Option<u64>) -> bool {
    v.is_none_or(|n| n == 0)
}

fn is_none_or_zero_i64(v: &Option<i64>) -> bool {
    v.is_none_or(|n| n == 0)
}

// Every message below is read as Go reads its struct (see [`crate::wire::go_object`]):
// from an object or `null` (the empty message), field names in any ASCII case, the last of
// a repeated field, a missing field or `null` as Go's empty value, maps and slices as Go
// fills them, and keys Go does not know skipped.

/// Wire envelope shared across conversation versions. `odbijeno` carries no `payload`.
///
/// The payload is kept as it came ([`RawJson`], Go's `json.RawMessage`), `null` too. An
/// empty `reason`, `deviceId` or `kod` is not written, as in Go.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct EnvelopeV1 {
    #[serde(default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "is_none_or_zero")]
    pub kod: Option<u64>,
    #[serde(rename = "deviceId", default, skip_serializing_if = "is_none_or_empty")]
    pub device_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "keep_null"
    )]
    pub payload: Option<RawJson>,
}

const ENVELOPE_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("kind"),
        Field::value("reason"),
        Field::value("kod"),
        Field::value("deviceId"),
        Field::new("payload", Kind::Raw),
    ],
    baseline: &[],
};
go_struct!(EnvelopeV1, ENVELOPE_SCHEMA);

impl EnvelopeV1 {
    pub fn with_payload<T: Serialize>(
        kind: &str,
        device_id: &str,
        payload: &T,
    ) -> Result<Self, ConversationV1Error> {
        let raw =
            RawJson::from_value(payload).map_err(|e| ConversationV1Error::Json(e.to_string()))?;
        Ok(Self {
            kind: kind.to_owned(),
            device_id: Some(device_id.to_owned()),
            payload: Some(raw),
            reason: None,
            kod: None,
        })
    }

    /// Reads the payload as Go reads an envelope's payload: a missing payload is the empty
    /// message, and so is `null`; anything else is read as `T`, its depth counted from its
    /// own top.
    pub fn parse_payload<T: go_text::GoRead>(&self) -> Result<T, ConversationV1Error> {
        match &self.payload {
            Some(raw) => raw.parse(),
            None => RawJson::null().parse(),
        }
        .map_err(|e| ConversationV1Error::Json(e.to_string()))
    }
}

/// What the sender wants (`{all, rules}`). `rules` are the application's subscription rules;
/// this side does not keep them, but reads them as Go's types, so a message Go refuses for
/// them is refused here too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct WantsSpec {
    #[serde(default)]
    pub all: bool,
}

const WANTS_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("all"),
        Field::new("rules", Kind::Check(go_rules)),
    ],
    baseline: &[],
};
go_struct!(WantsSpec, WANTS_SCHEMA);

/// One subscription rule as Go reads it; only its shape is checked.
#[derive(Deserialize, Default)]
#[serde(remote = "Self")]
#[allow(dead_code)]
struct Rule {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    sector_id: String,
    #[serde(default)]
    area_id: i64,
    #[serde(default)]
    year_from: i64,
    #[serde(default)]
    year_to: i64,
    #[serde(default)]
    razina: String,
    #[serde(default)]
    drzi_dana: i64,
}

const RULE_SCHEMA: Schema = Schema {
    fields: &[
        Field::int("id"),
        Field::value("kind"),
        Field::value("sector_id"),
        Field::int("area_id"),
        Field::int("year_from"),
        Field::int("year_to"),
        Field::value("razina"),
        Field::int("drzi_dana"),
    ],
    baseline: &[],
};
go_read_only!(Rule, RULE_SCHEMA);

fn go_rules(text: &str) -> Result<(), String> {
    go_object::vec::<_, Rule>(&mut serde_json::Deserializer::from_str(text))
        .map(drop)
        .map_err(|e| e.to_string())
}

/// What the sender reports about an offline map, for display only; only its shape is
/// checked, as for [`WantsSpec`]'s rules.
#[derive(Deserialize, Default)]
#[serde(remote = "Self")]
#[allow(dead_code)]
struct MapReport {
    #[serde(default)]
    otisak: String,
    #[serde(default)]
    slozena: bool,
    #[serde(default)]
    dijelova: i64,
    #[serde(default)]
    svih: i64,
}

const MAP_REPORT_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("otisak"),
        Field::value("slozena"),
        Field::int("dijelova"),
        Field::int("svih"),
    ],
    baseline: &[],
};
go_read_only!(MapReport, MAP_REPORT_SCHEMA);

fn go_map_report(text: &str) -> Result<(), String> {
    serde_json::from_str::<Option<MapReport>>(text)
        .map(drop)
        .map_err(|e| e.to_string())
}

/// Numbers are Go's `int`: any 64-bit integer, negative too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct FrontierPayload {
    #[serde(default, deserialize_with = "go_object::map")]
    pub frontier: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wants: Option<WantsSpec>,
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub gradnja: Option<String>,
    #[serde(
        default,
        deserialize_with = "go_object::vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub mogucnosti: Vec<String>,
    #[serde(
        default,
        deserialize_with = "go_object::map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub vrste: BTreeMap<String, i64>,
    #[serde(
        rename = "cekaNadogradnju",
        default,
        skip_serializing_if = "is_none_or_zero_i64"
    )]
    pub ceka_nadogradnju: Option<i64>,
    #[serde(
        default,
        deserialize_with = "go_object::vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub uloge: Vec<String>,
}

const FRONTIER_SCHEMA: Schema = Schema {
    fields: &[
        Field::new("frontier", Kind::Map),
        Field::new("wants", Kind::Struct),
        Field::value("program"),
        Field::value("gradnja"),
        Field::new("mogucnosti", Kind::Slice),
        Field::new("vrste", Kind::Map),
        Field::int("cekaNadogradnju"),
        Field::new("uloge", Kind::Slice),
        Field::new("karta", Kind::Check(go_map_report)),
    ],
    baseline: &[],
};
go_struct!(FrontierPayload, FRONTIER_SCHEMA);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct GranicaOdbijenihPayload {
    #[serde(default, deserialize_with = "go_object::map")]
    pub granica: BTreeMap<String, String>,
}

const GRANICA_SCHEMA: Schema = Schema {
    fields: &[Field::new("granica", Kind::Map)],
    baseline: &[],
};
go_struct!(GranicaOdbijenihPayload, GRANICA_SCHEMA);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct HoleRange {
    #[serde(default)]
    pub od: String,
    #[serde(rename = "do", default)]
    pub do_: String,
}

const HOLE_SCHEMA: Schema = Schema {
    fields: &[Field::value("od"), Field::value("do")],
    baseline: &[],
};
go_struct!(HoleRange, HOLE_SCHEMA);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct RupePayload {
    #[serde(default, deserialize_with = "go_object::map")]
    pub trazim: BTreeMap<String, HoleRange>,
}

const RUPE_SCHEMA: Schema = Schema {
    fields: &[Field::new("trazim", Kind::StructMap)],
    baseline: &[],
};
go_struct!(RupePayload, RUPE_SCHEMA);

/// A version as the ledger sends it, read as Go reads its version (see
/// [`crate::wire::go_object`]): field names in any ASCII case, the last of a repeated
/// field, a missing field or `null` as Go's empty value, and keys Go does not know
/// skipped. The payload is kept as it came ([`RawJson`], Go's `json.RawMessage`), byte for
/// byte, `null` too; a missing one is `null`, as Go writes it and signs it.
///
/// `created_at` is read as Go reads a time ([`crate::wire::go_time`]): a version whose time
/// Go does not read is an error, so the message that carries it is refused, as in Go.
/// The text is kept as it came, unescaped; a missing or `null` time is Go's zero time,
/// `0001-01-01T00:00:00Z`. It is written as Go writes the time
/// ([`go_time::to_go_text`]): `+00:00` as `Z`, the fraction without its last zeros, and an
/// offset of 24 hours or more not at all, so such a version cannot be sent, as in Go.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct VersionV1 {
    #[serde(default)]
    pub version_id: String,
    #[serde(default)]
    pub entity: String,
    #[serde(default)]
    pub entity_id: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub supersedes: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default = "RawJson::null")]
    pub payload: RawJson,
    #[serde(
        default = "go_zero_time_text",
        deserialize_with = "go_time_text",
        serialize_with = "go_time_write"
    )]
    pub created_at: String,
    /// Go's `int`: any 64-bit integer, negative too.
    #[serde(default)]
    pub schema_version: i64,
    /// Not written when it is empty, as in Go (`omitempty`).
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub channel: Option<String>,
    /// The author's signature over the version and the author's public key, both base64
    /// (`wire::version_signature`). Empty for a version without a signature: one made
    /// before signing existed, or one that came through a peer that does not carry it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub potpis: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kljuc_autora: String,
}

impl Default for VersionV1 {
    fn default() -> Self {
        Self {
            version_id: String::new(),
            entity: String::new(),
            entity_id: String::new(),
            node_id: String::new(),
            supersedes: String::new(),
            archived: false,
            payload: RawJson::null(),
            created_at: go_zero_time_text(),
            schema_version: 0,
            channel: None,
            potpis: String::new(),
            kljuc_autora: String::new(),
        }
    }
}

/// Go's field names (`json` tags) of a version.
pub(crate) const VERSION_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("version_id"),
        Field::value("entity"),
        Field::value("entity_id"),
        Field::value("node_id"),
        Field::value("supersedes"),
        Field::value("archived"),
        Field::new("payload", Kind::Raw),
        Field::time("created_at"),
        Field::int("schema_version"),
        Field::value("channel"),
        Field::value("potpis"),
        Field::value("kljuc_autora"),
    ],
    baseline: &[],
};
go_struct!(VersionV1, VERSION_SCHEMA);

/// What Go writes for a time never set.
const GO_ZERO_TIME_TEXT: &str = "0001-01-01T00:00:00Z";

fn go_zero_time_text() -> String {
    GO_ZERO_TIME_TEXT.to_owned()
}

/// A time written as Go writes it.
fn go_time_write<S: serde::Serializer>(text: &str, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&go_time::to_go_text(text).map_err(serde::ser::Error::custom)?)
}

/// A time as Go reads it, kept as the unescaped text. `null` never gets here: the Go
/// reader leaves it out, so the field is Go's zero time.
fn go_time_text<'de, D: Deserializer<'de>>(de: D) -> Result<String, D::Error> {
    let raw = Box::<RawValue>::deserialize(de)?;
    match go_time::from_json(raw.get()).map_err(serde::de::Error::custom)? {
        Some(_) => serde_json::from_str(raw.get()).map_err(serde::de::Error::custom),
        None => Ok(go_zero_time_text()),
    }
}

/// `tailscale` are the sender's addresses in a private VPN network, with a port; sent only
/// when the conversation goes over that network.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct DeltaPayload {
    #[serde(default, deserialize_with = "go_object::vec")]
    pub versions: Vec<VersionV1>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub skraceno: bool,
    #[serde(
        default,
        deserialize_with = "go_object::vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tailscale: Vec<String>,
    #[serde(
        default,
        deserialize_with = "go_object::map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub rupe: BTreeMap<String, HoleRange>,
    #[serde(
        default,
        deserialize_with = "go_object::map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub popuna: BTreeMap<String, HoleRange>,
}

const DELTA_SCHEMA: Schema = Schema {
    fields: &[
        Field::new("versions", Kind::StructSlice),
        Field::value("skraceno"),
        Field::new("tailscale", Kind::Slice),
        Field::new("rupe", Kind::StructMap),
        Field::new("popuna", Kind::StructMap),
    ],
    baseline: &[],
};
go_struct!(DeltaPayload, DELTA_SCHEMA);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct ZeljePayload {
    #[serde(default, deserialize_with = "go_object::vec")]
    pub otisci: Vec<String>,
}

const ZELJE_SCHEMA: Schema = Schema {
    fields: &[Field::new("otisci", Kind::Slice)],
    baseline: &[],
};
go_struct!(ZeljePayload, ZELJE_SCHEMA);

/// One content item. `podaci` are the bytes, base64 on the wire and read as Go reads a
/// `[]byte` ([`crate::wire::go_bytes`]); `bajtova` is Go's `int`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct ContentItemV1 {
    #[serde(default)]
    pub otisak: String,
    #[serde(default)]
    pub vrsta: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kanal: String,
    #[serde(default)]
    pub bajtova: i64,
    #[serde(default, with = "go_bytes")]
    pub podaci: Vec<u8>,
}

const CONTENT_ITEM_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("otisak"),
        Field::value("vrsta"),
        Field::value("kanal"),
        Field::int("bajtova"),
        Field::bytes("podaci"),
    ],
    baseline: &[],
};
go_struct!(ContentItemV1, CONTENT_ITEM_SCHEMA);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct SadrzajPayload {
    #[serde(default, deserialize_with = "go_object::vec")]
    pub stavke: Vec<ContentItemV1>,
}

const SADRZAJ_SCHEMA: Schema = Schema {
    fields: &[Field::new("stavke", Kind::StructSlice)],
    baseline: &[],
};
go_struct!(SadrzajPayload, SADRZAJ_SCHEMA);

/// `applied` is Go's `int`: any 64-bit integer, negative too; only a notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct DonePayload {
    #[serde(default)]
    pub applied: i64,
}

const DONE_SCHEMA: Schema = Schema {
    fields: &[Field::int("applied")],
    baseline: &[],
};
go_struct!(DonePayload, DONE_SCHEMA);

pub async fn read_line_bytes<R>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, ConversationV1Error>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .await
            .map_err(|e| ConversationV1Error::Io(e.to_string()))?;
        if n == 0 {
            return Err(ConversationV1Error::UnexpectedEof);
        }
        if line.len() >= max_bytes {
            return Err(ConversationV1Error::TooLarge { limit: max_bytes });
        }
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        line.push(byte[0]);
    }
}

pub async fn read_line_message<R, T>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<T, ConversationV1Error>
where
    R: AsyncRead + Unpin,
    T: go_text::GoRead,
{
    let line = read_line_bytes(reader, max_bytes).await?;
    // Bytes that are not UTF-8 are read as Go reads them (`go_text`).
    go_text::from_slice(&line).map_err(|e| ConversationV1Error::Json(e.to_string()))
}

pub async fn write_line_message<W, T>(
    writer: &mut W,
    msg: &T,
    max_bytes: usize,
) -> Result<(), ConversationV1Error>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut bytes = to_go_json_vec(msg).map_err(|e| ConversationV1Error::Json(e.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > max_bytes {
        return Err(ConversationV1Error::TooLarge { limit: max_bytes });
    }
    writer
        .write_all(&bytes)
        .await
        .map_err(|e| ConversationV1Error::Io(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| ConversationV1Error::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::go_json::to_go_json_string;

    fn to_line<T: Serialize>(v: &T) -> String {
        let mut s = to_go_json_string(v).unwrap();
        s.push('\n');
        s
    }

    #[test]
    fn conversation_v1_vectors_match_byte_for_byte() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../vektori/vektori-razgovora.json"))
                .expect("vektori-razgovora.json");
        let z: serde_json::Value =
            serde_json::from_str(include_str!("../../../vektori/vektori-zice.json"))
                .expect("vektori-zice.json");

        // frontier & frontierBezZnanja
        for key in ["frontier", "frontierBezZnanja"] {
            let line = v[key].as_str().unwrap();
            let env: EnvelopeV1 = serde_json::from_str(line.trim_end()).unwrap();
            assert_eq!(env.kind, KIND_V1_FRONTIER);
            let payload: FrontierPayload = env.parse_payload().unwrap();
            let rebuilt = EnvelopeV1::with_payload(
                KIND_V1_FRONTIER,
                env.device_id.as_deref().unwrap(),
                &payload,
            )
            .unwrap();
            assert_eq!(to_line(&rebuilt), line, "{key}");
        }

        // granicaOdbijenih
        let granica_line = v["granicaOdbijenih"].as_str().unwrap();
        let granica_env: EnvelopeV1 = serde_json::from_str(granica_line.trim_end()).unwrap();
        let granica_payload: GranicaOdbijenihPayload = granica_env.parse_payload().unwrap();
        assert_eq!(
            to_line(
                &EnvelopeV1::with_payload(
                    KIND_V1_GRANICA_ODBIJENIH,
                    granica_env.device_id.as_deref().unwrap(),
                    &granica_payload
                )
                .unwrap()
            ),
            granica_line
        );

        // rupe
        let rupe_line = v["rupe"].as_str().unwrap();
        let rupe_env: EnvelopeV1 = serde_json::from_str(rupe_line.trim_end()).unwrap();
        let rupe_payload: RupePayload = rupe_env.parse_payload().unwrap();
        assert_eq!(
            to_line(
                &EnvelopeV1::with_payload(
                    KIND_V1_RUPE,
                    rupe_env.device_id.as_deref().unwrap(),
                    &rupe_payload
                )
                .unwrap()
            ),
            rupe_line
        );

        // delta
        let delta_line = v["delta"].as_str().unwrap();
        let delta_env: EnvelopeV1 = serde_json::from_str(delta_line.trim_end()).unwrap();
        let delta_payload: DeltaPayload = delta_env.parse_payload().unwrap();
        assert_eq!(delta_payload.versions.len(), 2);
        assert_eq!(
            to_line(
                &EnvelopeV1::with_payload(
                    KIND_V1_DELTA,
                    delta_env.device_id.as_deref().unwrap(),
                    &delta_payload
                )
                .unwrap()
            ),
            delta_line
        );

        // praznaDelta: Go sends `"versions":null`, Rust deserializes null as empty Vec and serializes `[]`.
        let empty_delta_line = v["praznaDelta"].as_str().unwrap();
        let empty_delta_env: EnvelopeV1 =
            serde_json::from_str(empty_delta_line.trim_end()).unwrap();
        let empty_delta_payload: DeltaPayload = empty_delta_env.parse_payload().unwrap();
        assert!(empty_delta_payload.versions.is_empty());
        assert_eq!(
            to_line(
                &EnvelopeV1::with_payload(
                    KIND_V1_DELTA,
                    empty_delta_env.device_id.as_deref().unwrap(),
                    &empty_delta_payload
                )
                .unwrap()
            ),
            "{\"kind\":\"delta\",\"deviceId\":\"admin-1\",\"payload\":{\"versions\":[]}}\n"
        );

        // zelje
        let zelje_line = v["zelje"].as_str().unwrap();
        let zelje_env: EnvelopeV1 = serde_json::from_str(zelje_line.trim_end()).unwrap();
        let zelje_payload: ZeljePayload = zelje_env.parse_payload().unwrap();
        assert_eq!(
            to_line(
                &EnvelopeV1::with_payload(
                    KIND_V1_ZELJE,
                    zelje_env.device_id.as_deref().unwrap(),
                    &zelje_payload
                )
                .unwrap()
            ),
            zelje_line
        );

        // sadrzaj & sadrzajBezKanala
        for key in ["sadrzaj", "sadrzajBezKanala"] {
            let sadrzaj_line = v[key].as_str().unwrap();
            let sadrzaj_env: EnvelopeV1 = serde_json::from_str(sadrzaj_line.trim_end()).unwrap();
            let sadrzaj_payload: SadrzajPayload = sadrzaj_env.parse_payload().unwrap();
            assert_eq!(
                to_line(
                    &EnvelopeV1::with_payload(
                        KIND_V1_SADRZAJ,
                        sadrzaj_env.device_id.as_deref().unwrap(),
                        &sadrzaj_payload
                    )
                    .unwrap()
                ),
                sadrzaj_line,
                "{key}"
            );
        }

        // done
        let done_line = v["done"].as_str().unwrap();
        let done_env: EnvelopeV1 = serde_json::from_str(done_line.trim_end()).unwrap();
        let done_payload: DonePayload = done_env.parse_payload().unwrap();
        assert_eq!(
            to_line(
                &EnvelopeV1::with_payload(
                    KIND_V1_DONE,
                    done_env.device_id.as_deref().unwrap(),
                    &done_payload
                )
                .unwrap()
            ),
            done_line
        );

        // verzija (RawValue payload preserved verbatim, created_at as text)
        let ver_str = v["verzija"].as_str().unwrap();
        let ver: VersionV1 = serde_json::from_str(ver_str).unwrap();
        assert_eq!(ver.created_at, "2025-10-09T08:53:21Z");
        assert_eq!(ver.payload.as_bytes(), br#"{"id":"biljeska-1"}"#);
        assert_eq!(serde_json::to_string(&ver).unwrap(), ver_str);

        // odbijenica (no payload), posebniZnakovi.odbijenica & odbijenicaSRazdjelnicima
        for odb_line in [
            z["odbijenica"].as_str().unwrap(),
            z["posebniZnakovi"]["odbijenica"].as_str().unwrap(),
            z["posebniZnakovi"]["odbijenicaSRazdjelnicima"]
                .as_str()
                .unwrap(),
        ] {
            let odb_env: EnvelopeV1 = serde_json::from_str(odb_line.trim_end()).unwrap();
            assert_eq!(odb_env.kind, KIND_V1_ODBIJENO);
            assert!(odb_env.payload.is_none());
            assert_eq!(to_line(&odb_env), odb_line);
        }

        // U+2028 and U+2029 inside RawValue payload are also escaped as \u2028 and \u2029
        let raw_sep = RawJson::from_bytes("{\"t\":\"a\u{2028}b\u{2029}c\"}");
        let ver_sep = VersionV1 {
            version_id: "0199c82c-0000-7000-8000-000000000004".into(),
            entity: "biljeske".into(),
            entity_id: "biljeska-3".into(),
            node_id: "admin-1".into(),
            supersedes: String::new(),
            archived: false,
            payload: raw_sep,
            created_at: "2025-10-09T08:53:23Z".into(),
            schema_version: 1,
            channel: None,
            potpis: String::new(),
            kljuc_autora: String::new(),
        };
        let sep_json = to_go_json_string(&ver_sep).unwrap();
        assert!(sep_json.contains(r#""t":"a\u2028b\u2029c""#));

        // Protocol v1 receive limits (docs/PROTOKOL.md, section 9)
        assert_eq!(max_line_bytes_for_kind(KIND_V1_FRONTIER), 8 * 1024 * 1024);
        assert_eq!(
            max_line_bytes_for_kind(KIND_V1_GRANICA_ODBIJENIH),
            8 * 1024 * 1024
        );
        assert_eq!(max_line_bytes_for_kind(KIND_V1_RUPE), 8 * 1024 * 1024);
        assert_eq!(max_line_bytes_for_kind(KIND_V1_DELTA), 64 * 1024 * 1024);
        assert_eq!(max_line_bytes_for_kind(KIND_V1_ZELJE), 1024 * 1024);
        assert_eq!(max_line_bytes_for_kind(KIND_V1_SADRZAJ), 128 * 1024 * 1024);
        assert_eq!(MAX_V1_SADRZAJ_UNREQUESTED_LINE_BYTES, 64 * 1024);
        assert_eq!(max_line_bytes_for_kind(KIND_V1_DONE), 64 * 1024);
        assert_eq!(max_line_bytes_for_kind(KIND_V1_ODBIJENO), 64 * 1024);

        // deltaSPosebnimZnakovima built from literal sadrzajSPosebnimZnakovima
        let raw_payload = RawJson::from_bytes(v["sadrzajSPosebnimZnakovima"].as_str().unwrap());
        let ver_special = VersionV1 {
            version_id: "0199c82c-0000-7000-8000-000000000003".into(),
            entity: "biljeske".into(),
            entity_id: "biljeska-2".into(),
            node_id: "admin-1".into(),
            supersedes: String::new(),
            archived: false,
            payload: raw_payload,
            created_at: "2025-10-09T08:53:22Z".into(),
            schema_version: 1,
            channel: None,
            potpis: String::new(),
            kljuc_autora: String::new(),
        };
        let delta_special = DeltaPayload {
            versions: vec![ver_special],
            ..Default::default()
        };
        let env_special =
            EnvelopeV1::with_payload(KIND_V1_DELTA, "admin-1", &delta_special).unwrap();
        assert_eq!(
            to_line(&env_special),
            v["deltaSPosebnimZnakovima"].as_str().unwrap()
        );
    }

    /// (`v` a version, `d` a delta message; JSON text; what Go reads; what Rust does).
    /// Go column: go1.27.1, `json.Unmarshal` into the ledger's version (`d`: a struct with
    /// its `versions`), the time as Unix seconds. Rust: `isto` reads the same (every row),
    /// `GRESKA` would refuse where Go reads.
    const VERSION_EDGES: &[(&str, &str, &str, &str)] = &[
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"VERSION_ID":"v","Entity":"e","entity_ID":"i","NODE_id":"n","SUPERSEDES":"s","ARCHIVED":true,"PAYLOAD":{"a":1},"Created_At":"2025-10-09T08:53:20Z","SCHEMA_VERSION":2,"CHANNEL":"c","POTPIS":"p","KLJUC_AUTORA":"k"}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=true pl={"a":1} ca=1760000000 sv=2 ch=c pot=p ka=k"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"ſuperſedeſ":"s2","Kljuc_autora":"k2","ar\u0063hived":true}"#,
            r#"vid=v ent=e eid=i node=n sup=s2 arh=true pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=k2"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"supersıdes":"x","node_İd":"x"}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"node_id":"a","NODE_ID":"b"}"#,
            r#"vid=v ent=e eid=i node=b sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"payload":{"b":2},"Payload":[ 1 ,2 ]}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl=[ 1 ,2 ] ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"payload":null}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl=null ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"payload":null,"payload":"x"}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl="x" ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09T08:53:21Z","CREATED_AT":"2025-10-09T08:53:22.5Z"}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000002 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09T08:53:21Z","created_at":null}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000001 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09t08:53:21Z","created_at":"2025-10-09T08:53:22Z"}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09T08:53:22Z","created_at":"x"}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"archived":true,"archived":null}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=true pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":"1","schema_version":1}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":null,"entity":null,"entity_id":null,"node_id":null,"supersedes":null,"archived":null,"payload":null,"created_at":null,"schema_version":null,"channel":null,"potpis":null,"kljuc_autora":null}"#,
            r#"vid= ent= eid= node= sup= arh=false pl=null ca=-62135596800 sv=0 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{}"#,
            r#"vid= ent= eid= node= sup= arh=false pl=null ca=-62135596800 sv=0 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"null"#,
            r#"vid= ent= eid= node= sup= arh=false pl=null ca=-62135596800 sv=0 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"payload":{"a":1}}"#,
            r#"vid= ent= eid= node= sup= arh=false pl={"a":1} ca=-62135596800 sv=0 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"x":1,"versions":[],"payload2":5,"\ud800":"y"}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09\u005408:53:20Z"}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09T10:53:20.75+02:00"}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":1760000000}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":""}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09T08:53:20\ud800"}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"entity":"a\ud800b","node_id":"\udc00","payload":{"t":"\ud800 \u0041"}}"#,
            r#"vid=v ent=a�b eid=i node=� sup=s arh=false pl={"t":"\ud800 \u0041"} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"archived":"true"}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":1.5}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":-1}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=-1 ch= pot= ka="#,
            "isto",
        ),
        ("v", r#"[]"#, r#"GRESKA"#, "isto"),
        (
            "d",
            r#"{"versions":[{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1},{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"version_id":"w"}]}"#,
            r#"n=2 [vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=] [vid=w ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=]"#,
            "isto",
        ),
        (
            "d",
            r#"{"versions":[{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1},{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":"2025-10-09T08:53:60Z"}]}"#,
            r#"GRESKA"#,
            "isto",
        ),
        (
            "d",
            r#"{"versions":[{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1},{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"created_at":null}]}"#,
            r#"n=2 [vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=] [vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=]"#,
            "isto",
        ),
        (
            "d",
            r#"{"versions":[{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1},{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"entity":"\ud800"}]}"#,
            r#"n=2 [vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=] [vid=v ent=� eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=]"#,
            "isto",
        ),
        (
            "d",
            r#"{"versions":[{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1},null]}"#,
            r#"n=2 [vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka=] [vid= ent= eid= node= sup= arh=false pl=null ca=-62135596800 sv=0 ch= pot= ka=]"#,
            "isto",
        ),
        ("d", r#"{"versions":null}"#, r#"n=0 "#, "isto"),
        // `-0` is 0 in Go's `int`; other zeros that are not integers stay errors.
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":-0}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=0 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version": -0 ,"schema_version":-0,"Schema_Version":3}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=3 ch= pot= ka="#,
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":-0.0}"#,
            "GRESKA",
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":0.0}"#,
            "GRESKA",
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1e0}"#,
            "GRESKA",
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":"-0"}"#,
            "GRESKA",
            "isto",
        ),
        (
            "d",
            r#"{"versions":[{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":-0}]}"#,
            r#"n=1 [vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=0 ch= pot= ka=]"#,
            "isto",
        ),
        // A control character written as it is in a key is an error; as an escape the key
        // names no field.
        (
            "v",
            "{\"version_id\":\"v\",\"entity\":\"e\",\"entity_id\":\"i\",\"node_id\":\"n\",\"supersedes\":\"s\",\"archived\":false,\"payload\":{\"a\":1},\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"k\u{2}\":1}",
            "GRESKA",
            "isto",
        ),
        (
            "v",
            "{\"version_id\":\"v\",\"entity\":\"e\",\"entity_id\":\"i\",\"node_id\":\"n\",\"supersedes\":\"s\",\"archived\":false,\"payload\":{\"a\":1},\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"a\nb\":1}",
            "GRESKA",
            "isto",
        ),
        (
            "v",
            r#"{"version_id":"v","entity":"e","entity_id":"i","node_id":"n","supersedes":"s","archived":false,"payload":{"a":1},"created_at":"2025-10-09T08:53:20Z","schema_version":1,"a\u0001b":1,"\u0000":2}"#,
            r#"vid=v ent=e eid=i node=n sup=s arh=false pl={"a":1} ca=1760000000 sv=1 ch= pot= ka="#,
            "isto",
        ),
        (
            "d",
            "{\"versions\":[{\"version_id\":\"v\",\"k\u{2}\":1}]}",
            "GRESKA",
            "isto",
        ),
        // Go reads a struct only from an object (or `null`), never from an array.
        ("d", "[]", "GRESKA", "isto"),
        (
            "d",
            r#"[[{"version_id":"x","created_at":"2025-10-09T08:53:20Z"}]]"#,
            "GRESKA",
            "isto",
        ),
        ("d", r#"{"versions":[[]]}"#, "GRESKA", "isto"),
        ("d", r#"{"rupe":{"k":["a","b"]}}"#, "GRESKA", "isto"),
        ("d", "null", "n=0 ", "isto"),
    ];

    fn version_reading(v: &VersionV1) -> String {
        let ca = crate::wire::go_time::parse(v.created_at.as_bytes()).map_or(i64::MIN, |t| t.unix);
        format!(
            "vid={} ent={} eid={} node={} sup={} arh={} pl={} ca={ca} sv={} ch={} pot={} ka={}",
            v.version_id,
            v.entity,
            v.entity_id,
            v.node_id,
            v.supersedes,
            v.archived,
            String::from_utf8_lossy(v.payload.as_bytes()),
            v.schema_version,
            v.channel.as_deref().unwrap_or(""),
            v.potpis,
            v.kljuc_autora,
        )
    }

    #[test]
    fn versions_read_as_in_go() {
        let mut refused = 0;
        for (kind, text, go, rust) in VERSION_EDGES {
            let got = if *kind == "v" {
                serde_json::from_str::<VersionV1>(text).map(|v| version_reading(&v))
            } else {
                serde_json::from_str::<DeltaPayload>(text).map(|d| {
                    let vs: Vec<String> = d
                        .versions
                        .iter()
                        .map(|v| format!("[{}]", version_reading(v)))
                        .collect();
                    format!("n={} {}", d.versions.len(), vs.join(" "))
                })
            }
            .unwrap_or_else(|_| "GRESKA".to_owned());
            if *rust == "GRESKA" {
                assert_ne!(*go, "GRESKA", "{text}");
                assert_eq!(got, "GRESKA", "{text}");
                refused += 1;
            } else {
                assert_eq!(got, *go, "{text}");
            }
        }
        assert_eq!(refused, 0);
    }

    /// (message, JSON text, what Go does). Go column: go1.27.1, `json.Unmarshal` into the
    /// Go side's envelope and messages. Go reads a struct only from an object; `null`
    /// leaves it empty, and Rust reads it as `{}`.
    const MESSAGE_SHAPES: &[(&str, &str, &str)] = &[
        ("env", "[]", "GRESKA"),
        (
            "env",
            r#"["delta",null,null,"dev",{"versions":[]}]"#,
            "GRESKA",
        ),
        (
            "env",
            r#"{"kind":"delta","deviceId":"dev","payload":[[]]}"#,
            "OK",
        ),
        ("env", r#"{"kind":"x"}"#, "OK"),
        ("frontier", "[]", "GRESKA"),
        ("frontier", "[{}]", "GRESKA"),
        ("frontier", "null", "OK"),
        ("frontier", r#"{"frontier":{}}"#, "OK"),
        ("frontier", r#"{"frontier":[]}"#, "GRESKA"),
        ("frontier", r#"{"frontier":{},"wants":[true]}"#, "GRESKA"),
        ("frontier", r#"{"frontier":{},"wants":{"all":true}}"#, "OK"),
        ("granica", "[]", "GRESKA"),
        ("granica", "null", "OK"),
        ("granica", r#"{"granica":{}}"#, "OK"),
        ("granica", r#"{"granica":[]}"#, "GRESKA"),
        ("rupe", "[]", "GRESKA"),
        ("rupe", "null", "OK"),
        ("rupe", r#"{"trazim":{"k":["a","b"]}}"#, "GRESKA"),
        ("rupe", r#"{"trazim":{"k":{"od":"a","do":"b"}}}"#, "OK"),
        ("delta", r#"{"versions":[],"skraceno":true}"#, "OK"),
        ("delta", r#"{"rupe":{"k":{"od":"a","do":"b"}}}"#, "OK"),
        ("zelje", "[]", "GRESKA"),
        ("zelje", r#"[["a"]]"#, "GRESKA"),
        ("zelje", "null", "OK"),
        ("zelje", r#"{"otisci":["a"]}"#, "OK"),
        ("sadrzaj", "[]", "GRESKA"),
        ("sadrzaj", "null", "OK"),
        ("sadrzaj", r#"{"stavke":[["o","v","",1,"AA=="]]}"#, "GRESKA"),
        (
            "sadrzaj",
            r#"{"stavke":[{"otisak":"o","vrsta":"v","kanal":"","bajtova":1,"podaci":"AA=="}]}"#,
            "OK",
        ),
        ("done", "[]", "GRESKA"),
        ("done", "[5]", "GRESKA"),
        ("done", r#"{"applied":5}"#, "OK"),
    ];

    #[test]
    fn messages_read_only_from_objects_as_in_go() {
        fn ok<T: serde::de::DeserializeOwned>(text: &str) -> &'static str {
            serde_json::from_str::<T>(text).map_or("GRESKA", |_| "OK")
        }
        for (kind, text, go) in MESSAGE_SHAPES {
            let got = match *kind {
                "env" => ok::<EnvelopeV1>(text),
                "frontier" => ok::<FrontierPayload>(text),
                "granica" => ok::<GranicaOdbijenihPayload>(text),
                "rupe" => ok::<RupePayload>(text),
                "delta" => ok::<DeltaPayload>(text),
                "zelje" => ok::<ZeljePayload>(text),
                "sadrzaj" => ok::<SadrzajPayload>(text),
                _ => ok::<DonePayload>(text),
            };
            assert_eq!(got, *go, "{kind} {text}");
        }
        // Go reads these as empty, and so does Rust.
        assert_eq!(serde_json::from_str::<EnvelopeV1>("null").unwrap().kind, "");
        assert_eq!(
            serde_json::from_str::<DonePayload>("null").unwrap().applied,
            0
        );
    }

    /// Go refuses a line nested deeper than 10 000 levels (go1.27.1), also when the deep
    /// part is a version's payload, which it keeps raw.
    #[tokio::test]
    async fn line_nested_deeper_than_go_reads_is_refused() {
        for (whole, go) in [(10_000, true), (10_001, false)] {
            // The line, the payload, `versions` and the version are four levels.
            let n = whole - 4;
            let line = format!(
                "{{\"kind\":\"delta\",\"payload\":{{\"versions\":[{{\"version_id\":\"v\",\"payload\":{}{}}}]}}}}\n",
                "[".repeat(n),
                "]".repeat(n)
            );
            let (mut w, mut r) = tokio::io::duplex(64 * 1024);
            w.write_all(line.as_bytes()).await.unwrap();
            let got = read_line_message::<_, EnvelopeV1>(&mut r, 1 << 20).await;
            assert_eq!(got.is_ok(), go, "{whole}");
            if let Ok(env) = got {
                let d: DeltaPayload = env.parse_payload().unwrap();
                assert_eq!(d.versions[0].payload.as_bytes().len(), 2 * n);
            }
        }
    }

    #[tokio::test]
    async fn line_codec_enforces_size_limits_and_roundtrips() {
        let (mut w, mut r) = tokio::io::duplex(4096);
        let env =
            EnvelopeV1::with_payload(KIND_V1_DONE, "node-1", &DonePayload { applied: 3 }).unwrap();
        write_line_message(&mut w, &env, max_line_bytes_for_kind(KIND_V1_DONE))
            .await
            .unwrap();
        let got: EnvelopeV1 = read_line_message(&mut r, max_line_bytes_for_kind(KIND_V1_DONE))
            .await
            .unwrap();
        assert_eq!(got.kind, KIND_V1_DONE);
        assert_eq!(got.parse_payload::<DonePayload>().unwrap().applied, 3);

        // Oversized line rejected without reading past limit
        write_line_message(&mut w, &env, 1024).await.unwrap();
        let err = read_line_message::<_, EnvelopeV1>(&mut r, 10).await;
        assert!(matches!(
            err,
            Err(ConversationV1Error::TooLarge { limit: 10 })
        ));
    }

    /// What Go reads, written as the Go probe writes it: a struct is `{name=value ...}` with
    /// the fields Go would write, sorted by name, each only when it is not empty; text is
    /// `h:` and its bytes in hex, bytes `b:` and hex, a raw value `raw:` and hex (a missing
    /// raw value that Go writes as `null` is `null`), a time `t:` and Unix seconds with
    /// nanoseconds, a map `{key in hex:value,...}`, a slice `[...]`, a pointer `&` and what it
    /// points to. Fields Rust only checks (`rules`, `karta`) are left out.
    mod dump {
        use super::super::*;
        use crate::pairing::{PairConfirm, PairHello};

        #[derive(Default)]
        pub struct D(Vec<(&'static str, String)>);

        impl D {
            fn put(mut self, n: &'static str, v: Option<String>) -> Self {
                if let Some(v) = v {
                    self.0.push((n, v));
                }
                self
            }
            fn s(self, n: &'static str, v: &str) -> Self {
                self.put(n, (!v.is_empty()).then(|| h(v)))
            }
            fn os(self, n: &'static str, v: &Option<String>) -> Self {
                self.s(n, v.as_deref().unwrap_or(""))
            }
            fn i(self, n: &'static str, v: i64) -> Self {
                self.put(n, (v != 0).then(|| v.to_string()))
            }
            fn b(self, n: &'static str, v: bool) -> Self {
                self.put(n, v.then(|| "true".to_owned()))
            }
            fn raw(self, n: &'static str, v: Option<&RawJson>) -> Self {
                let v = v.filter(|r| !r.as_bytes().is_empty());
                self.put(n, v.map(|r| format!("raw:{}", hex::encode(r.as_bytes()))))
            }
            pub fn end(mut self) -> String {
                self.0.sort_by(|a, b| a.0.cmp(b.0));
                let f: Vec<String> = self.0.iter().map(|(n, v)| format!("{n}={v}")).collect();
                format!("{{{}}}", f.join(" "))
            }
        }

        fn h(s: &str) -> String {
            format!("h:{}", hex::encode(s))
        }

        fn map<T>(m: &BTreeMap<String, T>, f: impl Fn(&T) -> String) -> Option<String> {
            let e: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}:{}", hex::encode(k), f(v)))
                .collect();
            (!m.is_empty()).then(|| format!("{{{}}}", e.join(",")))
        }

        fn list<T>(v: &[T], f: impl Fn(&T) -> String) -> Option<String> {
            let e: Vec<String> = v.iter().map(f).collect();
            (!v.is_empty()).then(|| format!("[{}]", e.join(",")))
        }

        fn hole(r: &HoleRange) -> String {
            D::default().s("od", &r.od).s("do", &r.do_).end()
        }

        fn version(v: &VersionV1) -> String {
            let t = go_time::parse(v.created_at.as_bytes()).unwrap();
            let ca = (t.unix != -62_135_596_800 || t.nanos != 0)
                .then(|| format!("t:{}.{:09}", t.unix, t.nanos));
            D::default()
                .s("version_id", &v.version_id)
                .s("entity", &v.entity)
                .s("entity_id", &v.entity_id)
                .s("node_id", &v.node_id)
                .s("supersedes", &v.supersedes)
                .b("archived", v.archived)
                .raw("payload", Some(&v.payload))
                .put("created_at", ca)
                .i("schema_version", v.schema_version)
                .os("channel", &v.channel)
                .s("potpis", &v.potpis)
                .s("kljuc_autora", &v.kljuc_autora)
                .end()
        }

        pub fn envelope(e: &EnvelopeV1) -> String {
            D::default()
                .s("kind", &e.kind)
                .os("reason", &e.reason)
                .put("kod", e.kod.filter(|k| *k != 0).map(|k| k.to_string()))
                .os("deviceId", &e.device_id)
                .raw("payload", e.payload.as_ref())
                .end()
        }

        /// A message read from text (`read`) or from an envelope's payload (`parse`),
        /// written by `f` as above, or `None` when it is not read.
        pub fn read<T: go_text::GoRead>(
            text: &[u8],
        ) -> impl Fn(fn(&T) -> String) -> Option<String> + '_ {
            move |f| go_text::from_slice::<T>(text).ok().map(|m| f(&m))
        }

        pub fn parse<T: go_text::GoRead>(
            e: &EnvelopeV1,
        ) -> impl Fn(fn(&T) -> String) -> Option<String> + '_ {
            move |f| e.parse_payload::<T>().ok().map(|m| f(&m))
        }

        pub fn frontier(f: &FrontierPayload) -> String {
            D::default()
                .put("frontier", map(&f.frontier, |v| h(v)))
                .put(
                    "wants",
                    f.wants
                        .as_ref()
                        .map(|w| format!("&{}", D::default().b("all", w.all).end())),
                )
                .os("program", &f.program)
                .os("gradnja", &f.gradnja)
                .put("mogucnosti", list(&f.mogucnosti, |v| h(v)))
                .put("vrste", map(&f.vrste, |v| v.to_string()))
                .i("cekaNadogradnju", f.ceka_nadogradnju.unwrap_or(0))
                .put("uloge", list(&f.uloge, |v| h(v)))
                .end()
        }
        pub fn granica(g: &GranicaOdbijenihPayload) -> String {
            D::default().put("granica", map(&g.granica, |v| h(v))).end()
        }
        pub fn rupe(r: &RupePayload) -> String {
            D::default().put("trazim", map(&r.trazim, hole)).end()
        }
        pub fn delta(d: &DeltaPayload) -> String {
            D::default()
                .put("versions", list(&d.versions, version))
                .b("skraceno", d.skraceno)
                .put("tailscale", list(&d.tailscale, |v| h(v)))
                .put("rupe", map(&d.rupe, hole))
                .put("popuna", map(&d.popuna, hole))
                .end()
        }
        pub fn zelje(z: &ZeljePayload) -> String {
            D::default().put("otisci", list(&z.otisci, |v| h(v))).end()
        }
        pub fn sadrzaj(s: &SadrzajPayload) -> String {
            let item = |i: &ContentItemV1| {
                D::default()
                    .s("otisak", &i.otisak)
                    .s("vrsta", &i.vrsta)
                    .s("kanal", &i.kanal)
                    .i("bajtova", i.bajtova)
                    .put(
                        "podaci",
                        (!i.podaci.is_empty()).then(|| format!("b:{}", hex::encode(&i.podaci))),
                    )
                    .end()
            };
            D::default().put("stavke", list(&s.stavke, item)).end()
        }
        pub fn done(d: &DonePayload) -> String {
            D::default().i("applied", d.applied).end()
        }
        pub fn hello(p: &PairHello) -> String {
            D::default()
                .s("protocol", &p.protocol)
                .s("deviceId", &p.device_id)
                .s("name", &p.name)
                .s("version", &p.version)
                .put("meta", map(&p.meta, |v| h(v)))
                .i("sas", p.sas)
                .end()
        }
        pub fn confirm(c: &PairConfirm) -> String {
            D::default()
                .b("approved", c.approved)
                .raw("payload", c.payload.as_ref())
                .end()
        }
    }

    /// Reads `text` as the message `kind` (as the Go probe names them: `fr` frontier, `gr`
    /// granica-odbijenih, `ru` rupe, `d2` delta, `ze` zelje, `sa` sadrzaj, `dn` done, `ph`
    /// pairing hello, `pc` pairing confirmation; `env` the envelope, `e:X` an envelope
    /// whose payload is read as `X`), written as [`dump`] writes it.
    fn go_reading(kind: &str, text: &[u8]) -> String {
        use crate::pairing::{PairConfirm, PairHello};
        macro_rules! by_kind {
            ($kind:expr, $src:ident, $arg:expr) => {
                match $kind {
                    "fr" => dump::$src::<FrontierPayload>($arg)(dump::frontier),
                    "gr" => dump::$src::<GranicaOdbijenihPayload>($arg)(dump::granica),
                    "ru" => dump::$src::<RupePayload>($arg)(dump::rupe),
                    "d2" => dump::$src::<DeltaPayload>($arg)(dump::delta),
                    "ze" => dump::$src::<ZeljePayload>($arg)(dump::zelje),
                    "sa" => dump::$src::<SadrzajPayload>($arg)(dump::sadrzaj),
                    "dn" => dump::$src::<DonePayload>($arg)(dump::done),
                    "ph" => dump::$src::<PairHello>($arg)(dump::hello),
                    "pc" => dump::$src::<PairConfirm>($arg)(dump::confirm),
                    other => panic!("{other}"),
                }
            };
        }
        if let Some(inner) = kind.strip_prefix("e:") {
            let Ok(e) = go_text::from_slice::<EnvelopeV1>(text) else {
                return "GRESKA".into();
            };
            return match by_kind!(inner, parse, &e) {
                Some(m) => format!("OK {} {m}", dump::envelope(&e)),
                None => format!("GRESKA2 {}", dump::envelope(&e)),
            };
        }
        let got = if kind == "env" {
            go_text::from_slice::<EnvelopeV1>(text)
                .ok()
                .map(|e| dump::envelope(&e))
        } else {
            by_kind!(kind, read, text)
        };
        got.map_or_else(|| "GRESKA".to_owned(), |m| format!("OK {m}"))
    }

    /// (point, message, JSON text, what Go reads). The points: 1 the messages read as Go
    /// reads its structs (names in any case, the last repeat, structs, slices and maps
    /// filled as Go fills them, text with U+FFFD); 2 `null` and `{}` in place of a message;
    /// 3 a version payload with bytes that are not UTF-8; 4 `schema_version`; 5 the payload
    /// of a pairing confirmation. Go column: go1.27.1, `json.Unmarshal` into the Go side's
    /// envelope, conversation messages, pairing hello and confirmation (`e:X`: the envelope,
    /// then its payload read into `X` as Go reads it; `GRESKA2` when only that fails),
    /// written as [`dump`] writes it. Rust reads every row as Go does.
    const GO_EDGES: &[(u8, &str, &[u8], &str)] = &[
        (1, "env", br#"{"kind":"done","deviceId":"a"}"#, "OK {deviceId=h:61 kind=h:646f6e65}"),
        (1, "env", br#"{"KIND":"done","DEVICEID":"a","Reason":"r","KOD":5,"PAYLOAD":{}}"#, "OK {deviceId=h:61 kind=h:646f6e65 kod=5 payload=raw:7b7d reason=h:72}"),
        (1, "env", br#"{"kind":"a","Kind":"b"}"#, "OK {kind=h:62}"),
        (1, "env", br#"{"kind":"a","kind":null}"#, "OK {kind=h:61}"),
        (1, "env", b"{\"kind\":\"a\",\"\xe2\x84\xaaind\":\"b\"}", "OK {kind=h:62}"),
        (1, "env", b"{\"kind\":\"a\",\"rea\xc5\xbfon\":\"r\"}", "OK {kind=h:61 reason=h:72}"),
        (1, "env", b"{\"kind\":\"a\",\"k\xc4\xb1nd\":\"b\"}", "OK {kind=h:61}"),
        (1, "env", br#"{"kind":"a","\u006bind":"b"}"#, "OK {kind=h:62}"),
        (1, "env", br#"{"kind":"a","\ud800":"x"}"#, "OK {kind=h:61}"),
        (1, "env", br#"{"kind":"a","reason":"\ud800x"}"#, "OK {kind=h:61 reason=h:efbfbd78}"),
        (1, "env", br#"{"kind":"a","payload":{"a":1},"Payload":[ 1 ]}"#, "OK {kind=h:61 payload=raw:5b2031205d}"),
        (1, "env", br#"{"kind":"a","payload":{"a":1},"payload":null}"#, "OK {kind=h:61 payload=raw:6e756c6c}"),
        (1, "env", br#"{"kind":5}"#, "GRESKA"),
        (1, "env", br#"{"kind":"a","kod":-1}"#, "GRESKA"),
        (1, "env", br#"{"kind":"a","kod":-0}"#, "GRESKA"),
        (1, "env", br#"{"kind":"a","kod":18446744073709551615}"#, "OK {kind=h:61 kod=18446744073709551615}"),
        (1, "env", br#"{"kind":"a","kod":18446744073709551616}"#, "GRESKA"),
        (1, "env", br#"{"kind":"a","kod":1.0}"#, "GRESKA"),
        (1, "env", br#"{"kind":"a","kod":"5"}"#, "GRESKA"),
        (1, "env", br#"{"kind":"a","kod":5,"kod":null}"#, "OK {kind=h:61 kod=5}"),
        (1, "env", br#"[]"#, "GRESKA"),
        (1, "env", br#"["done"]"#, "GRESKA"),
        (1, "fr", br#"{"frontier":{"a":"1"},"frontier":{"b":"2"}}"#, "OK {frontier={61:h:31,62:h:32}}"),
        (1, "fr", br#"{"frontier":{"a":"1"},"FRONTIER":{"a":"3"}}"#, "OK {frontier={61:h:33}}"),
        (1, "fr", br#"{"frontier":{"a":"1"},"frontier":null,"frontier":{"b":"2"}}"#, "OK {frontier={62:h:32}}"),
        (1, "fr", br#"{"frontier":{"a":"1","a":"2"}}"#, "OK {frontier={61:h:32}}"),
        (1, "fr", br#"{"frontier":{"a":"1","A":"2"}}"#, "OK {frontier={41:h:32,61:h:31}}"),
        (1, "fr", br#"{"frontier":{"a":null}}"#, "OK {frontier={61:h:}}"),
        (1, "fr", br#"{"frontier":{"\u0061":"1","a":"2"}}"#, "OK {frontier={61:h:32}}"),
        (1, "fr", br#"{"frontier":{"\ud800":"1","\udc00":"2"}}"#, "OK {frontier={efbfbd:h:32}}"),
        (1, "fr", br#"{"frontier":{"x\ud800y":"1"}}"#, "OK {frontier={78efbfbd79:h:31}}"),
        (1, "fr", br#"{"frontier":{"a":"\ud800"}}"#, "OK {frontier={61:h:efbfbd}}"),
        (1, "fr", br#"{"frontier":{"a":1}}"#, "GRESKA"),
        (1, "fr", br#"{"frontier":{"b":5},"frontier":null}"#, "GRESKA"),
        (1, "fr", br#"{"frontier":{"a":"1"},"frontier":[]}"#, "GRESKA"),
        (1, "fr", br#"{"frontier":{"\u0001":"1"}}"#, "OK {frontier={01:h:31}}"),
        (1, "fr", br#"{"vrste":{"a":-0,"b":-1,"c":9223372036854775807,"d":null}}"#, "OK {vrste={61:0,62:-1,63:9223372036854775807,64:0}}"),
        (1, "fr", br#"{"vrste":{"a":1e2}}"#, "GRESKA"),
        (1, "fr", br#"{"vrste":{"a":9223372036854775808}}"#, "GRESKA"),
        (1, "fr", br#"{"vrste":{"a":1.0}}"#, "GRESKA"),
        (1, "fr", br#"{"cekaNadogradnju":-5}"#, "OK {cekaNadogradnju=-5}"),
        (1, "fr", br#"{"cekaNadogradnju":-0}"#, "OK {}"),
        (1, "fr", br#"{"CEKANADOGRADNJU":2,"cekanadogradnju":null}"#, "OK {cekaNadogradnju=2}"),
        (1, "fr", br#"{"mogucnosti":["a",null,"b"]}"#, "OK {mogucnosti=[h:61,h:,h:62]}"),
        (1, "fr", b"{\"Mogucnosti\":[\"a\",\"b\"],\"mogucno\xc5\xbfti\":[null,\"c\"]}", "OK {mogucnosti=[h:61,h:63]}"),
        (1, "fr", br#"{"mogucnosti":["a","b"],"mogucnosti":["c"],"mogucnosti":[null,null]}"#, "OK {mogucnosti=[h:63,h:62]}"),
        (1, "fr", br#"{"mogucnosti":["a","b"],"mogucnosti":[],"mogucnosti":[null,null]}"#, "OK {mogucnosti=[h:,h:]}"),
        (1, "fr", br#"{"mogucnosti":"a"}"#, "GRESKA"),
        (1, "fr", br#"{"mogucnosti":["a",5]}"#, "GRESKA"),
        (1, "fr", br#"{"uloge":["a"],"Uloge":null}"#, "OK {}"),
        (1, "fr", br#"{"uloge":5}"#, "GRESKA"),
        (1, "fr", br#"{"wants":{"all":true},"wants":{"rules":[{"id":1}]}}"#, "OK {wants=&{all=true}}"),
        (1, "fr", br#"{"wants":{"all":true},"wants":null}"#, "OK {}"),
        (1, "fr", br#"{"wants":{"rules":5}}"#, "GRESKA"),
        (1, "fr", br#"{"wants":{"rules":[{"area_id":"x"}]}}"#, "GRESKA"),
        (1, "fr", br#"{"wants":{"rules":[{"id":-0,"year_to":-1}]}}"#, "OK {wants=&{}}"),
        (1, "fr", br#"{"wants":{"channels":5}}"#, "OK {wants=&{}}"),
        (1, "fr", br#"{"wants":[true]}"#, "GRESKA"),
        (1, "fr", br#"{"karta":{"otisak":"x"},"karta":{"svih":3}}"#, "OK {}"),
        (1, "fr", br#"{"karta":5}"#, "GRESKA"),
        (1, "fr", br#"{"karta":{"slozena":1}}"#, "GRESKA"),
        (1, "fr", br#"{"tailscale":5,"otisak":5}"#, "OK {}"),
        (1, "fr", br#"{"program":"a","PROGRAM":null}"#, "OK {program=h:61}"),
        (1, "fr", br#"null"#, "OK {}"),
        (1, "fr", br#"{}"#, "OK {}"),
        (1, "fr", br#"[]"#, "GRESKA"),
        (1, "fr", br#"[{}]"#, "GRESKA"),
        (1, "gr", br#"{"granica":{"a":"1"},"GRANICA":{"b":"2"}}"#, "OK {granica={61:h:31,62:h:32}}"),
        (1, "gr", br#"{"granica":[]}"#, "GRESKA"),
        (1, "ru", br#"{"trazim":{"k":{"od":"a"}},"trazim":{"k":{"do":"b"}}}"#, "OK {trazim={6b:{do=h:62}}}"),
        (1, "ru", br#"{"trazim":{"k":{"od":"a","do":"x"},"k":{"do":"b"}}}"#, "OK {trazim={6b:{do=h:62}}}"),
        (1, "ru", br#"{"trazim":{"k":null}}"#, "OK {trazim={6b:{}}}"),
        (1, "ru", br#"{"trazim":{"k":{"OD":"a","Do":"b","od":null}}}"#, "OK {trazim={6b:{do=h:62 od=h:61}}}"),
        (1, "ru", br#"{"trazim":{"k":[]}}"#, "GRESKA"),
        (1, "ru", br#"{"trazim":{"\ud800":{"od":"a"}},"TRAZIM":{"\udc00":{"do":"b"}}}"#, "OK {trazim={efbfbd:{do=h:62}}}"),
        (1, "ru", br#"{"trazim":{"k":{"od":5}},"trazim":null}"#, "GRESKA"),
        (1, "d2", br#"{"versions":[{"version_id":"a"}],"versions":[{"entity":"e"}]}"#, "OK {versions=[{entity=h:65 payload=raw:6e756c6c version_id=h:61}]}"),
        (1, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1},null]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=1 version_id=h:76},{payload=raw:6e756c6c}]}"),
        (1, "d2", br#"{"tailscale":["a"],"TAILSCALE":["b","c"]}"#, "OK {tailscale=[h:62,h:63]}"),
        (1, "d2", br#"{"tailscale":5}"#, "GRESKA"),
        (1, "d2", br#"{"rupe":{"k":{"od":"a"}},"rupe":{"j":{"do":"b"}},"popuna":{"k":null}}"#, "OK {popuna={6b:{}} rupe={6a:{do=h:62},6b:{od=h:61}}}"),
        (1, "d2", br#"{"skraceno":true,"skraceno":null}"#, "OK {skraceno=true}"),
        (1, "d2", br#"{"versions":[{"payload":{"a":1}}],"versions":[{"payload":null}]}"#, "OK {versions=[{payload=raw:6e756c6c}]}"),
        (1, "d2", br#"{"versions":[[]]}"#, "GRESKA"),
        (1, "ze", br#"{"otisci":["a"],"otisci":["b","c"]}"#, "OK {otisci=[h:62,h:63]}"),
        (1, "ze", br#"{"otisci":[null,"x"]}"#, "OK {otisci=[h:,h:78]}"),
        (1, "ze", br#"{"otisci":["a",5]}"#, "GRESKA"),
        (1, "sa", br#"{"stavke":[{"otisak":"o","vrsta":"v","bajtova":-1,"podaci":"AA=="}]}"#, "OK {stavke=[{bajtova=-1 otisak=h:6f podaci=b:00 vrsta=h:76}]}"),
        (1, "sa", br#"{"stavke":[{"podaci":"!!"}]}"#, "GRESKA"),
        (1, "sa", br#"{"stavke":[{"podaci":"AA\r\n=="}]}"#, "OK {stavke=[{podaci=b:00}]}"),
        (1, "sa", br#"{"stavke":[{"podaci":[1,null,255]}]}"#, "OK {stavke=[{podaci=b:0100ff}]}"),
        (1, "sa", br#"{"stavke":[{"podaci":"AA"}]}"#, "GRESKA"),
        (1, "sa", br#"{"stavke":[{"bajtova":18446744073709551615}]}"#, "GRESKA"),
        (1, "sa", br#"{"stavke":[{"otisak":"a"}],"stavke":[{"vrsta":"b"}]}"#, "OK {stavke=[{otisak=h:61 vrsta=h:62}]}"),
        (1, "sa", br#"{"stavke":[{"KANAL":"k","kanal":null}]}"#, "OK {stavke=[{kanal=h:6b}]}"),
        (1, "sa", br#"{"stavke":[null]}"#, "OK {stavke=[{}]}"),
        (1, "sa", br#"{"stavke":[["o"]]}"#, "GRESKA"),
        (1, "ph", br#"{"Protocol":"p","DEVICEID":"d","NAME":"n","Version":"v","SAS":2}"#, "OK {deviceId=h:64 name=h:6e protocol=h:70 sas=2 version=h:76}"),
        (1, "ph", br#"{"meta":{"a":"1"},"meta":{"b":"2"}}"#, "OK {meta={61:h:31,62:h:32}}"),
        (1, "ph", br#"{"meta":{"\ud800":"1"}}"#, "OK {meta={efbfbd:h:31}}"),
        (1, "ph", br#"{"meta":{"a":null}}"#, "OK {meta={61:h:}}"),
        (1, "ph", br#"{"meta":{"a":1}}"#, "GRESKA"),
        (1, "ph", br#"{"meta":[]}"#, "GRESKA"),
        (1, "ph", b"{\"\xc5\xbfa\xc5\xbf\":3}", "OK {sas=3}"),
        (1, "ph", br#"{"name":"\ud800"}"#, "OK {name=h:efbfbd}"),
        (1, "ph", br#"[]"#, "GRESKA"),
        (1, "ph", br#"["p","d","n","v"]"#, "GRESKA"),
        (1, "pc", br#"{"approved":true,"APPROVED":null}"#, "OK {approved=true}"),
        (1, "pc", br#"{"Approved":true,"payload":{"a":1},"PAYLOAD":[2]}"#, "OK {approved=true payload=raw:5b325d}"),
        (1, "pc", br#"{"approved":1}"#, "GRESKA"),
        (1, "pc", br#"[true]"#, "GRESKA"),
        (1, "fr", b"{\"frontier\":{\"a\xffb\":\"1\",\"a\xfeb\":\"2\"}}", "OK {frontier={61efbfbd62:h:32}}"),
        (1, "fr", b"{\"frontier\":{\"a\":\"\xe2\x80\"}}", "OK {frontier={61:h:efbfbdefbfbd}}"),
        (1, "ph", b"{\"meta\":{\"\xff\":\"x\"}}", "OK {meta={efbfbd:h:78}}"),
        (1, "env", b"{\"kind\":\"\xffa\"}", "OK {kind=h:efbfbd61}"),
        (2, "env", br#"null"#, "OK {}"),
        (2, "env", br#"{}"#, "OK {}"),
        (2, "dn", br#"null"#, "OK {}"),
        (2, "dn", br#"{}"#, "OK {}"),
        (2, "ph", br#"null"#, "OK {}"),
        (2, "ph", br#"{}"#, "OK {}"),
        (2, "pc", br#"null"#, "OK {}"),
        (2, "pc", br#"{}"#, "OK {}"),
        (2, "e:dn", br#"{"kind":"done"}"#, "OK {kind=h:646f6e65} {}"),
        (2, "e:dn", br#"{"kind":"done","payload":null}"#, "OK {kind=h:646f6e65 payload=raw:6e756c6c} {}"),
        (2, "e:dn", br#"{"kind":"done","payload":{}}"#, "OK {kind=h:646f6e65 payload=raw:7b7d} {}"),
        (2, "e:dn", br#"{"kind":"done","payload":[]}"#, "GRESKA2 {kind=h:646f6e65 payload=raw:5b5d}"),
        (2, "e:dn", br#"{"kind":"done","payload":5}"#, "GRESKA2 {kind=h:646f6e65 payload=raw:35}"),
        (2, "e:fr", br#"{"kind":"frontier"}"#, "OK {kind=h:66726f6e74696572} {}"),
        (2, "e:d2", br#"{"kind":"delta","payload":null}"#, "OK {kind=h:64656c7461 payload=raw:6e756c6c} {}"),
        (2, "e:pc", br#"{"kind":"x"}"#, "OK {kind=h:78} {}"),
        (2, "e:ph", br#"{"payload":{}}"#, "OK {payload=raw:7b7d} {}"),
        (2, "dn", br#"{"applied":-1}"#, "OK {applied=-1}"),
        (2, "dn", br#"{"applied":-0}"#, "OK {}"),
        (2, "dn", br#"{"applied":9223372036854775808}"#, "GRESKA"),
        (2, "dn", br#"{"APPLIED":3,"applied":null}"#, "OK {applied=3}"),
        (2, "ph", br#"{"sas":-1}"#, "OK {sas=-1}"),
        (2, "ph", br#"{"sas":4294967296}"#, "OK {sas=4294967296}"),
        (2, "ph", br#"{"sas":9223372036854775807}"#, "OK {sas=9223372036854775807}"),
        (2, "ph", br#"{"sas":9223372036854775808}"#, "GRESKA"),
        (2, "ph", br#"{"sas":-0}"#, "OK {}"),
        (2, "ph", br#"{"sas":1.0}"#, "GRESKA"),
        (2, "pc", br#"{"approved":null}"#, "OK {}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:22ff22 schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a22ff227d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:22ff22 schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"a\" : \"\xe2\x80\" , \"b\":[1, 2] }}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:7b226122203a2022e28022202c202262223a5b312c20325d207d schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"a\" : \"\xe2\x80\" , \"b\":[1, 2] }}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a7b226122203a2022e28022202c202262223a5b312c20325d207d7d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:7b226122203a2022e28022202c202262223a5b312c20325d207d schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xed\xa0\x80\"}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:22eda08022 schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xed\xa0\x80\"}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a22eda080227d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:22eda08022 schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xc0\xaf<&>\xe2\x80\xa8\"}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:22c0af3c263ee280a822 schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xc0\xaf<&>\xe2\x80\xa8\"}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a22c0af3c263ee280a8227d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:22c0af3c263ee280a822 schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"x\":\"\xf4\x90\x80\x80\",\"y\":\"\xee\x80\x80ff\"}}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:7b2278223a22f4908080222c2279223a22ee80806666227d schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"x\":\"\xf4\x90\x80\x80\",\"y\":\"\xee\x80\x80ff\"}}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a7b2278223a22f4908080222c2279223a22ee80806666227d7d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:7b2278223a22f4908080222c2279223a22ee80806666227d schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\"}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:22ee808022 schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\"}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a22ee8080227d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:22ee808022 schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\xff\"}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:22ee8080ff22 schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\xff\"}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a22ee8080ff227d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:22ee8080ff22 schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":[\"\\ud800\",\"\xff\"]}]}", "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:5b225c7564383030222c22ff225d schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":[\"\\ud800\",\"\xff\"]}]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a5b225c7564383030222c22ff225d7d5d7d} {versions=[{created_at=t:1760000000.000000000 payload=raw:5b225c7564383030222c22ff225d schema_version=1 version_id=h:76}]}"),
        (3, "e:d2", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}],\"tailscale\":[\"\xff\"]}}", "OK {kind=h:64656c7461 payload=raw:7b2276657273696f6e73223a5b7b2276657273696f6e5f6964223a2276222c22637265617465645f6174223a22323032352d31302d30395430383a35333a32305a222c22736368656d615f76657273696f6e223a312c227061796c6f6164223a22ff227d5d2c227461696c7363616c65223a5b22ff225d7d} {tailscale=[h:efbfbd] versions=[{created_at=t:1760000000.000000000 payload=raw:22ff22 schema_version=1 version_id=h:76}]}"),
        (3, "d2", b"{\"versions\":[{\"payload\":\"\xff\",\"PAYLOAD\":\"\xfe\"}]}", "OK {versions=[{payload=raw:22fe22}]}"),
        (3, "d2", b"{\"versions\":[{\"payload\":\"\xff\",\"entity\":\"\xff\"}]}", "OK {versions=[{entity=h:efbfbd payload=raw:22ff22}]}"),
        (3, "d2", b"{\"versions\":[{\"payload\":\xff}]}", "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":-1}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=-1 version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":-0}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":0}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":1}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=1 version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":2147483648}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=2147483648 version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":4294967296}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=4294967296 version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":9223372036854775807}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=9223372036854775807 version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":9223372036854775808}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":-9223372036854775808}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=-9223372036854775808 version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":-9223372036854775809}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":1e2}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":1E2}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":1.0}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":-0.0}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":0.5}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":"1"}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":null}]}"#, "OK {versions=[{created_at=t:1760000000.000000000 payload=raw:6e756c6c schema_version=1 version_id=h:76}]}"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":true}]}"#, "GRESKA"),
        (4, "d2", br#"{"versions":[{"version_id":"v","created_at":"2025-10-09T08:53:20Z","schema_version":1,"schema_version":[1]}]}"#, "GRESKA"),
        (5, "pc", br#"{"approved":true,"payload":{"a" : 1}}"#, "OK {approved=true payload=raw:7b226122203a20317d}"),
        (5, "pc", br#"{"approved":true,"payload":"\ud800"}"#, "OK {approved=true payload=raw:225c756438303022}"),
        (5, "pc", br#"{"approved":true,"payload":{"a":"\udc00\ud800"}}"#, "OK {approved=true payload=raw:7b2261223a225c75646330305c7564383030227d}"),
        (5, "pc", br#"{"approved":true,"payload":null}"#, "OK {approved=true payload=raw:6e756c6c}"),
        (5, "pc", br#"{"approved":true,"payload":[ ]}"#, "OK {approved=true payload=raw:5b205d}"),
        (5, "pc", br#"{"approved":true,"payload":1e400}"#, "OK {approved=true payload=raw:3165343030}"),
        (5, "pc", br#"{"approved":true,"payload":-0}"#, "OK {approved=true payload=raw:2d30}"),
        (5, "pc", br#"{"approved":true,"payload":{"a":1,"a":2}}"#, "OK {approved=true payload=raw:7b2261223a312c2261223a327d}"),
        (5, "pc", br#"{"approved":true,"payload":"<&>"}"#, "OK {approved=true payload=raw:223c263e22}"),
        (5, "pc", b"{\"approved\":true,\"payload\":\"\xff\xe2\x80\"}", "OK {approved=true payload=raw:22ffe28022}"),
        (5, "pc", br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#, "OK {approved=true payload=raw:5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d}"),
        (5, "pc", br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#, "OK {approved=true payload=raw:5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d}"),
        (5, "pc", br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#, "OK {approved=true payload=raw:5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d}"),
        // The character Rust marks bytes with (U+E000), as it is and escaped, next to bytes
        // that are not UTF-8: read as Go reads it, in keys and values alike.
        (3, "ru", b"{\"trazim\":{\"\xee\x80\x80ff\":{\"od\":\"\xff\"}},\"trazim\":{\"\\ue000ff\":{\"do\":\"x\"}}}", "OK {trazim={ee80806666:{do=h:78}}}"),
        (3, "ru", b"{\"trazim\":{\"\xee\x80\x80ff\":{\"od\":\"\xee\x80\x80\"}},\"trazim\":{\"\xee\x80\x80\xee\x80\x80\":{\"do\":\"\xfe\"}}}", "OK {trazim={ee80806666:{od=h:ee8080},ee8080ee8080:{do=h:efbfbd}}}"),
        (3, "fr", b"{\"frontier\":{\"\xee\x80\x80ff\":\"\xff\",\"\\ue000ff\":\"\xee\x80\x800a\"},\"FRONTIER\":{\"x\xff\":\"\\uE000\"}}", "OK {frontier={78efbfbd:h:ee8080,ee80806666:h:ee80803061}}"),
        (3, "fr", b"{\"wants\":{\"all\":true},\"wants\":{\"\xee\x80\x80ff\":1,\"\xff\":2}}", "OK {wants=&{all=true}}"),
        (3, "d2", b"{\"versions\":[{\"payload\":\"\xee\x80\x80ff\xff\",\"entity\":\"\xee\x80\x80ff\"}],\"versions\":[{\"\xee\x80\x80\":\"\xff\"}]}", "OK {versions=[{entity=h:ee80806666 payload=raw:22ee80806666ff22}]}"),
        (3, "e:d2", b"{\"kind\":\"\xee\x80\x80ff\xff\",\"payload\":{\"versions\":[{\"payload\":[\"\xee\x80\x80ff\",\"\xfe\xee\x80\x80\xee\x80\x80\"],\"node_id\":\"\xee\x80\x80\"}],\"rupe\":{\"\xee\x80\x80ff\":{\"od\":\"\xee\x80\x80\"}}}}", "OK {kind=h:ee80806666efbfbd payload=raw:7b2276657273696f6e73223a5b7b227061796c6f6164223a5b22ee80806666222c22feee8080ee8080225d2c226e6f64655f6964223a22ee8080227d5d2c2272757065223a7b22ee80806666223a7b226f64223a22ee8080227d7d7d} {rupe={ee80806666:{od=h:ee8080}} versions=[{node_id=h:ee8080 payload=raw:5b22ee80806666222c22feee8080ee8080225d}]}"),
        (3, "pc", b"{\"approved\":true,\"payload\":{\"\xee\x80\x80ff\":\"\xff\xee\x80\x80\"}}", "OK {approved=true payload=raw:7b22ee80806666223a22ffee8080227d}"),
        (3, "ph", b"{\"meta\":{\"\xee\x80\x80ff\":\"\xee\x80\x80\",\"\\ue000ff\":\"\xff\"},\"name\":\"\xee\x80\x800a\xff\"}", "OK {meta={ee80806666:h:efbfbd} name=h:ee80803061efbfbd}"),
        // A `[]byte` given more than once is read into the bytes it holds, as Go reads it.
        (1, "sa", b"{\"stavke\":[{\"podaci\":\"QUJD\"}],\"stavke\":[{\"podaci\":[null,null]}]}", "OK {stavke=[{podaci=b:4142}]}"),
        (1, "sa", b"{\"stavke\":[{\"podaci\":\"QUJD\",\"podaci\":[null]}]}", "OK {stavke=[{podaci=b:41}]}"),
        (1, "sa", b"{\"stavke\":[{\"podaci\":\"QUJD\",\"podaci\":\"\",\"podaci\":[null,null]}]}", "OK {stavke=[{podaci=b:4142}]}"),
        (1, "sa", b"{\"stavke\":[{\"podaci\":\"QUJD\",\"podaci\":[],\"podaci\":[null,null]}]}", "OK {stavke=[{podaci=b:0000}]}"),
        (1, "sa", b"{\"stavke\":[{\"podaci\":[1,2,3,4,5,6,7,8,9,10],\"podaci\":\"AAAAAAAA\\n\\n\\n\\n\",\"podaci\":[null,null,null,null,null,null,null,null,null,null]}]}", "OK {stavke=[{podaci=b:0000000000000000090a}]}"),
        (1, "sa", b"{\"stavke\":[{\"podaci\":[1,2,3,4,5,6,7,8,9,10],\"podaci\":\"AAAAAAAA\",\"podaci\":[null,null,null,null,null,null,null,null,null,null]}]}", "OK {stavke=[{podaci=b:0000000000000708090a}]}"),
        (1, "sa", b"{\"stavke\":[{\"podaci\":\"QUJD\",\"podaci\":\"QQ\"}]}", "GRESKA"),
        // The characters Rust marks bytes with (U+E000 to U+E0FF), as they are and escaped,
        // next to bytes that are not UTF-8: read as Go reads them, in keys and values alike.
        (3, "ru", b"{\"trazim\":{\"\xee\x83\xbf\":{\"od\":\"\xff\"}},\"trazim\":{\"\\ue0ff\":{\"do\":\"x\"}}}", "OK {trazim={ee83bf:{do=h:78}}}"),
        (3, "ru", b"{\"trazim\":{\"\xee\x80\x80\xee\x83\xbf\":{\"od\":\"\xee\x82\x80\"}},\"trazim\":{\"\xff\":{\"do\":\"\xee\x83\xbf\xfe\"}}}", "OK {trazim={ee8080ee83bf:{od=h:ee8280},efbfbd:{do=h:ee83bfefbfbd}}}"),
        (3, "fr", b"{\"frontier\":{\"\xee\x82\x80\":\"\xff\",\"\xff\":\"\xee\x83\xbf\",\"\\ue080\":\"\xee\x81\xbf\xee\x84\x80\"}}", "OK {frontier={ee8280:h:ee81bfee8480,efbfbd:h:ee83bf}}"),
        (3, "fr", b"{\"frontier\":{\"\xff\":\"a\"},\"frontier\":{\"\\ufffd\":\"b\",\"\xee\x83\xbf\xff\":\"c\"}}", "OK {frontier={ee83bfefbfbd:h:63,efbfbd:h:62}}"),
        (3, "d2", b"{\"versions\":[{\"payload\":\"\xee\x83\xbf\xff\xee\x82\x80\",\"entity\":\"\xee\x80\x80\xee\x83\xbf\xfe\"}],\"versions\":[{\"\xee\x83\xbf\":\"\xff\"}]}", "OK {versions=[{entity=h:ee8080ee83bfefbfbd payload=raw:22ee83bfffee828022}]}"),
        (3, "e:d2", b"{\"kind\":\"\xee\x83\xbf\xff\",\"payload\":{\"versions\":[{\"payload\":[\"\xee\x82\x80\",\"\xfe\xee\x80\x80\xee\x83\xbf\"],\"node_id\":\"\xee\x83\xbf\"}],\"rupe\":{\"\xee\x83\xbf\":{\"od\":\"\xee\x82\x80\"}}}}", "OK {kind=h:ee83bfefbfbd payload=raw:7b2276657273696f6e73223a5b7b227061796c6f6164223a5b22ee8280222c22feee8080ee83bf225d2c226e6f64655f6964223a22ee83bf227d5d2c2272757065223a7b22ee83bf223a7b226f64223a22ee8280227d7d7d} {rupe={ee83bf:{od=h:ee8280}} versions=[{node_id=h:ee83bf payload=raw:5b22ee8280222c22feee8080ee83bf225d}]}"),
        (3, "pc", b"{\"approved\":true,\"payload\":{\"\xee\x83\xbf\":\"\xff\xee\x82\x80\",\"\\ue0ff\":[\"\xee\x80\x80\"]}}", "OK {approved=true payload=raw:7b22ee83bf223a22ffee8280222c225c7565306666223a5b22ee8080225d7d}"),
        (3, "ph", b"{\"meta\":{\"\xee\x83\xbf\":\"\xee\x82\x80\",\"\\ue0ff\":\"\xff\"},\"name\":\"\xee\x80\x80\xee\x83\xbf\xff\xee\x81\xbf\"}", "OK {meta={ee83bf:h:efbfbd} name=h:ee8080ee83bfefbfbdee81bf}"),
        (3, "sa", b"{\"stavke\":[{\"otisak\":\"\xee\x83\xbf\xff\",\"vrsta\":\"\xee\x82\x80\xee\x82\x80\"}]}", "OK {stavke=[{otisak=h:ee83bfefbfbd vrsta=h:ee8280ee8280}]}"),
        (3, "env", b"{\"kind\":\"delta\",\"payload\":\"\xee\x83\xbf\xff\",\"reason\":\"\xee\x82\x80\"}", "OK {kind=h:64656c7461 payload=raw:22ee83bfff22 reason=h:ee8280}"),
    ];

    #[test]
    fn conversation_and_pairing_messages_read_as_in_go() {
        for (point, kind, text, go) in GO_EDGES {
            assert_eq!(
                go_reading(kind, text),
                *go,
                "{point} {kind} {}",
                String::from_utf8_lossy(text)
            );
        }
    }

    /// (message, JSON text, what Go's `json.Marshal` writes after reading it, or
    /// `MARSHALERR`). Go column: go1.27.1; a raw value (a version's payload, a
    /// confirmation's payload) is written compact, with `<`, `>`, `&`, U+2028 and U+2029
    /// escaped and every other byte as it came, bytes that are not UTF-8 too. A version's
    /// time is written as Go writes it, and an empty channel not at all.
    const GO_WRITES: &[(&str, &[u8], &[u8])] = &[
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xff\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}]}}"),
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"a\" : \"\xe2\x80\" , \"b\":[1, 2] }}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":{\"a\":\"\xe2\x80\",\"b\":[1,2]},\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"a\" : \"\xe2\x80\" , \"b\":[1, 2] }}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"a\":\"\xe2\x80\",\"b\":[1,2]}}]}}"),
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xed\xa0\x80\"}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xed\xa0\x80\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xed\xa0\x80\"}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xed\xa0\x80\"}]}}"),
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xc0\xaf<&>\xe2\x80\xa8\"}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xc0\xaf\\u003c\\u0026\\u003e\\u2028\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xc0\xaf<&>\xe2\x80\xa8\"}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xc0\xaf\\u003c\\u0026\\u003e\\u2028\"}]}}"),
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"x\":\"\xf4\x90\x80\x80\",\"y\":\"\xee\x80\x80ff\"}}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":{\"x\":\"\xf4\x90\x80\x80\",\"y\":\"\xee\x80\x80ff\"},\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"x\":\"\xf4\x90\x80\x80\",\"y\":\"\xee\x80\x80ff\"}}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":{\"x\":\"\xf4\x90\x80\x80\",\"y\":\"\xee\x80\x80ff\"}}]}}"),
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\"}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xee\x80\x80\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\"}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\"}]}}"),
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\xff\"}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xee\x80\x80\xff\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\xff\"}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xee\x80\x80\xff\"}]}}"),
        ("d2", b"{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":[\"\\ud800\",\"\xff\"]}]}", b"{\"versions\":[{\"version_id\":\"v\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":[\"\\ud800\",\"\xff\"],\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1}]}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":[\"\\ud800\",\"\xff\"]}]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":[\"\\ud800\",\"\xff\"]}]}}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}],\"tailscale\":[\"\xff\"]}}", b"{\"kind\":\"delta\",\"payload\":{\"versions\":[{\"version_id\":\"v\",\"created_at\":\"2025-10-09T08:53:20Z\",\"schema_version\":1,\"payload\":\"\xff\"}],\"tailscale\":[\"\xff\"]}}"),
        ("d2", b"{\"versions\":[{\"payload\":\"\xff\",\"PAYLOAD\":\"\xfe\"}]}", b"{\"versions\":[{\"version_id\":\"\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xfe\",\"created_at\":\"0001-01-01T00:00:00Z\",\"schema_version\":0}]}"),
        ("d2", b"{\"versions\":[{\"payload\":\"\xff\",\"entity\":\"\xff\"}]}", b"{\"versions\":[{\"version_id\":\"\",\"entity\":\"\xef\xbf\xbd\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xff\",\"created_at\":\"0001-01-01T00:00:00Z\",\"schema_version\":0}]}"),
        ("d2", b"{\"versions\":[{\"payload\":\xff}]}", b"GRESKA"),
        ("pc", br#"{"approved":true,"payload":{"a" : 1}}"#, br#"{"approved":true,"payload":{"a":1}}"#),
        ("pc", br#"{"approved":true,"payload":"\ud800"}"#, br#"{"approved":true,"payload":"\ud800"}"#),
        ("pc", br#"{"approved":true,"payload":{"a":"\udc00\ud800"}}"#, br#"{"approved":true,"payload":{"a":"\udc00\ud800"}}"#),
        ("pc", br#"{"approved":true,"payload":null}"#, br#"{"approved":true,"payload":null}"#),
        ("pc", br#"{"approved":true,"payload":[ ]}"#, br#"{"approved":true,"payload":[]}"#),
        ("pc", br#"{"approved":true,"payload":1e400}"#, br#"{"approved":true,"payload":1e400}"#),
        ("pc", br#"{"approved":true,"payload":-0}"#, br#"{"approved":true,"payload":-0}"#),
        ("pc", br#"{"approved":true,"payload":{"a":1,"a":2}}"#, br#"{"approved":true,"payload":{"a":1,"a":2}}"#),
        ("pc", br#"{"approved":true,"payload":"<&>"}"#, br#"{"approved":true,"payload":"\u003c\u0026\u003e"}"#),
        ("pc", b"{\"approved\":true,\"payload\":\"\xff\xe2\x80\"}", b"{\"approved\":true,\"payload\":\"\xff\xe2\x80\"}"),
        ("pc", br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#, br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#),
        ("pc", br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#, br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#),
        ("pc", br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#, br#"{"approved":true,"payload":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}"#),
        ("sa", b"{\"stavke\":[{\"podaci\":\"QUJD\",\"podaci\":[null]}]}", b"{\"stavke\":[{\"otisak\":\"\",\"vrsta\":\"\",\"bajtova\":0,\"podaci\":\"QQ==\"}]}"),
        ("sa", b"{\"stavke\":[{\"podaci\":[1,2,3],\"podaci\":\"AA==\",\"podaci\":[null,null,null,null]}]}", b"{\"stavke\":[{\"otisak\":\"\",\"vrsta\":\"\",\"bajtova\":0,\"podaci\":\"AAIDAA==\"}]}"),
        ("d2", b"{\"versions\":[{\"created_at\":\"2026-01-01T00:00:00.500+00:00\",\"channel\":\"\"}]}", b"{\"versions\":[{\"version_id\":\"\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":null,\"created_at\":\"2026-01-01T00:00:00.5Z\",\"schema_version\":0}]}"),
        ("d2", b"{\"versions\":[{\"created_at\":\"2026-01-01T00:00:00+24:00\"}]}", b"MARSHALERR"),
        ("d2", b"{\"versions\":[{\"created_at\":\"2026-01-01T00:00:00,1234567891-00:00\",\"channel\":\"k\"}]}", b"{\"versions\":[{\"version_id\":\"\",\"entity\":\"\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":null,\"created_at\":\"2026-01-01T00:00:00.123456789Z\",\"schema_version\":0,\"channel\":\"k\"}]}"),
        ("d2", b"{\"versions\":[{\"payload\":\"\xee\x83\xbf\xff\xee\x82\x80\",\"entity\":\"\xee\x80\x80\xee\x83\xbf\xfe\"}],\"versions\":[{\"\xee\x83\xbf\":\"\xff\"}]}", b"{\"versions\":[{\"version_id\":\"\",\"entity\":\"\xee\x80\x80\xee\x83\xbf\xef\xbf\xbd\",\"entity_id\":\"\",\"node_id\":\"\",\"supersedes\":\"\",\"archived\":false,\"payload\":\"\xee\x83\xbf\xff\xee\x82\x80\",\"created_at\":\"0001-01-01T00:00:00Z\",\"schema_version\":0}]}"),
        ("pc", b"{\"approved\":true,\"payload\":{\"\xee\x83\xbf\":\"\xff\xee\x82\x80\",\"\\ue0ff\":[\"\xee\x80\x80\"]}}", b"{\"approved\":true,\"payload\":{\"\xee\x83\xbf\":\"\xff\xee\x82\x80\",\"\\ue0ff\":[\"\xee\x80\x80\"]}}"),
        ("env", b"{\"kind\":\"delta\",\"payload\":\"\xee\x83\xbf\xff\",\"reason\":\"\xee\x82\x80\"}", b"{\"kind\":\"delta\",\"reason\":\"\xee\x82\x80\",\"payload\":\"\xee\x83\xbf\xff\"}"),
    ];

    #[test]
    fn raw_values_are_written_as_go_writes_them() {
        use crate::pairing::PairConfirm;
        fn write<T: go_text::GoRead + Serialize>(text: &[u8]) -> Vec<u8> {
            go_text::from_slice::<T>(text).map_or_else(
                |_| b"GRESKA".to_vec(),
                |m| to_go_json_vec(&m).unwrap_or_else(|_| b"MARSHALERR".to_vec()),
            )
        }
        for (kind, text, go) in GO_WRITES {
            let got = match *kind {
                "d2" => write::<DeltaPayload>(text),
                "env" => write::<EnvelopeV1>(text),
                "sa" => write::<SadrzajPayload>(text),
                _ => write::<PairConfirm>(text),
            };
            assert_eq!(got, *go, "{kind} {}", String::from_utf8_lossy(text));
        }
    }

    /// The payload of a pairing confirmation is kept raw at any depth Go reads: the
    /// confirmation is one level, so a payload of 9 999 levels is read and one of 10 000 is
    /// not (go1.27.1), arrays or objects alike. A `serde_json::Value` would stop at 128.
    #[test]
    fn confirmation_payload_is_kept_to_the_depth_go_reads() {
        use crate::pairing::PairConfirm;
        for (n, go) in [
            (127, true),
            (128, true),
            (129, true),
            (9_998, true),
            (9_999, true),
            (10_000, false),
        ] {
            for payload in [
                format!("{}{}", "[".repeat(n), "]".repeat(n)),
                format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n)),
            ] {
                let text = format!("{{\"approved\":true,\"payload\":{payload}}}");
                let got = go_text::from_slice::<PairConfirm>(text.as_bytes());
                assert_eq!(got.is_ok(), go, "{n}");
                if let Ok(c) = got {
                    assert_eq!(c.payload.unwrap().as_bytes(), payload.as_bytes());
                }
            }
        }
    }
}
