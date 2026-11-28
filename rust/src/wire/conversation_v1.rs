//! Version 1 line-delimited JSON conversation codec and message types (`docs/PROTOKOL.md`).
//!
//! This module provides only the wire codec and message structs verified against
//! `vektori/vektori-razgovora.json`; conversation session logic is kept out until
//! the general ledger abstraction is designed.

use crate::wire::go_json::to_go_json_vec;
use crate::wire::go_object::{Field, Kind, Schema, go_struct, object_only};
use crate::wire::{go_text, go_time};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
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

/// Deserializes JSON `null` as `T::default()` for collections in Go-compatible v1 payloads.
pub fn null_as_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Option::<T>::deserialize(de).map(|opt| opt.unwrap_or_default())
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// Wire envelope shared across conversation versions. `odbijeno` carries no `payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct EnvelopeV1 {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kod: Option<u64>,
    #[serde(rename = "deviceId", default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Box<RawValue>>,
}

impl EnvelopeV1 {
    pub fn with_payload<T: Serialize>(
        kind: &str,
        device_id: &str,
        payload: &T,
    ) -> Result<Self, ConversationV1Error> {
        let raw = serde_json::value::to_raw_value(payload)
            .map_err(|e| ConversationV1Error::Json(e.to_string()))?;
        Ok(Self {
            kind: kind.to_owned(),
            device_id: Some(device_id.to_owned()),
            payload: Some(raw),
            reason: None,
            kod: None,
        })
    }

    pub fn parse_payload<T: DeserializeOwned>(&self) -> Result<T, ConversationV1Error> {
        let Some(ref raw) = self.payload else {
            return Err(ConversationV1Error::Json("missing payload".to_owned()));
        };
        // Go reads the payload as a text of its own, so its depth counts from its top.
        go_text::check_depth(raw.get(), 0).map_err(ConversationV1Error::Json)?;
        serde_json::from_str(raw.get()).map_err(|e| ConversationV1Error::Json(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct WantsSpec {
    #[serde(default, skip_serializing_if = "is_false")]
    pub all: bool,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub channels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct FrontierPayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub frontier: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wants: Option<WantsSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gradnja: Option<String>,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub mogucnosti: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub vrste: BTreeMap<String, u32>,
    #[serde(
        rename = "cekaNadogradnju",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ceka_nadogradnju: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct GranicaOdbijenihPayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub granica: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct HoleRange {
    pub od: String,
    #[serde(rename = "do")]
    pub do_: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct RupePayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub trazim: BTreeMap<String, HoleRange>,
}

/// A version as the ledger sends it, read as Go reads its version (see
/// [`crate::wire::go_object`]): field names in any ASCII case, the last of a repeated
/// field, a missing field or `null` as Go's empty value, and keys Go does not know
/// skipped. The payload is kept as it came (`json.RawMessage`), `null` too; a missing one
/// is `null`, as Go writes it and signs it.
///
/// `created_at` is read as Go reads a time ([`crate::wire::go_time`]): a version whose time
/// Go does not read is an error, so the message that carries it is refused, as in Go.
/// The text is kept as it came, unescaped; a missing or `null` time is Go's zero time,
/// `0001-01-01T00:00:00Z`.
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
    #[serde(default = "null_payload")]
    pub payload: Box<RawValue>,
    #[serde(default = "go_zero_time_text", deserialize_with = "go_time_text")]
    pub created_at: String,
    /// Go reads any `int` here; this takes 0 to 2^32 - 1 only.
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The author's signature over the version and the author's public key, both base64
    /// (`wire::version_signature`). Empty for a version without a signature: one made
    /// before signing existed, or one that came through a peer that does not carry it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub potpis: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kljuc_autora: String,
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

// Go reads these as structs: from an object, `null` as `{}`, never from an array.
object_only!(
    EnvelopeV1,
    WantsSpec,
    FrontierPayload,
    GranicaOdbijenihPayload,
    HoleRange,
    RupePayload,
    DeltaPayload,
    ZeljePayload,
    ContentItemV1,
    SadrzajPayload,
    DonePayload,
);

fn null_payload() -> Box<RawValue> {
    RawValue::from_string("null".to_owned()).expect("null is JSON")
}

/// What Go writes for a time never set.
const GO_ZERO_TIME_TEXT: &str = "0001-01-01T00:00:00Z";

fn go_zero_time_text() -> String {
    GO_ZERO_TIME_TEXT.to_owned()
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct DeltaPayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub versions: Vec<VersionV1>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub skraceno: bool,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub rupe: BTreeMap<String, HoleRange>,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub popuna: BTreeMap<String, HoleRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct ZeljePayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub otisci: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct ContentItemV1 {
    pub otisak: String,
    pub vrsta: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kanal: String,
    pub bajtova: u64,
    pub podaci: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct SadrzajPayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub stavke: Vec<ContentItemV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(remote = "Self")]
pub struct DonePayload {
    pub applied: u64,
}

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
    T: DeserializeOwned,
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
        assert_eq!(ver.payload.get(), r#"{"id":"biljeska-1"}"#);
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
        let raw_sep = RawValue::from_string("{\"t\":\"a\u{2028}b\u{2029}c\"}".to_owned()).unwrap();
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
        let raw_payload =
            RawValue::from_string(v["sadrzajSPosebnimZnakovima"].as_str().unwrap().to_owned())
                .unwrap();
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
    /// its `versions`), the time as Unix seconds. Rust: `isto` reads the same, `GRESKA`
    /// refuses where Go reads: only a `schema_version` outside `u32`.
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
            "GRESKA",
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
            v.payload.get(),
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
        assert_eq!(refused, 1);
    }

    /// (message, JSON text, what Go does). Go column: go1.27.1, `json.Unmarshal` into the
    /// Go side's envelope and messages. Go reads a struct only from an object; `null`
    /// leaves it empty, and Rust reads it as `{}`. Rust refuses where Go reads in one way
    /// only: a field Rust requires (`kind`, `applied`) is missing, as in `{}`.
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
        fn ok<T: DeserializeOwned>(text: &str) -> &'static str {
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
        // Go reads these as empty; Rust requires the field, as it does in `{}`.
        assert!(serde_json::from_str::<EnvelopeV1>("null").is_err());
        assert!(serde_json::from_str::<DonePayload>("null").is_err());
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
                assert_eq!(d.versions[0].payload.get().len(), 2 * n);
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
}
