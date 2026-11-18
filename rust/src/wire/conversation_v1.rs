//! Version 1 line-delimited JSON conversation codec and message types (`docs/PROTOKOL.md`).
//!
//! This module provides only the wire codec and message structs verified against
//! `vektori/vektori-razgovora.json`; conversation session logic is kept out until
//! the general ledger abstraction is designed.

use crate::wire::go_json::to_go_json_vec;
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

pub const MAX_V1_CONTROL_LINE_BYTES: usize = 64 * 1024;
pub const MAX_V1_RUPE_LINE_BYTES: usize = 128 * 1024;
pub const MAX_V1_DELTA_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_V1_SADRZAJ_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_V1_DONE_LINE_BYTES: usize = 16 * 1024;

pub fn max_line_bytes_for_kind(kind: &str) -> usize {
    match kind {
        KIND_V1_FRONTIER | KIND_V1_GRANICA_ODBIJENIH | KIND_V1_ZELJE => MAX_V1_CONTROL_LINE_BYTES,
        KIND_V1_RUPE => MAX_V1_RUPE_LINE_BYTES,
        KIND_V1_DELTA => MAX_V1_DELTA_LINE_BYTES,
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
pub struct EnvelopeV1 {
    pub kind: String,
    #[serde(rename = "deviceId", default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Box<RawValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kod: Option<u64>,
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
        serde_json::from_str(raw.get()).map_err(|e| ConversationV1Error::Json(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
pub struct GranicaOdbijenihPayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub granica: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoleRange {
    pub od: String,
    #[serde(rename = "do")]
    pub do_: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RupePayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub trazim: BTreeMap<String, HoleRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionV1 {
    pub version_id: String,
    pub entity: String,
    pub entity_id: String,
    pub node_id: String,
    pub supersedes: String,
    pub archived: bool,
    pub payload: Box<RawValue>,
    pub created_at: String,
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
pub struct ZeljePayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub otisci: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentItemV1 {
    pub otisak: String,
    pub vrsta: String,
    pub kanal: String,
    pub bajtova: u64,
    pub podaci: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SadrzajPayload {
    #[serde(default, deserialize_with = "null_as_default")]
    pub stavke: Vec<ContentItemV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    serde_json::from_slice(&line).map_err(|e| ConversationV1Error::Json(e.to_string()))
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

        // sadrzaj
        let sadrzaj_line = v["sadrzaj"].as_str().unwrap();
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
            sadrzaj_line
        );

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

        // odbijenica (no payload) & posebniZnakovi.odbijenica (`<`, `>`, `&` escaped like Go)
        for odb_line in [
            z["odbijenica"].as_str().unwrap(),
            z["posebniZnakovi"]["odbijenica"].as_str().unwrap(),
        ] {
            let odb_env: EnvelopeV1 = serde_json::from_str(odb_line.trim_end()).unwrap();
            assert_eq!(odb_env.kind, KIND_V1_ODBIJENO);
            assert!(odb_env.payload.is_none());
            assert_eq!(to_line(&odb_env), odb_line);
        }

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
