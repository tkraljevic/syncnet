use crate::wire::frame::{FrameError, read_frame_async, write_frame_async};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, fmt, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};

pub const KIND_HELLO: &str = "hello";
pub const KIND_REQUEST: &str = "request";
pub const KIND_PAGE: &str = "page";
pub const KIND_WANTS: &str = "zelje";
pub const KIND_CONTENT: &str = "sadrzaj";
pub const KIND_DONE: &str = "done";
pub const KIND_REFUSED: &str = "odbijeno";

pub const MAX_HELLO_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_REQUEST_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_PAGE_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_WANTS_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_CONTENT_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DONE_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

pub const MAX_REASON_BYTES: usize = 512;
pub const MAX_PROGRAM_BYTES: usize = 128;
pub const MAX_ERROR_BYTES: usize = 1024;
pub const MAX_CAPABILITIES_COUNT: usize = 32;
pub const MAX_SCHEMA_KINDS_COUNT: usize = 1024;

pub const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(60);

pub const REASON_BUSY_0038: &str = "čvor je zauzet, pokušajte kasnije";
pub const REASON_WRITE_BUSY_0038: &str =
    "čvor upravo upisuje ono što je primio od drugih; poslano stiže sljedećom razmjenom";
pub const REASON_NO_TAILSCALE_0038: &str =
    "na ovom računalu razmjena preko Tailscalea je isključena ([sync] tailscale = false)";

/// Stable numeric refusal codes (`kodovi.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum RefusalCode {
    None = 0,
    General = 0x0100,
    UnknownChannel = 0x0101,
    Busy = 0x0102,
    Refused = 0x0103,
    NotAMember = 0x0104,
    WriteBusy = 0x0106,
    NoTailscale = 0x0107,
}

impl RefusalCode {
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    pub fn from_u64_or_reason(kod: u64, reason: &str) -> Self {
        match kod {
            0x0100 => Self::General,
            0x0101 => Self::UnknownChannel,
            0x0102 => Self::Busy,
            0x0103 => Self::Refused,
            0x0104 => Self::NotAMember,
            0x0106 => Self::WriteBusy,
            0x0107 => Self::NoTailscale,
            0 => match reason {
                REASON_BUSY_0038 => Self::Busy,
                REASON_WRITE_BUSY_0038 => Self::WriteBusy,
                REASON_NO_TAILSCALE_0038 => Self::NoTailscale,
                _ => Self::None,
            },
            _ => Self::Refused,
        }
    }
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

pub fn max_frame_bytes_for_kind(kind: &str) -> usize {
    match kind {
        KIND_HELLO => MAX_HELLO_FRAME_BYTES,
        KIND_REQUEST => MAX_REQUEST_FRAME_BYTES,
        KIND_PAGE => MAX_PAGE_FRAME_BYTES,
        KIND_WANTS => MAX_WANTS_FRAME_BYTES,
        KIND_CONTENT => MAX_CONTENT_FRAME_BYTES,
        KIND_DONE => MAX_DONE_FRAME_BYTES,
        _ => MAX_ENVELOPE_BYTES,
    }
}

/// Truncates a UTF-8 string to at most `max_bytes` on a character boundary (`skrati` in `ograde_razgovora.go`).
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

pub fn bound_error_message(msg: &str) -> String {
    if msg.len() <= MAX_ERROR_BYTES {
        msg.to_owned()
    } else {
        format!("{}…", truncate_utf8(msg, MAX_ERROR_BYTES))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationEnvelope {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub kod: u64,
    #[serde(rename = "deviceId", default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl ConversationEnvelope {
    pub fn new<T: Serialize>(
        kind: impl Into<String>,
        device_id: impl Into<String>,
        payload: &T,
    ) -> Result<Self, ConversationError> {
        let val = serde_json::to_value(payload)
            .map_err(|e| ConversationError::Serialization(bound_error_message(&e.to_string())))?;
        Ok(Self {
            kind: kind.into(),
            reason: String::new(),
            kod: 0,
            device_id: device_id.into(),
            payload: Some(val),
        })
    }

    pub fn refusal(code: RefusalCode, reason: impl Into<String>) -> Self {
        let r = reason.into();
        let bounded = truncate_utf8(&r, MAX_REASON_BYTES).to_owned();
        Self {
            kind: KIND_REFUSED.to_owned(),
            reason: bounded,
            kod: code.as_u64(),
            device_id: String::new(),
            payload: None,
        }
    }

    pub fn decode_payload<T: DeserializeOwned>(&self) -> Result<T, ConversationError> {
        let val = self.payload.clone().unwrap_or(serde_json::Value::Null);
        serde_json::from_value(val)
            .map_err(|e| ConversationError::Serialization(bound_error_message(&e.to_string())))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConversationHello {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub program: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gradnja: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mogucnosti: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vrste: BTreeMap<String, u32>,
}

impl ConversationHello {
    pub fn sanitize_received(mut self) -> Self {
        self.program = truncate_utf8(&self.program, MAX_PROGRAM_BYTES).to_owned();
        self.gradnja = truncate_utf8(&self.gradnja, MAX_PROGRAM_BYTES).to_owned();
        if self.mogucnosti.len() > MAX_CAPABILITIES_COUNT {
            self.mogucnosti.truncate(MAX_CAPABILITIES_COUNT);
        }
        for cap in &mut self.mogucnosti {
            if cap.len() > 64 {
                *cap = truncate_utf8(cap, 64).to_owned();
            }
        }
        if self.vrste.len() > MAX_SCHEMA_KINDS_COUNT {
            let keys: Vec<String> = self
                .vrste
                .keys()
                .take(MAX_SCHEMA_KINDS_COUNT)
                .cloned()
                .collect();
            self.vrste.retain(|k, _| keys.contains(k));
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WantsMessage {
    #[serde(default)]
    pub otisci: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ContentBlobItem {
    pub otisak: String,
    pub mime: String,
    pub data_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ContentMessage {
    #[serde(default)]
    pub stavke: Vec<ContentBlobItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DoneMessage {
    pub applied: usize,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationError {
    RefusedByPeer {
        code: RefusalCode,
        reason: String,
    },
    UnexpectedKind {
        expected: String,
        actual: String,
    },
    WrongProtocol {
        peer: String,
        expected: String,
    },
    MessageTooLarge {
        kind: String,
        len: usize,
        max: usize,
    },
    Timeout {
        step: String,
    },
    Cancelled,
    Serialization(String),
    Io(String),
    Application(String),
}

impl fmt::Display for ConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RefusedByPeer { reason, .. } => write!(f, "čvor odbio razmjenu: {reason}"),
            Self::UnexpectedKind { expected, actual } => {
                let short_actual = truncate_utf8(actual, 64);
                write!(
                    f,
                    "neočekivana vrsta poruke u razgovoru: očekivano `{expected}`, primljeno `{short_actual}`"
                )
            }
            Self::WrongProtocol { peer, expected } => write!(
                f,
                "razgovor odbijen: druga strana govori protokol `{peer}`, a ovaj uređaj `{expected}`"
            ),
            Self::MessageTooLarge { kind, len, max } => write!(
                f,
                "poruka razmjene `{kind}` je prevelika ({len} B > dopušteno {max} B)"
            ),
            Self::Timeout { step } => write!(f, "istekao rok koraka razgovora ({step})"),
            Self::Cancelled => write!(f, "razgovor je otkazan"),
            Self::Serialization(m) => write!(f, "greška dekodiranja poruke razgovora: {m}"),
            Self::Io(m) => write!(f, "mrežna greška razgovora: {m}"),
            Self::Application(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ConversationError {}

pub async fn send_envelope<S>(
    stream: &mut S,
    env: &ConversationEnvelope,
    step_timeout: Duration,
) -> Result<(), ConversationError>
where
    S: AsyncWrite + Unpin,
{
    let max_len = max_frame_bytes_for_kind(&env.kind);
    let bytes = serde_json::to_vec(env)
        .map_err(|e| ConversationError::Serialization(bound_error_message(&e.to_string())))?;
    let res = timeout(step_timeout, write_frame_async(stream, &bytes, max_len))
        .await
        .map_err(|_| ConversationError::Timeout {
            step: format!("slanje {}", env.kind),
        })?;
    match res {
        Ok(()) => Ok(()),
        Err(FrameError::TooLarge { len, max }) => Err(ConversationError::MessageTooLarge {
            kind: env.kind.clone(),
            len,
            max,
        }),
        Err(FrameError::Io(m)) => Err(ConversationError::Io(bound_error_message(&m))),
    }
}

pub async fn receive_envelope_up_to<S>(
    stream: &mut S,
    expected_kind: &str,
    max_len: usize,
    step_timeout: Duration,
) -> Result<ConversationEnvelope, ConversationError>
where
    S: AsyncRead + Unpin,
{
    let capped_max = max_len.min(MAX_ENVELOPE_BYTES);
    let res = timeout(step_timeout, read_frame_async(stream, capped_max))
        .await
        .map_err(|_| ConversationError::Timeout {
            step: format!("primanje {expected_kind}"),
        })?;
    let bytes = match res {
        Ok(b) => b,
        Err(FrameError::TooLarge { len, max }) => {
            return Err(ConversationError::MessageTooLarge {
                kind: expected_kind.to_owned(),
                len,
                max,
            });
        }
        Err(FrameError::Io(m)) => return Err(ConversationError::Io(bound_error_message(&m))),
    };

    let env: ConversationEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| ConversationError::Serialization(bound_error_message(&e.to_string())))?;

    if env.kind == KIND_REFUSED {
        let bounded_reason = truncate_utf8(&env.reason, MAX_REASON_BYTES).to_owned();
        let code = RefusalCode::from_u64_or_reason(env.kod, &bounded_reason);
        return Err(ConversationError::RefusedByPeer {
            code,
            reason: bounded_reason,
        });
    }

    Ok(env)
}

pub async fn expect_envelope<S, T>(
    stream: &mut S,
    expected_kind: &str,
    step_timeout: Duration,
) -> Result<T, ConversationError>
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let max_len = max_frame_bytes_for_kind(expected_kind);
    let env = receive_envelope_up_to(stream, expected_kind, max_len, step_timeout).await?;
    if env.kind != expected_kind {
        return Err(ConversationError::UnexpectedKind {
            expected: expected_kind.to_owned(),
            actual: env.kind,
        });
    }
    env.decode_payload()
}

/// Executes a symmetric conversation step strictly ordered by role (`redom` in `razgovor.go`):
/// - Initiator (`initiator == true`) sends and flushes first, then receives.
/// - Responder (`initiator == false`) receives first, then sends and flushes.
///
/// This guarantees that one peer is always draining the stream while the other writes,
/// eliminating buffer-full deadlocks even when both sides transmit large pages.
pub async fn exchange_step_by_role<S, Out, In>(
    stream: &mut S,
    initiator: bool,
    kind: &str,
    device_id: &str,
    outgoing: &Out,
    step_timeout: Duration,
) -> Result<In, ConversationError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Out: Serialize,
    In: DeserializeOwned,
{
    let out_env = ConversationEnvelope::new(kind, device_id, outgoing)?;
    if initiator {
        send_envelope(stream, &out_env, step_timeout).await?;
        expect_envelope(stream, kind, step_timeout).await
    } else {
        let received = expect_envelope(stream, kind, step_timeout).await?;
        send_envelope(stream, &out_env, step_timeout).await?;
        Ok(received)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_codes_match_legacy_0038_literals_and_truncate_oversized_reasons() {
        for (reason, expected) in [
            (REASON_BUSY_0038, RefusalCode::Busy),
            (REASON_WRITE_BUSY_0038, RefusalCode::WriteBusy),
            (REASON_NO_TAILSCALE_0038, RefusalCode::NoTailscale),
            ("nepoznat razlog", RefusalCode::None),
        ] {
            assert_eq!(RefusalCode::from_u64_or_reason(0, reason), expected);
        }
        assert_eq!(
            RefusalCode::from_u64_or_reason(
                RefusalCode::NoTailscale.as_u64(),
                "Tailscale je iskljucen"
            ),
            RefusalCode::NoTailscale
        );

        let huge_reason = "čćž".repeat(500);
        let env = ConversationEnvelope::refusal(RefusalCode::Busy, huge_reason);
        assert!(env.reason.len() <= MAX_REASON_BYTES);
        assert_eq!(truncate_utf8("čćž", 3), "č");
        assert_eq!(truncate_utf8("abc", 0), "");
    }

    #[tokio::test]
    async fn role_ordered_step_prevents_deadlock_on_tiny_buffer_with_large_pages() {
        // 4 KiB duplex buffer, while both sides simultaneously exchange ~300 KiB payloads!
        let (mut initiator_io, mut responder_io) = tokio::io::duplex(4096);
        let large_a = "A".repeat(300 * 1024);
        let large_b = "B".repeat(300 * 1024);

        let large_a_clone = large_a.clone();
        let large_b_clone = large_b.clone();

        let t_init = tokio::spawn(async move {
            exchange_step_by_role::<_, String, String>(
                &mut initiator_io,
                true,
                KIND_PAGE,
                "node-a",
                &large_a_clone,
                Duration::from_secs(5),
            )
            .await
        });
        let t_resp = tokio::spawn(async move {
            exchange_step_by_role::<_, String, String>(
                &mut responder_io,
                false,
                KIND_PAGE,
                "node-b",
                &large_b_clone,
                Duration::from_secs(5),
            )
            .await
        });

        let (got_on_a, got_on_b) = tokio::join!(t_init, t_resp);
        assert_eq!(got_on_a.unwrap().unwrap(), large_b);
        assert_eq!(got_on_b.unwrap().unwrap(), large_a);
    }
}
