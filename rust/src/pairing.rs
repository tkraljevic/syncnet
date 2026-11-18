use crate::{
    identity::public_key_to_base64,
    tls::{TlsAuthError, handshake_pairing_client, handshake_pairing_server},
    wire::frame::{FrameError, read_frame_async, write_frame_async},
};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_rustls::{client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream};

pub const SAS_NONCE_LEN: usize = 32;
pub const SAS_VERSION: u32 = 2;
pub const MAX_HELLO_LEN: usize = 64 * 1024;
pub const MAX_SAS_MSG_LEN: usize = 4 * 1024;
pub const MAX_CONFIRM_LEN: usize = 1024 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

pub fn compute_sas_commit(protocol: &str, nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(protocol.as_bytes());
    h.update(b"-pair-commit-v2|");
    h.update(nonce);
    h.finalize().into()
}

pub fn verify_sas_commit(protocol: &str, revealed_nonce: &[u8], expected_commit: &[u8]) -> bool {
    if revealed_nonce.len() != SAS_NONCE_LEN || expected_commit.len() != 32 {
        return false;
    }
    let actual = compute_sas_commit(protocol, revealed_nonce);
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(expected_commit.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub fn compute_sas_code(
    protocol: &str,
    pub_a: &[u8; 32],
    pub_b: &[u8; 32],
    caller_nonce: &[u8; SAS_NONCE_LEN],
    listener_nonce: &[u8; SAS_NONCE_LEN],
) -> String {
    let (x, y) = if pub_a <= pub_b {
        (pub_a, pub_b)
    } else {
        (pub_b, pub_a)
    };
    let mut h = Sha256::new();
    h.update(protocol.as_bytes());
    h.update(b"-pair-v2|");
    h.update(x);
    h.update(y);
    h.update(caller_nonce);
    h.update(listener_nonce);
    let sum = h.finalize();
    let n = u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]]) % 1_000_000;
    format!("{n:06}")
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

mod opt_base64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_str(&STANDARD.encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => STANDARD
                .decode(s.trim())
                .map(Some)
                .map_err(|e| D::Error::custom(format!("neispravan base64 u SAS poruci: {e}"))),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairIdentity {
    pub protocol: String,
    pub device_id: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

impl PairIdentity {
    pub fn to_hello(&self) -> PairHello {
        let name = if self.name.trim().is_empty() {
            "device".to_owned()
        } else {
            self.name.clone()
        };
        PairHello {
            protocol: self.protocol.clone(),
            device_id: self.device_id.clone(),
            name,
            version: self.version.clone(),
            meta: self.meta.clone(),
            sas: SAS_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PairHello {
    pub protocol: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sas: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SasWireMessage {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_base64")]
    pub obveza: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_base64")]
    pub broj: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConfirm {
    pub approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairFinishResult {
    pub approved: bool,
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    NotAPeer(String),
    PeerNotWaitingToPair,
    WrongProtocol { peer: String, expected: String },
    LegacySasUnsupported,
    InvalidCommit,
    SelfPairing,
    PeerDisconnectedBeforeConfirm(String),
    Serialization(String),
    Frame(FrameError),
    Tls(TlsAuthError),
    Io(String),
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAPeer(m) => write!(f, "TLS handshake failed: {m}"),
            Self::PeerNotWaitingToPair => write!(f, "peer is not waiting to pair"),
            Self::WrongProtocol { peer, expected } => {
                write!(f, "protocol mismatch: peer={peer}, expected={expected}")
            }
            Self::LegacySasUnsupported => write!(f, "legacy SAS without commit is unsupported"),
            Self::InvalidCommit => write!(f, "invalid SAS commit"),
            Self::SelfPairing => write!(f, "cannot pair with self"),
            Self::PeerDisconnectedBeforeConfirm(m) => {
                write!(f, "peer disconnected before confirmation: {m}")
            }
            Self::Serialization(m) => write!(f, "pairing serialization error: {m}"),
            Self::Frame(e) => write!(f, "{e}"),
            Self::Tls(e) => write!(f, "{e}"),
            Self::Io(m) => write!(f, "pairing I/O error: {m}"),
        }
    }
}

impl std::error::Error for PairingError {}

impl From<TlsAuthError> for PairingError {
    fn from(err: TlsAuthError) -> Self {
        match err {
            TlsAuthError::NotAPeer(m) => Self::NotAPeer(m),
            TlsAuthError::WrongProtocol { peer, expected } => {
                Self::WrongProtocol { peer, expected }
            }
            other => Self::Tls(other),
        }
    }
}

impl From<FrameError> for PairingError {
    fn from(err: FrameError) -> Self {
        Self::Frame(err)
    }
}

pub async fn exchange_hello_async<S>(
    stream: &mut S,
    identity: &PairIdentity,
) -> Result<PairHello, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let our_hello = identity.to_hello();
    let encoded =
        serde_json::to_vec(&our_hello).map_err(|e| PairingError::Serialization(e.to_string()))?;
    write_frame_async(stream, &encoded, MAX_HELLO_LEN).await?;

    let raw = match read_frame_async(stream, MAX_HELLO_LEN).await {
        Ok(bytes) => bytes,
        Err(FrameError::Io(msg))
            if msg.contains("early eof") || msg.contains("unexpected end of file") =>
        {
            return Err(PairingError::PeerNotWaitingToPair);
        }
        Err(e) => return Err(PairingError::Frame(e)),
    };

    let peer: PairHello = serde_json::from_slice(&raw)
        .map_err(|e| PairingError::Serialization(format!("citanje pozdrava druge strane: {e}")))?;
    if peer.protocol != identity.protocol {
        return Err(PairingError::WrongProtocol {
            peer: peer.protocol,
            expected: identity.protocol.clone(),
        });
    }
    if peer.sas < SAS_VERSION {
        return Err(PairingError::LegacySasUnsupported);
    }
    Ok(peer)
}

pub async fn negotiate_sas_caller_async<S>(
    stream: &mut S,
    protocol: &str,
    caller_nonce: &[u8; SAS_NONCE_LEN],
) -> Result<[u8; SAS_NONCE_LEN], PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let commit = compute_sas_commit(protocol, caller_nonce);
    let step1 = SasWireMessage {
        obveza: Some(commit.to_vec()),
        broj: None,
    };
    let step1_bytes =
        serde_json::to_vec(&step1).map_err(|e| PairingError::Serialization(e.to_string()))?;
    write_frame_async(stream, &step1_bytes, MAX_SAS_MSG_LEN).await?;

    let reply_raw = read_frame_async(stream, MAX_SAS_MSG_LEN).await?;
    let reply: SasWireMessage = serde_json::from_slice(&reply_raw)
        .map_err(|e| PairingError::Serialization(e.to_string()))?;
    let Some(listener_vec) = reply.broj else {
        return Err(PairingError::InvalidCommit);
    };
    if reply.obveza.is_some() {
        return Err(PairingError::InvalidCommit);
    }
    let listener_nonce: [u8; SAS_NONCE_LEN] = listener_vec
        .try_into()
        .map_err(|_| PairingError::InvalidCommit)?;

    let step3 = SasWireMessage {
        obveza: None,
        broj: Some(caller_nonce.to_vec()),
    };
    let step3_bytes =
        serde_json::to_vec(&step3).map_err(|e| PairingError::Serialization(e.to_string()))?;
    write_frame_async(stream, &step3_bytes, MAX_SAS_MSG_LEN).await?;

    Ok(listener_nonce)
}

pub async fn negotiate_sas_listener_async<S>(
    stream: &mut S,
    protocol: &str,
    listener_nonce: &[u8; SAS_NONCE_LEN],
) -> Result<[u8; SAS_NONCE_LEN], PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let commit_raw = read_frame_async(stream, MAX_SAS_MSG_LEN).await?;
    let commit_msg: SasWireMessage = serde_json::from_slice(&commit_raw)
        .map_err(|e| PairingError::Serialization(e.to_string()))?;
    let Some(commit_vec) = commit_msg.obveza else {
        return Err(PairingError::InvalidCommit);
    };
    if commit_msg.broj.is_some() || commit_vec.len() != 32 {
        return Err(PairingError::InvalidCommit);
    }

    let step2 = SasWireMessage {
        obveza: None,
        broj: Some(listener_nonce.to_vec()),
    };
    let step2_bytes =
        serde_json::to_vec(&step2).map_err(|e| PairingError::Serialization(e.to_string()))?;
    write_frame_async(stream, &step2_bytes, MAX_SAS_MSG_LEN).await?;

    let reveal_raw = read_frame_async(stream, MAX_SAS_MSG_LEN).await?;
    let reveal_msg: SasWireMessage = serde_json::from_slice(&reveal_raw)
        .map_err(|e| PairingError::Serialization(e.to_string()))?;
    let Some(caller_vec) = reveal_msg.broj else {
        return Err(PairingError::InvalidCommit);
    };
    if reveal_msg.obveza.is_some()
        || caller_vec.len() != SAS_NONCE_LEN
        || !verify_sas_commit(protocol, &caller_vec, &commit_vec)
    {
        return Err(PairingError::InvalidCommit);
    }

    caller_vec
        .try_into()
        .map_err(|_| PairingError::InvalidCommit)
}

pub struct PendingPairing<S> {
    stream: S,
    peer_hello: PairHello,
    peer_key: [u8; 32],
    peer_host: Option<String>,
    sas: String,
    is_caller: bool,
}

impl<S> fmt::Debug for PendingPairing<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPairing")
            .field("peer_hello", &self.peer_hello)
            .field("peer_key", &public_key_to_base64(&self.peer_key))
            .field("peer_host", &self.peer_host)
            .field("sas", &self.sas)
            .field("is_caller", &self.is_caller)
            .finish()
    }
}

impl<S> PendingPairing<S> {
    pub fn sas(&self) -> &str {
        &self.sas
    }

    pub fn peer_key(&self) -> &[u8; 32] {
        &self.peer_key
    }

    pub fn peer_key_base64(&self) -> String {
        public_key_to_base64(&self.peer_key)
    }

    pub fn peer_hello(&self) -> &PairHello {
        &self.peer_hello
    }

    pub fn peer_host(&self) -> Option<&str> {
        self.peer_host.as_deref()
    }

    pub fn is_caller(&self) -> bool {
        self.is_caller
    }
}

impl<S> PendingPairing<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn finish<T: Serialize>(
        mut self,
        approved: bool,
        payload: Option<&T>,
    ) -> Result<PairFinishResult, PairingError> {
        let payload_val = if approved {
            match payload {
                Some(p) => Some(
                    serde_json::to_value(p)
                        .map_err(|e| PairingError::Serialization(e.to_string()))?,
                ),
                None => None,
            }
        } else {
            None
        };
        let mine = PairConfirm {
            approved,
            payload: payload_val,
        };
        let mine_bytes =
            serde_json::to_vec(&mine).map_err(|e| PairingError::Serialization(e.to_string()))?;

        let outcome = timeout(CONFIRM_TIMEOUT, async {
            write_frame_async(&mut self.stream, &mine_bytes, MAX_CONFIRM_LEN).await?;
            let theirs_raw = read_frame_async(&mut self.stream, MAX_CONFIRM_LEN)
                .await
                .map_err(|e| PairingError::PeerDisconnectedBeforeConfirm(e.to_string()))?;
            let theirs: PairConfirm = serde_json::from_slice(&theirs_raw)
                .map_err(|e| PairingError::PeerDisconnectedBeforeConfirm(e.to_string()))?;
            Ok::<PairConfirm, PairingError>(theirs)
        })
        .await
        .map_err(|_| {
            PairingError::PeerDisconnectedBeforeConfirm("istekao rok potvrde".to_owned())
        })?;

        let _ = self.stream.shutdown().await;
        let theirs = outcome?;
        if !approved || !theirs.approved {
            return Ok(PairFinishResult {
                approved: false,
                payload: None,
            });
        }
        Ok(PairFinishResult {
            approved: true,
            payload: theirs.payload,
        })
    }
}

async fn complete_pairing_handshake<S>(
    mut tls_stream: S,
    our_pub: [u8; 32],
    peer_pub: [u8; 32],
    peer_host: Option<String>,
    identity: &PairIdentity,
    is_caller: bool,
) -> Result<PendingPairing<S>, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if our_pub == peer_pub {
        let _ = tls_stream.shutdown().await;
        return Err(PairingError::SelfPairing);
    }
    let mut our_nonce = [0u8; SAS_NONCE_LEN];
    OsRng.fill_bytes(&mut our_nonce);

    let res = timeout(HANDSHAKE_TIMEOUT, async {
        let peer_hello = exchange_hello_async(&mut tls_stream, identity).await?;
        let (caller_nonce, listener_nonce) = if is_caller {
            let ln =
                negotiate_sas_caller_async(&mut tls_stream, &identity.protocol, &our_nonce).await?;
            (our_nonce, ln)
        } else {
            let cn = negotiate_sas_listener_async(&mut tls_stream, &identity.protocol, &our_nonce)
                .await?;
            (cn, our_nonce)
        };
        let sas = compute_sas_code(
            &identity.protocol,
            &our_pub,
            &peer_pub,
            &caller_nonce,
            &listener_nonce,
        );
        Ok::<(PairHello, String), PairingError>((peer_hello, sas))
    })
    .await;

    match res {
        Ok(Ok((peer_hello, sas))) => Ok(PendingPairing {
            stream: tls_stream,
            peer_hello,
            peer_key: peer_pub,
            peer_host,
            sas,
            is_caller,
        }),
        Ok(Err(e)) => {
            let _ = tls_stream.shutdown().await;
            Err(e)
        }
        Err(_) => {
            let _ = tls_stream.shutdown().await;
            Err(PairingError::Io(
                "istekao rok rukovanja uparivanja".to_owned(),
            ))
        }
    }
}

pub async fn dial_pairing_on<S>(
    stream: S,
    peer_host: Option<String>,
    sk: &SigningKey,
    identity: &PairIdentity,
) -> Result<PendingPairing<ClientTlsStream<S>>, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (tls_stream, verified) = timeout(
        HANDSHAKE_TIMEOUT,
        handshake_pairing_client(stream, sk, &identity.protocol),
    )
    .await
    .map_err(|_| PairingError::NotAPeer("istekao rok TLS rukovanja".to_owned()))??;

    complete_pairing_handshake(
        tls_stream,
        sk.verifying_key().to_bytes(),
        verified.public_key,
        peer_host,
        identity,
        true,
    )
    .await
}

pub async fn accept_pairing_on<S>(
    stream: S,
    peer_host: Option<String>,
    sk: &SigningKey,
    identity: &PairIdentity,
) -> Result<PendingPairing<ServerTlsStream<S>>, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (tls_stream, verified) = timeout(
        HANDSHAKE_TIMEOUT,
        handshake_pairing_server(stream, sk, &identity.protocol),
    )
    .await
    .map_err(|_| PairingError::NotAPeer("istekao rok TLS rukovanja".to_owned()))??;

    complete_pairing_handshake(
        tls_stream,
        sk.verifying_key().to_bytes(),
        verified.public_key,
        peer_host,
        identity,
        false,
    )
    .await
}

pub async fn dial_pairing(
    addr: SocketAddr,
    sk: &SigningKey,
    identity: &PairIdentity,
) -> Result<PendingPairing<ClientTlsStream<TcpStream>>, PairingError> {
    let tcp = timeout(Duration::from_secs(15), TcpStream::connect(addr))
        .await
        .map_err(|_| PairingError::Io("istekao rok TCP spajanja".to_owned()))?
        .map_err(|e| PairingError::Io(e.to_string()))?;
    let peer_host = Some(addr.ip().to_string());
    dial_pairing_on(tcp, peer_host, sk, identity).await
}

/// Waits for one valid pairing handshake on `listener`. Connections that fail the
/// TLS 1.3 handshake (`PairingError::NotAPeer`, such as port probes) are ignored so
/// that the listener stays open for the real peer.
pub async fn listen_pairing(
    listener: &TcpListener,
    sk: &SigningKey,
    identity: &PairIdentity,
) -> Result<PendingPairing<ServerTlsStream<TcpStream>>, PairingError> {
    loop {
        let (tcp, remote) = listener
            .accept()
            .await
            .map_err(|e| PairingError::Io(e.to_string()))?;
        let peer_host = Some(remote.ip().to_string());
        match accept_pairing_on(tcp, peer_host, sk, identity).await {
            Ok(pending) => return Ok(pending),
            Err(PairingError::NotAPeer(_)) => continue,
            Err(other) => return Err(other),
        }
    }
}

#[derive(Debug)]
pub enum ActivePendingPairing {
    Dialed(PendingPairing<ClientTlsStream<TcpStream>>),
    Accepted(PendingPairing<ServerTlsStream<TcpStream>>),
}

impl ActivePendingPairing {
    pub fn sas(&self) -> &str {
        match self {
            Self::Dialed(p) => p.sas(),
            Self::Accepted(p) => p.sas(),
        }
    }

    pub fn peer_key(&self) -> &[u8; 32] {
        match self {
            Self::Dialed(p) => p.peer_key(),
            Self::Accepted(p) => p.peer_key(),
        }
    }

    pub fn peer_key_base64(&self) -> String {
        match self {
            Self::Dialed(p) => p.peer_key_base64(),
            Self::Accepted(p) => p.peer_key_base64(),
        }
    }

    pub fn peer_hello(&self) -> &PairHello {
        match self {
            Self::Dialed(p) => p.peer_hello(),
            Self::Accepted(p) => p.peer_hello(),
        }
    }

    pub fn peer_host(&self) -> Option<&str> {
        match self {
            Self::Dialed(p) => p.peer_host(),
            Self::Accepted(p) => p.peer_host(),
        }
    }

    pub async fn finish<T: Serialize>(
        self,
        approved: bool,
        payload: Option<&T>,
    ) -> Result<PairFinishResult, PairingError> {
        match self {
            Self::Dialed(p) => p.finish(approved, payload).await,
            Self::Accepted(p) => p.finish(approved, payload).await,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PairSlotSnapshot {
    pub waiting: bool,
    pub pending: bool,
    pub listen_port: Option<u16>,
    pub sas: Option<String>,
    pub peer_device_id: Option<String>,
    pub peer_name: Option<String>,
    pub peer_public_key: Option<String>,
    pub peer_host: Option<String>,
    pub error: Option<String>,
}

struct PairingSlotInner {
    generation: u64,
    waiting_cancel: Option<oneshot::Sender<()>>,
    listen_port: Option<u16>,
    pending: Option<ActivePendingPairing>,
    last_error: Option<String>,
}

#[derive(Clone)]
pub struct PairingSessionSlot {
    inner: Arc<Mutex<PairingSlotInner>>,
}

impl fmt::Debug for PairingSessionSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingSessionSlot").finish_non_exhaustive()
    }
}

impl Default for PairingSessionSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingSessionSlot {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PairingSlotInner {
                generation: 0,
                waiting_cancel: None,
                listen_port: None,
                pending: None,
                last_error: None,
            })),
        }
    }

    pub fn snapshot(&self) -> PairSlotSnapshot {
        let guard = self.inner.lock().expect("pairing slot lock");
        let mut snap = PairSlotSnapshot {
            waiting: guard.waiting_cancel.is_some(),
            pending: guard.pending.is_some(),
            listen_port: guard.listen_port,
            error: guard.last_error.clone(),
            ..Default::default()
        };
        if let Some(ref p) = guard.pending {
            snap.sas = Some(p.sas().to_owned());
            snap.peer_device_id = Some(p.peer_hello().device_id.clone());
            snap.peer_name = Some(p.peer_hello().name.clone());
            snap.peer_public_key = Some(p.peer_key_base64());
            snap.peer_host = p.peer_host().map(ToOwned::to_owned);
        }
        snap
    }

    pub async fn start_listening(
        &self,
        bind_addr: SocketAddr,
        sk: SigningKey,
        identity: PairIdentity,
    ) -> Result<PairSlotSnapshot, String> {
        {
            let guard = self.inner.lock().expect("pairing slot lock");
            if guard.waiting_cancel.is_some() || guard.pending.is_some() {
                return Err("Uparivanje je vec u tijeku".into());
            }
        }
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Greska otvaranja porta za uparivanje: {e}"))?;
        let local_port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let (tx, rx) = oneshot::channel();
        let my_gen = {
            let mut guard = self.inner.lock().expect("pairing slot lock");
            guard.generation += 1;
            guard.waiting_cancel = Some(tx);
            guard.listen_port = Some(local_port);
            guard.last_error = None;
            guard.generation
        };

        let inner = self.inner.clone();
        tokio::spawn(async move {
            let res = tokio::select! {
                _ = rx => return,
                r = listen_pairing(&listener, &sk, &identity) => r,
            };
            let mut guard = inner.lock().expect("pairing slot lock");
            if guard.generation != my_gen {
                if let Ok(stale) = res {
                    tokio::spawn(async move {
                        let _ = stale.finish::<serde_json::Value>(false, None).await;
                    });
                }
                return;
            }
            guard.waiting_cancel = None;
            guard.listen_port = None;
            match res {
                Ok(pending) => {
                    guard.pending = Some(ActivePendingPairing::Accepted(pending));
                }
                Err(e) => {
                    guard.last_error = Some(e.to_string());
                }
            }
        });

        Ok(self.snapshot())
    }

    pub fn stop_listening(&self) -> PairSlotSnapshot {
        let pending_to_reject = {
            let mut guard = self.inner.lock().expect("pairing slot lock");
            guard.generation += 1;
            if let Some(cancel) = guard.waiting_cancel.take() {
                let _ = cancel.send(());
            }
            guard.listen_port = None;
            guard.pending.take()
        };
        if let Some(pending) = pending_to_reject {
            tokio::spawn(async move {
                let _ = pending.finish::<serde_json::Value>(false, None).await;
            });
        }
        self.snapshot()
    }

    pub async fn dial(
        &self,
        addr: SocketAddr,
        sk: SigningKey,
        identity: PairIdentity,
    ) -> Result<PairSlotSnapshot, String> {
        {
            let guard = self.inner.lock().expect("pairing slot lock");
            if guard.pending.is_some() {
                return Err("Jedno uparivanje vec ceka odluku".into());
            }
        }
        let pending = dial_pairing(addr, &sk, &identity)
            .await
            .map_err(|e| e.to_string())?;
        {
            let mut guard = self.inner.lock().expect("pairing slot lock");
            guard.generation += 1;
            if let Some(cancel) = guard.waiting_cancel.take() {
                let _ = cancel.send(());
            }
            guard.listen_port = None;
            guard.pending = Some(ActivePendingPairing::Dialed(pending));
            guard.last_error = None;
        }
        Ok(self.snapshot())
    }

    pub fn take_pending(&self) -> Option<ActivePendingPairing> {
        let mut guard = self.inner.lock().expect("pairing slot lock");
        guard.pending.take()
    }
}

pub fn reject_pending_in_background(pending: ActivePendingPairing) {
    tokio::spawn(async move {
        let _ = pending.finish::<serde_json::Value>(false, None).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_signing_key;
    use serde_json::json;

    #[test]
    fn sas_code_is_order_independent_for_keys_and_order_dependent_for_nonces() {
        let a = [0x10u8; 32];
        let b = [0x20u8; 32];
        let nc = [0x01u8; 32];
        let nl = [0x02u8; 32];

        let s1 = compute_sas_code("list2cart", &a, &b, &nc, &nl);
        let s2 = compute_sas_code("list2cart", &b, &a, &nc, &nl);
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 6);

        let s_swapped_nonces = compute_sas_code("list2cart", &a, &b, &nl, &nc);
        assert_ne!(s1, s_swapped_nonces);

        let s_other_proto = compute_sas_code("list2cart-sim", &a, &b, &nc, &nl);
        assert_ne!(s1, s_other_proto);
    }

    #[test]
    fn sas_commit_reveal_verifies_and_rejects_tampered_nonce() {
        let nonce = [0xABu8; SAS_NONCE_LEN];
        let commit = compute_sas_commit("list2cart", &nonce);
        assert!(verify_sas_commit("list2cart", &nonce, &commit));

        let mut bad = nonce;
        bad[0] ^= 1;
        assert!(!verify_sas_commit("list2cart", &bad, &commit));
        assert!(!verify_sas_commit("list2cart", &[0u8; 16], &commit));
    }

    #[tokio::test]
    async fn full_tls13_pairing_agrees_on_sas_and_exchanges_payload_only_on_mutual_approval() {
        let sk_a = generate_signing_key();
        let sk_b = generate_signing_key();
        let id_a = PairIdentity {
            protocol: "list2cart".to_owned(),
            device_id: "A".to_owned(),
            name: "Mobitel A".to_owned(),
            version: "0.1.0".to_owned(),
            meta: BTreeMap::new(),
        };
        let id_b = PairIdentity {
            protocol: "list2cart".to_owned(),
            device_id: "B".to_owned(),
            name: "Laptop B".to_owned(),
            version: "0.1.0".to_owned(),
            meta: BTreeMap::new(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().unwrap();

        // Send a raw non-TLS probe first: `listen_pairing` must skip `NotAPeer` and keep waiting!
        let probe_addr = addr;
        tokio::spawn(async move {
            if let Ok(mut raw) = TcpStream::connect(probe_addr).await {
                let _ = raw.write_all(b"GET / HTTP/1.1\r\n\r\n").await;
                let _ = raw.shutdown().await;
            }
        });

        let sk_a_clone = sk_a.clone();
        let id_a_clone = id_a.clone();
        let listen_task =
            tokio::spawn(async move { listen_pairing(&listener, &sk_a_clone, &id_a_clone).await });

        tokio::time::sleep(Duration::from_millis(25)).await;
        let dial_pending = dial_pairing(addr, &sk_b, &id_b).await.expect("dial");
        let listen_pending = listen_task.await.unwrap().expect("listen");

        assert_eq!(dial_pending.sas(), listen_pending.sas());
        assert_eq!(dial_pending.sas().len(), 6);
        assert_eq!(
            dial_pending.peer_key(),
            &sk_a.verifying_key().to_bytes(),
            "dialer learns listener's TLS-proven public key"
        );
        assert_eq!(
            listen_pending.peer_key(),
            &sk_b.verifying_key().to_bytes(),
            "listener learns dialer's TLS-proven public key"
        );
        assert_eq!(dial_pending.peer_hello().device_id, "A");
        assert_eq!(listen_pending.peer_hello().device_id, "B");

        let finish_a = tokio::spawn(async move {
            listen_pending
                .finish(true, Some(&json!({"note": "from A"})))
                .await
        });
        let res_b = dial_pending
            .finish(true, Some(&json!({"note": "from B"})))
            .await
            .expect("finish B");
        let res_a = finish_a.await.unwrap().expect("finish A");

        assert!(res_a.approved && res_b.approved);
        assert_eq!(res_b.payload, Some(json!({"note": "from A"})));
        assert_eq!(res_a.payload, Some(json!({"note": "from B"})));
    }

    #[tokio::test]
    async fn refusal_on_either_side_hands_over_nothing() {
        let sk_a = generate_signing_key();
        let sk_b = generate_signing_key();
        let id_a = PairIdentity {
            protocol: "list2cart".to_owned(),
            device_id: "A".to_owned(),
            name: "A".to_owned(),
            version: "0.1.0".to_owned(),
            meta: BTreeMap::new(),
        };
        let id_b = PairIdentity {
            protocol: "list2cart".to_owned(),
            device_id: "B".to_owned(),
            name: "B".to_owned(),
            version: "0.1.0".to_owned(),
            meta: BTreeMap::new(),
        };

        let (c_io, s_io) = tokio::io::duplex(16 * 1024);
        let sk_a_clone = sk_a.clone();
        let id_a_clone = id_a.clone();
        let srv = tokio::spawn(async move {
            let p = accept_pairing_on(s_io, None, &sk_a_clone, &id_a_clone)
                .await
                .unwrap();
            p.finish(false, Some(&json!({"secret": "never"}))).await
        });

        let cli_p = dial_pairing_on(c_io, None, &sk_b, &id_b).await.unwrap();
        let cli_res = cli_p
            .finish(true, Some(&json!({"secret": "from B"})))
            .await
            .unwrap();
        let srv_res = srv.await.unwrap().unwrap();

        assert!(!cli_res.approved);
        assert_eq!(cli_res.payload, None);
        assert!(!srv_res.approved);
        assert_eq!(srv_res.payload, None);
    }

    #[tokio::test]
    async fn rejects_wrong_protocol_legacy_sas_broken_commit_and_truncated_steps() {
        let sk_a = generate_signing_key();
        let sk_b = generate_signing_key();
        let id_a = PairIdentity {
            protocol: "list2cart".to_owned(),
            device_id: "A".to_owned(),
            name: "A".to_owned(),
            version: "0.1.0".to_owned(),
            meta: BTreeMap::new(),
        };

        // 1. Wrong protocol rejected at TLS ALPN / certificate CN verification
        let id_wrong = PairIdentity {
            protocol: "list2cart-sim".to_owned(),
            device_id: "B".to_owned(),
            name: "B".to_owned(),
            version: "0.1.0".to_owned(),
            meta: BTreeMap::new(),
        };
        let (c1, s1) = tokio::io::duplex(16 * 1024);
        let sk_a1 = sk_a.clone();
        let id_a1 = id_a.clone();
        let t1 = tokio::spawn(async move { accept_pairing_on(s1, None, &sk_a1, &id_a1).await });
        let r1 = dial_pairing_on(c1, None, &sk_b, &id_wrong).await;
        assert!(matches!(
            r1,
            Err(PairingError::WrongProtocol { .. }
                | PairingError::NotAPeer(_)
                | PairingError::Tls(_))
        ));
        let _ = t1.await;

        // 2. Legacy SAS (< 2) rejected in Hello
        let (mut c2, mut s2) = tokio::io::duplex(16 * 1024);
        let id_a2 = id_a.clone();
        let t2 = tokio::spawn(async move {
            let legacy_hello = PairHello {
                protocol: "list2cart".to_owned(),
                device_id: "old".to_owned(),
                name: "Old".to_owned(),
                version: "0.0.1".to_owned(),
                meta: BTreeMap::new(),
                sas: 0,
            };
            let _ = read_frame_async(&mut s2, MAX_HELLO_LEN).await;
            let bytes = serde_json::to_vec(&legacy_hello).unwrap();
            write_frame_async(&mut s2, &bytes, MAX_HELLO_LEN)
                .await
                .unwrap();
        });
        let r2 = exchange_hello_async(&mut c2, &id_a2).await;
        assert!(matches!(r2, Err(PairingError::LegacySasUnsupported)));
        let _ = t2.await;

        // 3. Broken commit (caller reveals a different nonce than committed) is rejected with InvalidCommit
        let (mut c3, mut s3) = tokio::io::duplex(16 * 1024);
        let t3 = tokio::spawn(async move {
            let committed = [0x11u8; SAS_NONCE_LEN];
            let revealed = [0x22u8; SAS_NONCE_LEN];
            let commit = compute_sas_commit("list2cart", &committed);
            let m1 = serde_json::to_vec(&SasWireMessage {
                obveza: Some(commit.to_vec()),
                broj: None,
            })
            .unwrap();
            write_frame_async(&mut c3, &m1, MAX_SAS_MSG_LEN)
                .await
                .unwrap();
            let _ = read_frame_async(&mut c3, MAX_SAS_MSG_LEN).await.unwrap();
            let m3 = serde_json::to_vec(&SasWireMessage {
                obveza: None,
                broj: Some(revealed.to_vec()),
            })
            .unwrap();
            write_frame_async(&mut c3, &m3, MAX_SAS_MSG_LEN)
                .await
                .unwrap();
        });
        let listener_nonce = [0x33u8; SAS_NONCE_LEN];
        let r3 = negotiate_sas_listener_async(&mut s3, "list2cart", &listener_nonce).await;
        assert!(matches!(r3, Err(PairingError::InvalidCommit)));
        let _ = t3.await;

        // 4. Short commit or short listener nonce is rejected with InvalidCommit
        let (mut c4, mut s4) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let bad = serde_json::to_vec(&SasWireMessage {
                obveza: Some(vec![1, 2, 3]),
                broj: None,
            })
            .unwrap();
            let _ = write_frame_async(&mut c4, &bad, MAX_SAS_MSG_LEN).await;
        });
        assert!(matches!(
            negotiate_sas_listener_async(&mut s4, "list2cart", &listener_nonce).await,
            Err(PairingError::InvalidCommit)
        ));
    }
}
