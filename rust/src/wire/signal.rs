use crate::identity::{parse_public_key, public_key_to_base64};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;

pub const SIGNAL_KIND_POZIV: &str = "poziv";
pub const SIGNAL_KIND_ODZIV: &str = "odziv";
pub const SIGNAL_KIND_SINKRO: &str = "sinkro";
pub const SIGNAL_MAX_SKEW_SECS: i64 = 600;
pub const SIGNAL_REPLAY_CACHE_MAX: usize = 8192;
pub const SIGNAL_MAX_SINKRO_ATTEMPT: u32 = 3;

pub mod base64_bytes {
    use super::*;

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

pub mod opt_base64_bytes {
    use super::*;

    pub fn serialize<S>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
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
                .decode(s.as_bytes())
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalError {
    InvalidShape(String),
    UnknownSender,
    BadSignature,
    WrongRecipient,
    WrongRendezvous,
    ClockSkew,
    Replayed,
    ReplayCacheFull,
}

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShape(m) => write!(f, "neispravan oblik signalne poruke: {m}"),
            Self::UnknownSender => write!(f, "nepoznat posiljatelj signalne poruke"),
            Self::BadSignature => write!(f, "potpis signalne poruke ne vrijedi"),
            Self::WrongRecipient => write!(f, "signalna poruka nije za ovaj uredjaj"),
            Self::WrongRendezvous => write!(f, "signalna poruka stigla s krivog sastajalista"),
            Self::ClockSkew => write!(f, "vrijeme signalne poruke odstupa vise od 10 min"),
            Self::Replayed => write!(f, "ponovljena signalna poruka odbijena"),
            Self::ReplayCacheFull => write!(f, "pricuva signalnih poruka je puna"),
        }
    }
}

impl std::error::Error for SignalError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateAddr {
    pub kind: String,
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatReport {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_blocked: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalBody {
    pub ver: u32,
    pub sesija: String,
    pub od: String,
    pub za: String,
    pub sastajaliste: String,
    pub izdano: i64,
    #[serde(
        default,
        with = "opt_base64_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub tajna: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kandidati: Vec<CandidateAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<NatReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub odluka: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub razlog: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obrada_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pokusaj: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(
        default,
        with = "opt_base64_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub vj: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSignalMessage {
    #[serde(skip)]
    pub kind: String,
    #[serde(with = "base64_bytes")]
    pub tijelo: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub potpis: Vec<u8>,
}

pub fn signal_signing_prefix(protocol: &str, kind: &str) -> Vec<u8> {
    format!("{protocol}-{kind}-v1|").into_bytes()
}

impl SignedSignalMessage {
    pub fn sign(sk: &SigningKey, protocol: &str, kind: &str, mut body: SignalBody) -> Self {
        body.ver = 1;
        body.od = public_key_to_base64(sk.verifying_key().as_bytes());
        let raw_body = serde_json::to_vec(&body).expect("signal body serializes");
        let mut msg = signal_signing_prefix(protocol, kind);
        msg.extend_from_slice(&raw_body);
        let sig = sk.sign(&msg);
        Self {
            kind: kind.to_owned(),
            tijelo: raw_body,
            potpis: sig.to_bytes().to_vec(),
        }
    }

    pub fn parse_unverified_header(&self) -> Result<SignalBody, SignalError> {
        serde_json::from_slice(&self.tijelo).map_err(|e| SignalError::InvalidShape(e.to_string()))
    }
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: HashMap<String, i64>,
}

impl ReplayCache {
    pub fn record(
        &mut self,
        kind: &str,
        body: &SignalBody,
        now_unix: i64,
    ) -> Result<(), SignalError> {
        if self.seen.len() >= SIGNAL_REPLAY_CACHE_MAX {
            self.seen.retain(|_, exp| now_unix <= *exp);
        }
        let attempt = body.pokusaj.unwrap_or(0);
        let key = format!("{kind}|{}|{}|{attempt}", body.od, body.sesija);
        if self.seen.contains_key(&key) {
            return Err(SignalError::Replayed);
        }
        if self.seen.len() >= SIGNAL_REPLAY_CACHE_MAX {
            return Err(SignalError::ReplayCacheFull);
        }
        self.seen
            .insert(key, body.izdano + SIGNAL_MAX_SKEW_SECS + 60);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

pub fn verify_signed_signal<F>(
    protocol: &str,
    msg: &SignedSignalMessage,
    my_pub: &VerifyingKey,
    rendezvous_pub: &VerifyingKey,
    now_unix: i64,
    replay_cache: &mut ReplayCache,
    is_trusted: F,
) -> Result<SignalBody, SignalError>
where
    F: FnOnce(&VerifyingKey, Option<&[u8]>) -> bool,
{
    let body = msg.parse_unverified_header()?;
    let sender_vk = parse_public_key(&body.od).map_err(|_| SignalError::UnknownSender)?;

    // Verify signature strictly over the raw wire bytes of `tijelo`, never re-serialized!
    let mut signed = signal_signing_prefix(protocol, &msg.kind);
    signed.extend_from_slice(&msg.tijelo);
    let sig_arr: [u8; 64] = msg
        .potpis
        .clone()
        .try_into()
        .map_err(|_| SignalError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    sender_vk
        .verify(&signed, &sig)
        .map_err(|_| SignalError::BadSignature)?;

    if !is_trusted(&sender_vk, body.vj.as_deref()) {
        return Err(SignalError::UnknownSender);
    }

    if body.za != public_key_to_base64(my_pub.as_bytes()) {
        return Err(SignalError::WrongRecipient);
    }
    if body.sastajaliste != public_key_to_base64(rendezvous_pub.as_bytes()) {
        return Err(SignalError::WrongRendezvous);
    }
    if now_unix.abs_diff(body.izdano) > SIGNAL_MAX_SKEW_SECS as u64 {
        return Err(SignalError::ClockSkew);
    }

    let sess_bytes = hex::decode(&body.sesija)
        .map_err(|_| SignalError::InvalidShape("neispravna sesija".into()))?;
    let attempt = body.pokusaj.unwrap_or(0);
    let is_sinkro = msg.kind == SIGNAL_KIND_SINKRO;
    if body.ver != 1
        || !matches!(
            msg.kind.as_str(),
            SIGNAL_KIND_POZIV | SIGNAL_KIND_ODZIV | SIGNAL_KIND_SINKRO
        )
        || sess_bytes.len() != 16
        || is_sinkro != (attempt > 0)
        || attempt > SIGNAL_MAX_SINKRO_ATTEMPT
    {
        return Err(SignalError::InvalidShape(
            "neispravna inacica, sesija ili pokusaj".into(),
        ));
    }

    replay_cache.record(&msg.kind, &body, now_unix)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_signing_key;

    #[test]
    fn signal_verifies_raw_bytes_and_rejects_replay_and_wrong_target() {
        let sender = generate_signing_key();
        let target = generate_signing_key();
        let rendez = generate_signing_key();
        let mut cache = ReplayCache::default();

        let now = 1_760_000_000i64;
        let body = SignalBody {
            ver: 1,
            sesija: "00112233445566778899aabbccddeeff".to_owned(),
            od: String::new(),
            za: public_key_to_base64(target.verifying_key().as_bytes()),
            sastajaliste: public_key_to_base64(rendez.verifying_key().as_bytes()),
            izdano: now,
            tajna: Some(vec![0x42; 32]),
            kandidati: vec![],
            nat: None,
            odluka: None,
            razlog: None,
            obrada_ms: None,
            pokusaj: None,
            rtt_ms: None,
            vj: None,
        };

        let msg = SignedSignalMessage::sign(&sender, "list2cart", SIGNAL_KIND_POZIV, body);
        let parsed = verify_signed_signal(
            "list2cart",
            &msg,
            &target.verifying_key(),
            &rendez.verifying_key(),
            now + 5,
            &mut cache,
            |_, _| true,
        )
        .expect("valid signal");
        assert_eq!(parsed.tajna.as_deref(), Some([0x42u8; 32].as_slice()));

        // Replay must fail
        assert_eq!(
            verify_signed_signal(
                "list2cart",
                &msg,
                &target.verifying_key(),
                &rendez.verifying_key(),
                now + 6,
                &mut cache,
                |_, _| true,
            ),
            Err(SignalError::Replayed)
        );

        // Wrong recipient must fail
        let other = generate_signing_key();
        assert_eq!(
            verify_signed_signal(
                "list2cart",
                &msg,
                &other.verifying_key(),
                &rendez.verifying_key(),
                now + 6,
                &mut cache,
                |_, _| true,
            ),
            Err(SignalError::WrongRecipient)
        );
    }
}
