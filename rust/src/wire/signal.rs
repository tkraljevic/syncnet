use crate::identity::{parse_public_key_bytes, public_key_to_base64};
use crate::wire::go_bytes;
use crate::wire::go_json::to_go_json_vec;
use crate::wire::go_object::{Field, Kind, Schema, go_struct};
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
pub const SIGNAL_MAX_SINKRO_ATTEMPT: i64 = 3;

/// Strict base64 for the v2 bundle sketch, which has no Go counterpart yet. Signal fields
/// are read as Go reads them, through [`go_bytes`].
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

/// Address candidate in a signal body (`KandidatPoruke` in goCOP: `{"vrsta","adresa"}`).
/// Go always writes both fields, but reads a missing one (e.g. the old `{"kind","addr"}`
/// shape) as an empty string and takes the message, so Rust does too: a candidate with an
/// empty or bad address is for the caller to skip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct CandidateAddr {
    #[serde(default)]
    pub vrsta: String,
    #[serde(default)]
    pub adresa: String,
}

pub(crate) const CANDIDATE_SCHEMA: Schema = Schema {
    fields: &[Field::value("vrsta"), Field::value("adresa")],
    baseline: &[("vrsta", "\"\""), ("adresa", "\"\"")],
};
go_struct!(CandidateAddr, CANDIDATE_SCHEMA);

/// Sender's NAT report (`NATPoruke` in goCOP: `{"vrsta","udpBlokiran"}`, both omitted when empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct NatReport {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vrsta: String,
    #[serde(rename = "udpBlokiran", default, skip_serializing_if = "is_false")]
    pub udp_blokiran: bool,
}

pub(crate) const NAT_SCHEMA: Schema = Schema {
    fields: &[Field::value("vrsta"), Field::value("udpBlokiran")],
    baseline: &[],
};
go_struct!(NatReport, NAT_SCHEMA);

fn is_false(b: &bool) -> bool {
    !*b
}

// Go `omitempty` also drops zero numbers, empty strings and empty byte slices.
fn is_none_or_empty_bytes(v: &Option<Vec<u8>>) -> bool {
    v.as_ref().is_none_or(|b| b.is_empty())
}

fn is_none_or_empty_str(v: &Option<String>) -> bool {
    v.as_ref().is_none_or(|s| s.is_empty())
}

fn is_none_or_zero(v: &Option<i64>) -> bool {
    v.is_none_or(|n| n == 0)
}

/// Field names are read as Go reads them (see [`crate::wire::go_object`]): in any ASCII
/// case, and a field given twice counts the last time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase")]
pub struct SignalBody {
    /// Numbers are Go `int`, 64 bits on 64-bit platforms (a 32-bit Go build would already
    /// refuse values past 2^31 when it reads them): Go reads any of them, negative ones
    /// too, and only the checks after the signature say which it takes.
    ///
    /// Go reads a missing `ver` and a `null` one as 0 (`null` leaves a Go `int` as it is),
    /// so such a body is turned away by the shape check after the signature, as in Go, and
    /// not already when it is read. A `null` never reaches the derive: the Go reader
    /// ([`crate::wire::go_object`]) leaves it out, and a missing `ver` is 0.
    #[serde(default)]
    pub ver: i64,
    pub sesija: String,
    /// The sender's key as the message carries it. Several texts read to the same key
    /// (`\n` anywhere, extra bits in the last character, as in Go), so to compare, map,
    /// block or revoke by the sender use the key the check hands to `is_trusted`, or
    /// `public_key_to_base64` of the bytes this text reads to, never this text.
    pub od: String,
    pub za: String,
    pub sastajaliste: String,
    pub izdano: i64,
    #[serde(
        default,
        with = "go_bytes::opt",
        skip_serializing_if = "is_none_or_empty_bytes"
    )]
    pub tajna: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kandidati: Vec<CandidateAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<NatReport>,
    #[serde(default, skip_serializing_if = "is_none_or_empty_str")]
    pub odluka: Option<String>,
    #[serde(default, skip_serializing_if = "is_none_or_empty_str")]
    pub razlog: Option<String>,
    /// As sent, any `int`: nothing here limits it. Go clamps it only where it uses it, in
    /// hole punching: the time since the call is first held to 0 to 10 s (the answer
    /// deadline), then this value to 0 up to that time, and the RTT is the time less this.
    /// A negative value counts as 0, a value past the time as the whole time (RTT 0).
    #[serde(default, skip_serializing_if = "is_none_or_zero")]
    pub obrada_ms: Option<i64>,
    /// As sent, any `int`. Only the shape check limits it: 1 to 3 in `sinkro`, 0 or less in
    /// any other kind, so a negative one passes. Go uses a sinkro only when this is above
    /// the attempt in progress and not above the session's last attempt.
    #[serde(default, skip_serializing_if = "is_none_or_zero")]
    pub pokusaj: Option<i64>,
    /// As sent, any `int`: nothing here limits it. Go clamps it only where it uses it, in
    /// hole punching, to 0 up to 10 s: a negative value counts as 0, a larger one as 10 s.
    #[serde(default, skip_serializing_if = "is_none_or_zero")]
    pub rtt_ms: Option<i64>,
    #[serde(
        default,
        with = "go_bytes::opt",
        skip_serializing_if = "is_none_or_empty_bytes"
    )]
    pub vj: Option<Vec<u8>>,
}

pub(crate) const BODY_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("ver"),
        Field::value("sesija"),
        Field::value("od"),
        Field::value("za"),
        Field::value("sastajaliste"),
        Field::value("izdano"),
        Field::nullable("tajna"),
        Field::new("kandidati", Kind::StructSlice),
        Field::new("nat", Kind::Struct),
        Field::value("odluka"),
        Field::value("razlog"),
        Field::value("obradaMs"),
        Field::value("pokusaj"),
        Field::value("rttMs"),
        Field::nullable("vj"),
    ],
    baseline: &[
        ("ver", "1"),
        ("sesija", "\"\""),
        ("od", "\"\""),
        ("za", "\"\""),
        ("sastajaliste", "\"\""),
        ("izdano", "0"),
    ],
};
go_struct!(SignalBody, BODY_SCHEMA);

/// Read as Go reads the signed message: field names in any ASCII case, the last of a
/// repeated field, and a missing field as no bytes, which the checks then refuse as Go's
/// do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct SignedSignalMessage {
    #[serde(skip)]
    pub kind: String,
    #[serde(default, with = "go_bytes")]
    pub tijelo: Vec<u8>,
    #[serde(default, with = "go_bytes")]
    pub potpis: Vec<u8>,
}

pub(crate) const SIGNED_SCHEMA: Schema = Schema {
    fields: &[Field::nullable("tijelo"), Field::nullable("potpis")],
    baseline: &[],
};
go_struct!(SignedSignalMessage, SIGNED_SCHEMA);

pub fn signal_signing_prefix(protocol: &str, kind: &str) -> Vec<u8> {
    format!("{protocol}-{kind}-v1|").into_bytes()
}

impl SignedSignalMessage {
    pub fn sign(sk: &SigningKey, protocol: &str, kind: &str, mut body: SignalBody) -> Self {
        body.ver = 1;
        body.od = public_key_to_base64(sk.verifying_key().as_bytes());
        // Same bytes as Go `json.Marshal` (escapes `<`, `>`, `&`, U+2028, U+2029).
        let raw_body = to_go_json_vec(&body).expect("signal body serializes");
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
    // As in Go: a key that does not read is an unknown sender, one that reads but is not a
    // point a bad signature.
    let sender = parse_public_key_bytes(&body.od).map_err(|_| SignalError::UnknownSender)?;
    let sender_vk = VerifyingKey::from_bytes(&sender).map_err(|_| SignalError::BadSignature)?;

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
    // As in Go: `ver` from 1 up, so a later version still reads (PROTOKOL 8.4 lists no
    // other rule). A negative attempt outside sinkro passes as in Go. Go checks the kind
    // before this check, where it ignores a kind it does not know (PROTOKOL 8.4); Rust has
    // no such step in front, so it is checked here.
    if body.ver < 1
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

    #[test]
    fn candidates_and_nat_use_go_field_names() {
        // Field names and omitempty as in goCOP `KandidatPoruke` and `NATPoruke`.
        let go_body = r#"{"ver":1,"sesija":"00112233445566778899aabbccddeeff","od":"a","za":"b","sastajaliste":"c","izdano":1760000000,"kandidati":[{"vrsta":"javna","adresa":"203.0.113.7:4242"},{"vrsta":"lokalna","adresa":"192.168.1.20:4242"}],"nat":{"vrsta":"simetricni","udpBlokiran":true}}"#;
        let body: SignalBody = serde_json::from_str(go_body).expect("Go-shaped signal body");
        assert_eq!(
            body.kandidati,
            vec![
                CandidateAddr {
                    vrsta: "javna".into(),
                    adresa: "203.0.113.7:4242".into(),
                },
                CandidateAddr {
                    vrsta: "lokalna".into(),
                    adresa: "192.168.1.20:4242".into(),
                },
            ]
        );
        assert_eq!(
            body.nat,
            Some(NatReport {
                vrsta: "simetricni".into(),
                udp_blokiran: true,
            })
        );
        assert_eq!(serde_json::to_string(&body).unwrap(), go_body);

        let empty_nat = NatReport {
            vrsta: String::new(),
            udp_blokiran: false,
        };
        assert_eq!(serde_json::to_string(&empty_nat).unwrap(), "{}");
    }

    /// Go reads a candidate in the old `{"kind","addr"}` shape as one with empty fields
    /// and takes the message (measured in Go), so Rust reads it the same.
    #[test]
    fn candidate_without_go_fields_reads_empty() {
        let old_shape = r#"{"ver":1,"sesija":"00112233445566778899aabbccddeeff","od":"a","za":"b","sastajaliste":"c","izdano":1760000000,"kandidati":[{"kind":"javna","addr":"203.0.113.7:4242"}]}"#;
        let body: SignalBody = serde_json::from_str(old_shape).unwrap();
        assert_eq!(
            body.kandidati,
            vec![CandidateAddr {
                vrsta: String::new(),
                adresa: String::new(),
            }]
        );
    }

    #[test]
    fn signed_body_matches_go_marshal() {
        // Go `omitempty` drops 0, "" and empty []byte; Go escapes <, >, &, U+2028, U+2029.
        let sender = SigningKey::from_bytes(&[7u8; 32]);
        let body = SignalBody {
            ver: 1,
            sesija: "00112233445566778899aabbccddeeff".to_owned(),
            od: String::new(),
            za: "b".to_owned(),
            sastajaliste: "c".to_owned(),
            izdano: 1_760_000_000,
            tajna: Some(vec![]),
            kandidati: vec![],
            nat: None,
            odluka: Some("odbij".to_owned()),
            razlog: Some("<a> & b\u{2028}".to_owned()),
            obrada_ms: Some(0),
            pokusaj: Some(0),
            rtt_ms: Some(0),
            vj: Some(vec![]),
        };
        let msg = SignedSignalMessage::sign(&sender, "list2cart", SIGNAL_KIND_ODZIV, body);
        let od = public_key_to_base64(sender.verifying_key().as_bytes());
        let want = format!(
            r#"{{"ver":1,"sesija":"00112233445566778899aabbccddeeff","od":"{od}","za":"b","sastajaliste":"c","izdano":1760000000,"odluka":"odbij","razlog":"\u003ca\u003e \u0026 b\u2028"}}"#
        );
        assert_eq!(String::from_utf8(msg.tijelo.clone()).unwrap(), want);

        let parsed = msg.parse_unverified_header().unwrap();
        assert_eq!(parsed.razlog.as_deref(), Some("<a> & b\u{2028}"));
        assert_eq!(parsed.obrada_ms, None);

        let mut empty_odluka = parsed;
        empty_odluka.odluka = Some(String::new());
        empty_odluka.razlog = Some(String::new());
        let raw = String::from_utf8(to_go_json_vec(&empty_odluka).unwrap()).unwrap();
        assert!(!raw.contains("odluka") && !raw.contains("razlog"), "{raw}");
    }

    /// The sender's key in `od` is read as Go reads it: a key that does not read is an
    /// unknown sender, a key that reads but is not a point is a bad signature.
    #[test]
    fn sender_key_reads_as_in_go() {
        use crate::identity::key_edges::assert_edges_as_in_go;

        let me = SigningKey::from_bytes(&[3; 32]);
        let rendezvous = SigningKey::from_bytes(&[4; 32]);
        let at = 1_760_000_000i64;
        #[rustfmt::skip]
        let table = [
            ("ispravno", "prima", "prima"),
            ("prazno", "nepoznat", "nepoznat"),
            ("samo_razmak", "nepoznat", "nepoznat"),
            ("nije_base64", "nepoznat", "nepoznat"),
            ("31B", "nepoznat", "nepoznat"),
            ("33B", "nepoznat", "nepoznat"),
            ("bez_paddinga", "nepoznat", "nepoznat"),
            ("visak_paddinga", "nepoznat", "nepoznat"),
            ("razmak_ispred", "nepoznat", "prima"),
            ("razmak_iza", "nepoznat", "prima"),
            ("tab_iza", "nepoznat", "prima"),
            ("novi_red_ispred", "prima", "prima"),
            ("novi_red_iza", "prima", "prima"),
            ("crlf_iza", "prima", "prima"),
            ("novi_red_u_sredini", "prima", "nepoznat"),
            ("visak_bitova", "prima", "nepoznat"),
            ("url_safe", "nepoznat", "nepoznat"),
            ("url_safe_kanonski", "prima", "prima"),
            ("nije_tocka", "kriv:potpis", "nepoznat"),
            ("identitet", "prima", "prima"),
            ("identitet_nekanonski_y", "prima", "prima"),
            ("identitet_s_predznakom", "prima", "prima"),
            ("red2_R_identitet", "kriv:potpis", "kriv:potpis"),
            ("red2_R_tocka", "prima", "prima"),
        ];
        assert_edges_as_in_go(&table, |edge| {
            let body = SignalBody {
                ver: 1,
                sesija: "00112233445566778899aabbccddeeff".into(),
                od: edge.key.clone(),
                za: public_key_to_base64(me.verifying_key().as_bytes()),
                sastajaliste: public_key_to_base64(rendezvous.verifying_key().as_bytes()),
                izdano: at,
                tajna: None,
                kandidati: vec![],
                nat: None,
                odluka: None,
                razlog: None,
                obrada_ms: None,
                pokusaj: None,
                rtt_ms: None,
                vj: None,
            };
            let tijelo = to_go_json_vec(&body).unwrap();
            let mut signed = signal_signing_prefix("gocop", SIGNAL_KIND_POZIV);
            signed.extend_from_slice(&tijelo);
            let msg = SignedSignalMessage {
                kind: SIGNAL_KIND_POZIV.into(),
                potpis: edge.signer.sign(&signed).to_vec(),
                tijelo,
            };
            let got = verify_signed_signal(
                "gocop",
                &msg,
                &me.verifying_key(),
                &rendezvous.verifying_key(),
                at,
                &mut ReplayCache::default(),
                |_, _| true,
            );
            match got {
                Ok(_) => "prima".into(),
                Err(SignalError::UnknownSender) => "nepoznat".into(),
                Err(SignalError::BadSignature) => "kriv:potpis".into(),
                Err(e) => format!("drugo:{e}"),
            }
        });
    }

    /// The shape check after the signature, as the Go probe measured it on bodies written
    /// by hand: `ver` from 1 up, numbers as Go `int`, a missing or `null` `ver` turned away
    /// only after the signature. The Rust column is the check before: `ver` exactly 1 and
    /// numbers read as `u32`, so a body Go reads could fail already when it was read.
    #[test]
    fn body_shape_as_in_go() {
        let sender = SigningKey::from_bytes(&[1; 32]);
        let me = SigningKey::from_bytes(&[3; 32]);
        let rendezvous = SigningKey::from_bytes(&[4; 32]);
        let other = SigningKey::from_bytes(&[6; 32]);
        let at = 1_760_000_000i64;
        let b64 = |k: &SigningKey| public_key_to_base64(k.verifying_key().as_bytes());

        // (kind, `ver` first or none, fields after `izdano`, bad signature, other recipient)
        let case = |name: &str| -> (&'static str, Option<&'static str>, &'static str, bool, bool) {
            let p = SIGNAL_KIND_POZIV;
            let s = SIGNAL_KIND_SINKRO;
            match name {
                "ver_1" => (p, Some("1"), "", false, false),
                "ver_0" => (p, Some("0"), "", false, false),
                "ver_2" => (p, Some("2"), "", false, false),
                "ver_3" => (p, Some("3"), "", false, false),
                "ver_-1" => (p, Some("-1"), "", false, false),
                "ver_2^31" => (p, Some("2147483648"), "", false, false),
                "ver_2^32" => (p, Some("4294967296"), "", false, false),
                "ver_i64_max" => (p, Some("9223372036854775807"), "", false, false),
                "ver_i64_max+1" => (p, Some("9223372036854775808"), "", false, false),
                "ver_bez" => (p, None, "", false, false),
                "ver_null" => (p, Some("null"), "", false, false),
                "ver_tekst" => (p, Some("\"1\""), "", false, false),
                "ver_1.0" => (p, Some("1.0"), "", false, false),
                "ver_1e0" => (p, Some("1e0"), "", false, false),
                "ver_2_sinkro" => (s, Some("2"), r#","pokusaj":1"#, false, false),
                "ver_0_krivi_potpis" => (p, Some("0"), "", true, false),
                "ver_bez_krivi_potpis" => (p, None, "", true, false),
                "ver_null_krivi_potpis" => (p, Some("null"), "", true, false),
                "ver_-1_krivi_potpis" => (p, Some("-1"), "", true, false),
                "ver_2^32_drugi_za" => (p, Some("4294967296"), "", false, true),
                "ver_0_drugi_za" => (p, Some("0"), "", false, true),
                "poziv_pokusaj_-1" => (p, Some("1"), r#","pokusaj":-1"#, false, false),
                "poziv_pokusaj_0" => (p, Some("1"), r#","pokusaj":0"#, false, false),
                "poziv_pokusaj_1" => (p, Some("1"), r#","pokusaj":1"#, false, false),
                "poziv_pokusaj_-2^32" => (p, Some("1"), r#","pokusaj":-4294967296"#, false, false),
                "sinkro_pokusaj_bez" => (s, Some("1"), "", false, false),
                "sinkro_pokusaj_0" => (s, Some("1"), r#","pokusaj":0"#, false, false),
                "sinkro_pokusaj_-1" => (s, Some("1"), r#","pokusaj":-1"#, false, false),
                "sinkro_pokusaj_1" => (s, Some("1"), r#","pokusaj":1"#, false, false),
                "sinkro_pokusaj_3" => (s, Some("1"), r#","pokusaj":3"#, false, false),
                "sinkro_pokusaj_4" => (s, Some("1"), r#","pokusaj":4"#, false, false),
                "sinkro_pokusaj_2^32+1" => (s, Some("1"), r#","pokusaj":4294967297"#, false, false),
                "obradaMs_-1" => (
                    SIGNAL_KIND_ODZIV,
                    Some("1"),
                    r#","obradaMs":-1"#,
                    false,
                    false,
                ),
                "rttMs_-1" => (s, Some("1"), r#","pokusaj":1,"rttMs":-1"#, false, false),
                "vrsta_nepoznata" => ("nepoznata", Some("1"), "", false, false),
                "vrsta_Poziv" => ("Poziv", Some("1"), "", false, false),
                "vrsta_prazna" => ("", Some("1"), "", false, false),
                "poziv_Pokusaj_1" => (p, Some("1"), r#","Pokusaj":1"#, false, false),
                "poziv_POKUSAJ_1" => (p, Some("1"), r#","POKUSAJ":1"#, false, false),
                "sinkro_POKUSAJ_2" => (s, Some("1"), r#","POKUSAJ":2"#, false, false),
                "sinkro_Pokusaj_2" => (s, Some("1"), r#","Pokusaj":2"#, false, false),
                "sinkro_poKusaj_kelvin" => (s, Some("1"), r#","po\u212Ausaj":2"#, false, false),
                "sinkro_pokuSaj_dugo_s" => (s, Some("1"), r#","poku\u017Faj":2"#, false, false),
                "sinkro_pokusaj_razmak" => (s, Some("1"), r#","pokusaj ":2"#, false, false),
                "sinkro_pokusaj_tursko_i" => (
                    s,
                    Some("1"),
                    r#","pokusaj":2,"pok\u0131saj":9"#,
                    false,
                    false,
                ),
                "sinkro_pokusaj_1_pa_5" => {
                    (s, Some("1"), r#","pokusaj":1,"pokusaj":5"#, false, false)
                }
                "sinkro_pokusaj_5_pa_1" => {
                    (s, Some("1"), r#","pokusaj":5,"pokusaj":1"#, false, false)
                }
                "sinkro_pokusaj_tocno_pa_veliko" => {
                    (s, Some("1"), r#","pokusaj":2,"POKUSAJ":9"#, false, false)
                }
                "sinkro_veliko_pa_tocno" => {
                    (s, Some("1"), r#","POKUSAJ":9,"pokusaj":2"#, false, false)
                }
                "sinkro_pokusaj_2_pa_null" => {
                    (s, Some("1"), r#","pokusaj":2,"pokusaj":null"#, false, false)
                }
                "sinkro_pokusaj_null" => (s, Some("1"), r#","pokusaj":null"#, false, false),
                "sinkro_pokusaj_2_pa_tekst" => {
                    (s, Some("1"), r#","pokusaj":2,"pokusaj":"2""#, false, false)
                }
                "poziv_pokusaj_0_pa_Pokusaj_1" => {
                    (p, Some("1"), r#","pokusaj":0,"Pokusaj":1"#, false, false)
                }
                "poziv_Pokusaj_1_pa_pokusaj_0" => {
                    (p, Some("1"), r#","Pokusaj":1,"pokusaj":0"#, false, false)
                }
                "poziv_VER_0_iza" => (p, Some("1"), r#","VER":0"#, false, false),
                "poziv_ver_null_iza" => (p, Some("1"), r#","ver":null"#, false, false),
                "poziv_izdano_null_iza" => (p, Some("1"), r#","izdano":null"#, false, false),
                "poziv_Izdano_0_iza" => (p, Some("1"), r#","Izdano":0"#, false, false),
                "poziv_kandidati_null" => (p, Some("1"), r#","kandidati":null"#, false, false),
                "poziv_kandidati_pa_null" => (
                    p,
                    Some("1"),
                    r#","kandidati":[{"vrsta":"javna","adresa":"1.2.3.4:5"}],"Kandidati":null"#,
                    false,
                    false,
                ),
                "poziv_kandidati_bez_polja" => (
                    p,
                    Some("1"),
                    r#","kandidati":[{"vrsta":"javna"}]"#,
                    false,
                    false,
                ),
                "poziv_kandidati_broj" => (p, Some("1"), r#","kandidati":1"#, false, false),
                "poziv_nat_null" => (p, Some("1"), r#","nat":null"#, false, false),
                "poziv_NAT_objekt" => (
                    p,
                    Some("1"),
                    r#","NAT":{"VRSTA":"x","udpblokiran":true}"#,
                    false,
                    false,
                ),
                "poziv_obradaMs_null" => (p, Some("1"), r#","obradaMs":null"#, false, false),
                "poziv_OBRADAMS_tekst" => (p, Some("1"), r#","OBRADAMS":"1""#, false, false),
                "poziv_rttMs_null" => (p, Some("1"), r#","rttms":null"#, false, false),
                "poziv_tajna_null" => (p, Some("1"), r#","tajna":null"#, false, false),
                "poziv_Vj_null" => (p, Some("1"), r#","Vj":null"#, false, false),
                "poziv_odluka_null" => (p, Some("1"), r#","Odluka":null"#, false, false),
                "poziv_nepoznato" => (p, Some("1"), r#","nepoznato":{"a":[1,2]}"#, false, false),
                "poziv_nepoznato_null" => (p, Some("1"), r#","nepoznato":null"#, false, false),
                "poziv_prazno_ime" => (p, Some("1"), r#","":1"#, false, false),
                _ => panic!("no case {name}"),
            }
        };
        let message = |kind: &str, ver: Option<&str>, rest: &str, bad: bool, other_za: bool| {
            let za = if other_za { b64(&other) } else { b64(&me) };
            let ver = ver.map(|v| format!(r#""ver":{v},"#)).unwrap_or_default();
            let tijelo = format!(
                r#"{{{ver}"sesija":"00112233445566778899aabbccddeeff","od":"{}","za":"{za}","sastajaliste":"{}","izdano":{at}{rest}}}"#,
                b64(&sender),
                b64(&rendezvous),
            )
            .into_bytes();
            let mut signed = signal_signing_prefix("gocop", kind);
            signed.extend_from_slice(&tijelo);
            let mut potpis = sender.sign(&signed).to_bytes().to_vec();
            if bad {
                potpis[0] ^= 1;
            }
            SignedSignalMessage {
                kind: kind.into(),
                tijelo,
                potpis,
            }
        };
        let verdict = |r: Result<SignalBody, SignalError>| match r {
            Ok(_) => "prima".to_owned(),
            Err(SignalError::InvalidShape(_)) => "oblik".into(),
            Err(SignalError::BadSignature) => "potpis".into(),
            Err(SignalError::UnknownSender) => "nepoznat".into(),
            Err(SignalError::WrongRecipient) => "za".into(),
            Err(SignalError::WrongRendezvous) => "sastajaliste".into(),
            Err(SignalError::ClockSkew) => "vrijeme".into(),
            Err(SignalError::Replayed) => "ponovljena".into(),
            Err(SignalError::ReplayCacheFull) => "puna".into(),
        };
        let check = |msg: &SignedSignalMessage, cache: &mut ReplayCache| {
            verify_signed_signal(
                "gocop",
                msg,
                &me.verifying_key(),
                &rendezvous.verifying_key(),
                at,
                cache,
                |_, _| true,
            )
        };

        // Go checks the kind before this check and ignores a kind it does not know, so its
        // own check takes any kind (the probe: `prima`). Rust checks it here: `-`.
        #[rustfmt::skip]
        let table = [
            ("ver_1", "prima", "prima"),
            ("ver_0", "oblik", "oblik"),
            ("ver_2", "prima", "oblik"),
            ("ver_3", "prima", "oblik"),
            ("ver_-1", "oblik", "oblik"),
            ("ver_2^31", "prima", "oblik"),
            ("ver_2^32", "prima", "oblik"),
            ("ver_i64_max", "prima", "oblik"),
            ("ver_i64_max+1", "oblik", "oblik"),
            ("ver_bez", "oblik", "oblik"),
            ("ver_null", "oblik", "oblik"),
            ("ver_tekst", "oblik", "oblik"),
            ("ver_1.0", "oblik", "oblik"),
            ("ver_1e0", "oblik", "oblik"),
            ("ver_2_sinkro", "prima", "oblik"),
            ("ver_0_krivi_potpis", "potpis", "potpis"),
            ("ver_bez_krivi_potpis", "potpis", "oblik"),
            ("ver_null_krivi_potpis", "potpis", "oblik"),
            ("ver_-1_krivi_potpis", "potpis", "oblik"),
            ("ver_2^32_drugi_za", "za", "oblik"),
            ("ver_0_drugi_za", "za", "za"),
            ("poziv_pokusaj_-1", "prima", "oblik"),
            ("poziv_pokusaj_0", "prima", "prima"),
            ("poziv_pokusaj_1", "oblik", "oblik"),
            ("poziv_pokusaj_-2^32", "prima", "oblik"),
            ("sinkro_pokusaj_bez", "oblik", "oblik"),
            ("sinkro_pokusaj_0", "oblik", "oblik"),
            ("sinkro_pokusaj_-1", "oblik", "oblik"),
            ("sinkro_pokusaj_1", "prima", "prima"),
            ("sinkro_pokusaj_3", "prima", "prima"),
            ("sinkro_pokusaj_4", "oblik", "oblik"),
            ("sinkro_pokusaj_2^32+1", "oblik", "oblik"),
            ("obradaMs_-1", "prima", "oblik"),
            ("rttMs_-1", "prima", "oblik"),
            ("vrsta_nepoznata", "-", "oblik"),
            ("vrsta_Poziv", "-", "oblik"),
            ("vrsta_prazna", "-", "oblik"),
            // Field names, repeats, `null` and unknown fields, measured on the same bodies
            // through the Go side's whole check. The Rust column here is from before the
            // body's field names were read as in Go.
            ("poziv_Pokusaj_1", "oblik", "prima"),
            ("poziv_POKUSAJ_1", "oblik", "prima"),
            ("sinkro_POKUSAJ_2", "prima", "oblik"),
            ("sinkro_Pokusaj_2", "prima", "oblik"),
            ("sinkro_poKusaj_kelvin", "prima", "oblik"),
            ("sinkro_pokuSaj_dugo_s", "prima", "oblik"),
            ("sinkro_pokusaj_razmak", "oblik", "oblik"),
            ("sinkro_pokusaj_tursko_i", "prima", "prima"),
            ("sinkro_pokusaj_1_pa_5", "oblik", "oblik"),
            ("sinkro_pokusaj_5_pa_1", "prima", "oblik"),
            ("sinkro_pokusaj_tocno_pa_veliko", "oblik", "prima"),
            ("sinkro_veliko_pa_tocno", "prima", "prima"),
            ("sinkro_pokusaj_2_pa_null", "prima", "oblik"),
            ("sinkro_pokusaj_null", "oblik", "oblik"),
            ("sinkro_pokusaj_2_pa_tekst", "oblik", "oblik"),
            ("poziv_pokusaj_0_pa_Pokusaj_1", "oblik", "prima"),
            ("poziv_Pokusaj_1_pa_pokusaj_0", "prima", "prima"),
            ("poziv_VER_0_iza", "oblik", "prima"),
            ("poziv_ver_null_iza", "prima", "oblik"),
            ("poziv_izdano_null_iza", "prima", "oblik"),
            ("poziv_Izdano_0_iza", "vrijeme", "prima"),
            ("poziv_kandidati_null", "prima", "oblik"),
            ("poziv_kandidati_pa_null", "prima", "prima"),
            ("poziv_kandidati_bez_polja", "prima", "oblik"),
            ("poziv_kandidati_broj", "oblik", "oblik"),
            ("poziv_nat_null", "prima", "prima"),
            ("poziv_NAT_objekt", "prima", "prima"),
            ("poziv_obradaMs_null", "prima", "prima"),
            ("poziv_OBRADAMS_tekst", "oblik", "prima"),
            ("poziv_rttMs_null", "prima", "prima"),
            ("poziv_tajna_null", "prima", "prima"),
            ("poziv_Vj_null", "prima", "prima"),
            ("poziv_odluka_null", "prima", "prima"),
            ("poziv_nepoznato", "prima", "prima"),
            ("poziv_nepoznato_null", "prima", "prima"),
            ("poziv_prazno_ime", "prima", "prima"),
        ];
        crate::go_table::assert_rows_as_in_go(&table, |name| {
            let (kind, ver, rest, bad, other_za) = case(name);
            let got = verdict(check(
                &message(kind, ver, rest, bad, other_za),
                &mut ReplayCache::default(),
            ));
            if name.starts_with("vrsta_") {
                assert_eq!(
                    got, "oblik",
                    "{name}: Rust turns away a kind it does not know"
                );
            }
            got
        });

        // Go keys the replay cache by the attempt as written: 0 and -1 are two messages.
        let mut cache = ReplayCache::default();
        let first = verdict(check(
            &message(
                SIGNAL_KIND_POZIV,
                Some("1"),
                r#","pokusaj":0"#,
                false,
                false,
            ),
            &mut cache,
        ));
        let second = verdict(check(
            &message(
                SIGNAL_KIND_POZIV,
                Some("1"),
                r#","pokusaj":-1"#,
                false,
                false,
            ),
            &mut cache,
        ));
        assert_eq!((first.as_str(), second.as_str()), ("prima", "prima"));
    }

    /// The signed message as it comes off the wire, with `potpis`, `tijelo`, `tajna` and
    /// `vj` written in shapes that Go's `encoding/json` reads into the same bytes (see the
    /// table in `wire::go_bytes`, measured in Go): base64 with a line break, extra bits in
    /// the last character, or an array of numbers. Each must verify as the plain message
    /// does; a shape Go refuses must not.
    #[test]
    fn signal_fields_read_as_go_reads_bytes() {
        let sender = SigningKey::from_bytes(&[5; 32]);
        let me = SigningKey::from_bytes(&[6; 32]);
        let rendezvous = SigningKey::from_bytes(&[7; 32]);
        let at = 1_760_000_000i64;
        let body = SignalBody {
            ver: 1,
            sesija: "00112233445566778899aabbccddeeff".into(),
            od: public_key_to_base64(sender.verifying_key().as_bytes()),
            za: public_key_to_base64(me.verifying_key().as_bytes()),
            sastajaliste: public_key_to_base64(rendezvous.verifying_key().as_bytes()),
            izdano: at,
            tajna: Some(vec![0x42; 32]),
            kandidati: vec![],
            nat: None,
            odluka: None,
            razlog: None,
            obrada_ms: None,
            pokusaj: None,
            rtt_ms: None,
            vj: Some(vec![1, 2, 3]),
        };
        let plain = String::from_utf8(to_go_json_vec(&body).unwrap()).unwrap();
        let tajna = STANDARD.encode([0x42u8; 32]);
        let tijela = [
            plain.clone(),
            plain.replace(&tajna, &format!("{}\\n{}", &tajna[..20], &tajna[20..])),
            plain.replace(r#""vj":"AQID""#, r#""vj":[1,2,3]"#),
            plain.replace(
                &format!(r#""{tajna}""#),
                &format!("{:?}", [0x42u8; 32]).replace(' ', ""),
            ),
        ];
        for (i, tijelo) in tijela.iter().enumerate() {
            assert_eq!(i == 0, *tijelo == plain, "{tijelo}");
            let mut signed = signal_signing_prefix("gocop", SIGNAL_KIND_POZIV);
            signed.extend_from_slice(tijelo.as_bytes());
            let potpis = STANDARD.encode(sender.sign(&signed).to_bytes());
            let tijelo_b64 = STANDARD.encode(tijelo.as_bytes());
            // The last character of a 64-byte signature carries 2 bits and 4 extra ones.
            let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let last = alphabet.find(potpis.as_bytes()[85] as char).unwrap();
            let loose = alphabet.as_bytes()[last ^ 0b1111] as char;
            let bytes_arr = |b: &[u8]| format!("{b:?}").replace(' ', "");
            let raw_sig = sender.sign(&signed).to_bytes();
            let cases = [
                (tijelo_b64.clone(), potpis.clone(), true),
                (
                    tijelo_b64.clone(),
                    format!("{}\\r\\n{}", &potpis[..76], &potpis[76..]),
                    true,
                ),
                (
                    tijelo_b64.clone(),
                    format!("{}{loose}==", &potpis[..85]),
                    true,
                ),
                (
                    format!("{}\\n{}", &tijelo_b64[..10], &tijelo_b64[10..]),
                    potpis.clone(),
                    true,
                ),
                (
                    tijelo_b64.clone(),
                    potpis.trim_end_matches('=').to_owned(),
                    false,
                ),
                (format!(" {tijelo_b64}"), potpis.clone(), false),
            ];
            let mut wires: Vec<(String, bool)> = cases
                .iter()
                .map(|(t, p, ok)| (format!(r#"{{"tijelo":"{t}","potpis":"{p}"}}"#), *ok))
                .collect();
            wires.push((
                format!(
                    r#"{{"tijelo":"{tijelo_b64}","potpis":{}}}"#,
                    bytes_arr(&raw_sig)
                ),
                true,
            ));
            wires.push((
                format!(
                    r#"{{"tijelo":{},"potpis":"{potpis}"}}"#,
                    bytes_arr(tijelo.as_bytes())
                ),
                true,
            ));
            for (wire, go_takes) in wires {
                let msg = serde_json::from_str::<SignedSignalMessage>(&wire).map(|mut m| {
                    m.kind = SIGNAL_KIND_POZIV.into();
                    m
                });
                let got = msg.ok().and_then(|m| {
                    verify_signed_signal(
                        "gocop",
                        &m,
                        &me.verifying_key(),
                        &rendezvous.verifying_key(),
                        at,
                        &mut ReplayCache::default(),
                        |_, _| true,
                    )
                    .ok()
                });
                assert_eq!(got.is_some(), go_takes, "{wire}");
                if let Some(read) = got {
                    assert_eq!(
                        read.tajna.as_deref(),
                        Some([0x42u8; 32].as_slice()),
                        "{wire}"
                    );
                    assert_eq!(read.vj.as_deref(), Some([1u8, 2, 3].as_slice()), "{wire}");
                }
            }
        }
    }
}
