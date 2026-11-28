//! The author's signature over a version, byte for byte as the Go implementation makes it.
//!
//! The computer that writes a version into the ledger signs it with its key; whoever
//! receives the version checks that this key wrote it and that nothing in it was changed
//! on the way.
//!
//! Signed are the tag `<protocol>-verzija-v1|` and the JSON of these fields, in this order:
//! `version_id`, `entity`, `entity_id`, `node_id`, `supersedes`, `archived`, `channel`,
//! `schema_version`, `created_at` (Unix seconds), `kljuc_autora` (base64) and `sadrzaj`
//! (hex SHA-256).
//!
//! The payload is not signed as it stands but as a digest of the shape it has on the wire:
//! compact, with `<`, `>`, `&`, U+2028 and U+2029 escaped. The same record therefore gives
//! the same digest whether it was stored with spaces or without. `created_at` is signed in
//! seconds, because the part below a second does not survive every path.
//!
//! This shape does not change: versions already signed with it would stop verifying.
//!
//! The signature says only that this key signed the version. Whether the key may write
//! under the name in `node_id` is for the receiver to decide.
//!
//! A version with neither `potpis` nor `kljuc_autora` is unsigned. One with either of
//! them passes only when the signature holds under that key: a wrong signature, or only
//! one of the two fields, never does. Both fields are read as Go reads base64
//! (`wire::go_base64`), so the two sides take and refuse the same texts.

use crate::identity::{parse_public_key_bytes, public_key_to_base64};
use crate::wire::conversation_v1::VersionV1;
use crate::wire::go_base64::decode_std;
use crate::wire::go_json::{go_raw_json_vec, to_go_json_vec};
use crate::wire::go_time;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

/// What of a version the signature covers, as the values stand in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionData<'a> {
    pub version_id: &'a str,
    pub entity: &'a str,
    pub entity_id: &'a str,
    pub node_id: &'a str,
    pub supersedes: &'a str,
    pub archived: bool,
    /// Empty for the channel everyone holds.
    pub channel: &'a str,
    pub schema_version: i64,
    pub created_at_unix: i64,
    /// The payload as JSON text, in any spacing.
    pub payload: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSignatureError {
    /// The payload is not one JSON value, so it has no wire shape to sign.
    PayloadNotJson,
    /// The author's key is not 32 bytes of base64. A key of the right length that is not
    /// a point of the curve is a bad signature, as in Go.
    BadAuthorKey,
    /// The signature is not valid for this version under the author's key.
    BadSignature,
    /// The version carries neither a signature nor an author's key.
    Unsigned,
    /// The time of a version from the wire is not an RFC 3339 timestamp.
    BadCreatedAt,
}

impl fmt::Display for VersionSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PayloadNotJson => "version payload is not JSON",
            Self::BadAuthorKey => "version author key is invalid",
            Self::BadSignature => "version signature is invalid",
            Self::Unsigned => "version is not signed",
            Self::BadCreatedAt => "version time is invalid",
        })
    }
}

impl std::error::Error for VersionSignatureError {}

/// The canonical shape that is signed; the field order is the wire.
#[derive(Serialize)]
struct SignedVersion<'a> {
    version_id: &'a str,
    entity: &'a str,
    entity_id: &'a str,
    node_id: &'a str,
    supersedes: &'a str,
    archived: bool,
    channel: &'a str,
    schema_version: i64,
    created_at: i64,
    kljuc_autora: &'a str,
    sadrzaj: &'a str,
}

/// The tag in front of the signed bytes; a signature from a network with another protocol
/// name does not verify here.
pub fn version_signing_prefix(protocol: &str) -> String {
    format!("{protocol}-verzija-v1|")
}

/// Hex SHA-256 of the payload in the shape it has on the wire.
pub fn payload_digest(payload: &str) -> Result<String, VersionSignatureError> {
    let wire = go_raw_json_vec(payload).map_err(|_| VersionSignatureError::PayloadNotJson)?;
    Ok(hex::encode(Sha256::digest(wire)))
}

/// The bytes the author signs: the tag with the protocol name and the canonical shape of
/// the version with the author's key.
pub fn version_signing_bytes(
    protocol: &str,
    v: &VersionData<'_>,
    author_key: &str,
) -> Result<Vec<u8>, VersionSignatureError> {
    let digest = payload_digest(v.payload)?;
    let mut bytes = version_signing_prefix(protocol).into_bytes();
    bytes.extend(
        to_go_json_vec(&SignedVersion {
            version_id: v.version_id,
            entity: v.entity,
            entity_id: v.entity_id,
            node_id: v.node_id,
            supersedes: v.supersedes,
            archived: v.archived,
            channel: v.channel,
            schema_version: v.schema_version,
            created_at: v.created_at_unix,
            kljuc_autora: author_key,
            sadrzaj: &digest,
        })
        .expect("text, numbers and booleans always serialize"),
    );
    Ok(bytes)
}

/// Signs a version with the author's key. Returns the signature and the public key, both
/// base64, as they are stored with the version and sent on the wire.
pub fn sign_version(
    author: &SigningKey,
    protocol: &str,
    v: &VersionData<'_>,
) -> Result<(String, String), VersionSignatureError> {
    let author_key = public_key_to_base64(author.verifying_key().as_bytes());
    let bytes = version_signing_bytes(protocol, v, &author_key)?;
    Ok((STANDARD.encode(author.sign(&bytes).to_bytes()), author_key))
}

/// Says whether the signature of a version holds under the author's key that stands with it.
///
/// The checks go in Go's order: the key must be 32 bytes of base64, the payload JSON, and
/// then the signature must hold. A key of 32 bytes that is not a point of the curve, and a
/// signature that is not 64 bytes, are both a bad signature.
pub fn verify_version_signature(
    protocol: &str,
    v: &VersionData<'_>,
    signature: &str,
    author_key: &str,
) -> Result<(), VersionSignatureError> {
    let key =
        parse_public_key_bytes(author_key).map_err(|_| VersionSignatureError::BadAuthorKey)?;
    let bytes = version_signing_bytes(protocol, v, author_key)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| VersionSignatureError::BadSignature)?;
    let signature = decode_std(signature)
        .ok()
        .and_then(|raw| Signature::from_slice(&raw).ok())
        .ok_or(VersionSignatureError::BadSignature)?;
    key.verify(&bytes, &signature)
        .map_err(|_| VersionSignatureError::BadSignature)
}

/// The time of a version as Go reads its `created_at` (a `time.Time`, see
/// [`go_time`]): the text is already unescaped, as Go unescapes it first. Where Go fails
/// to read the time it turns the version away, so here it is [`BadCreatedAt`]. The
/// signature covers whole seconds, so a part of a second does not count.
///
/// [`BadCreatedAt`]: VersionSignatureError::BadCreatedAt
fn created_at_unix(text: &str) -> Result<i64, VersionSignatureError> {
    go_time::parse(text.as_bytes())
        .map(|t| t.unix)
        .ok_or(VersionSignatureError::BadCreatedAt)
}

/// Checks the author's signature of a version as it came in a conversation.
///
/// `Unsigned` only when both `potpis` and `kljuc_autora` are empty; with either of them the
/// signature must hold.
pub fn verify_version_v1(protocol: &str, version: &VersionV1) -> Result<(), VersionSignatureError> {
    if version.potpis.is_empty() && version.kljuc_autora.is_empty() {
        return Err(VersionSignatureError::Unsigned);
    }
    let data = VersionData {
        version_id: &version.version_id,
        entity: &version.entity,
        entity_id: &version.entity_id,
        node_id: &version.node_id,
        supersedes: &version.supersedes,
        archived: version.archived,
        channel: version.channel.as_deref().unwrap_or(""),
        schema_version: i64::from(version.schema_version),
        created_at_unix: created_at_unix(&version.created_at)?,
        payload: version.payload.get(),
    };
    verify_version_signature(protocol, &data, &version.potpis, &version.kljuc_autora)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::conversation_v1::{DeltaPayload, EnvelopeV1, KIND_V1_DELTA};
    use crate::wire::go_json::to_go_json_string;
    use serde_json::Value;

    fn wire_vectors() -> Value {
        serde_json::from_str(include_str!("../../../vektori/vektori-zice.json")).unwrap()
    }

    fn author(v: &Value) -> SigningKey {
        let seed: [u8; 32] = hex::decode(v["ulaz"]["sjemeA"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn version_signature_vectors_match_byte_for_byte() {
        let v = wire_vectors();
        let protocol = v["ulaz"]["protokol"].as_str().unwrap();
        let author = author(&v);

        for name in ["obicna", "posebniZnakovi"] {
            let vector = &v["potpisVerzije"][name];
            let text = |field: &str| vector[field].as_str().unwrap();
            let input = |field: &str| vector["ulaz"][field].as_str().unwrap();
            let data = VersionData {
                version_id: input("version_id"),
                entity: input("entity"),
                entity_id: input("entity_id"),
                node_id: input("node_id"),
                supersedes: input("supersedes"),
                archived: vector["ulaz"]["archived"].as_bool().unwrap(),
                channel: input("channel"),
                schema_version: vector["ulaz"]["schema_version"].as_i64().unwrap(),
                created_at_unix: created_at_unix(input("created_at")).unwrap(),
                payload: input("payload"),
            };

            assert_eq!(
                String::from_utf8(go_raw_json_vec(data.payload).unwrap()).unwrap(),
                text("oblikSadrzaja"),
                "{name}"
            );
            assert_eq!(
                payload_digest(data.payload).unwrap(),
                text("sadrzaj"),
                "{name}"
            );
            assert_eq!(
                String::from_utf8(
                    version_signing_bytes(protocol, &data, text("kljucAutora")).unwrap()
                )
                .unwrap(),
                text("bajtovi"),
                "{name}"
            );

            let (signature, author_key) = sign_version(&author, protocol, &data).unwrap();
            assert_eq!(signature, text("potpis"), "{name}");
            assert_eq!(author_key, text("kljucAutora"), "{name}");
            verify_version_signature(protocol, &data, text("potpis"), text("kljucAutora"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));

            // Every covered value is bound: a change in any of them breaks the signature.
            let other_id = format!("{}x", data.entity_id);
            for changed in [
                VersionData {
                    archived: !data.archived,
                    ..data
                },
                VersionData {
                    entity_id: &other_id,
                    ..data
                },
                VersionData {
                    created_at_unix: data.created_at_unix + 1,
                    ..data
                },
                VersionData {
                    payload: r#"{"drugo":1}"#,
                    ..data
                },
            ] {
                assert_eq!(
                    verify_version_signature(protocol, &changed, &signature, &author_key),
                    Err(VersionSignatureError::BadSignature),
                    "{name}"
                );
            }
            assert_eq!(
                verify_version_signature("drugi", &data, &signature, &author_key),
                Err(VersionSignatureError::BadSignature),
                "{name}: a signature from another protocol"
            );
        }
    }

    #[test]
    fn the_same_payload_signs_the_same_in_any_spacing() {
        let spaced = "{ \"a\" : [ 1 , \"b c\" ] ,\n\t\"d\" : \"<\u{2028}>\" }";
        let compact = r#"{"a":[1,"b c"],"d":"\u003c\u2028\u003e"}"#;
        assert_eq!(
            String::from_utf8(go_raw_json_vec(spaced).unwrap()).unwrap(),
            compact
        );
        assert_eq!(payload_digest(spaced), payload_digest(compact));

        for not_json in ["", "{", "{} {}", "nije json"] {
            assert_eq!(
                payload_digest(not_json),
                Err(VersionSignatureError::PayloadNotJson),
                "{not_json:?}"
            );
        }
    }

    /// The version the edge cases sign: the plain one from the shared vectors.
    fn edge_version(potpis: &str, kljuc_autora: &str) -> VersionV1 {
        VersionV1 {
            version_id: "019a2b3c-4d5e-7f00-8000-000000000001".into(),
            entity: "users".into(),
            entity_id: "korisnik-1".into(),
            node_id: "admin-1".into(),
            supersedes: String::new(),
            archived: false,
            payload: serde_json::value::RawValue::from_string(
                r#"{"full_name":"Ana Horvat","username":"ahorvat"}"#.to_owned(),
            )
            .unwrap(),
            created_at: "2025-10-09T08:53:20Z".into(),
            schema_version: 1,
            channel: None,
            potpis: potpis.to_owned(),
            kljuc_autora: kljuc_autora.to_owned(),
        }
    }

    /// Signs the edge version over whatever text stands in `kljuc_autora`.
    fn sign_edge_over(author: &SigningKey, kljuc_autora: &str) -> String {
        let version = edge_version("", kljuc_autora);
        let data = VersionData {
            version_id: &version.version_id,
            entity: &version.entity,
            entity_id: &version.entity_id,
            node_id: &version.node_id,
            supersedes: &version.supersedes,
            archived: version.archived,
            channel: "",
            schema_version: 1,
            created_at_unix: 1_760_000_000,
            payload: version.payload.get(),
        };
        let bytes = version_signing_bytes("gocop", &data, kljuc_autora).unwrap();
        STANDARD.encode(author.sign(&bytes).to_bytes())
    }

    /// What the receiver makes of a version, in the words of the Go probe.
    fn edge_outcome(potpis: &str, kljuc_autora: &str) -> &'static str {
        match verify_version_v1("gocop", &edge_version(potpis, kljuc_autora)) {
            Ok(()) => "vrijedi",
            Err(VersionSignatureError::Unsigned) => "nepotpisana",
            Err(VersionSignatureError::BadAuthorKey) => "kriv:kljuc",
            Err(VersionSignatureError::BadSignature) => "kriv:potpis",
            Err(e) => panic!("{e}"),
        }
    }

    /// Flips the lowest bit of the last character before the padding: the bytes stay the
    /// same, the text is no longer the canonical one.
    fn with_trailing_bit(text: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let data = text.trim_end_matches('=');
        let last = data.len() - 1;
        let c = ALPHABET
            .iter()
            .position(|&a| a == data.as_bytes()[last])
            .unwrap();
        format!(
            "{}{}{}",
            &data[..last],
            ALPHABET[c ^ 1] as char,
            &text[data.len()..]
        )
    }

    fn url_safe(text: &str) -> String {
        text.replace('+', "-").replace('/', "_")
    }

    /// Every edge of the signature and the author's key ends as in Go. The expected
    /// outcomes come from Go's own check of the version signature, behind the receiver's
    /// rule that a version with neither field is unsigned, run over the same inputs.
    #[test]
    fn signature_edges_end_as_in_go() {
        let author = SigningKey::from_bytes(&[1; 32]);
        let k = public_key_to_base64(author.verifying_key().as_bytes());
        let s = sign_edge_over(&author, &k);
        // The same strings Go prints for this seed and version.
        assert_eq!(k, "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=");
        assert_eq!(
            s,
            "EJz/fA0DxfGJvduZ70r2R2IFnZhv9oyEZ4Vq/W7Od/s1ePCelqT+iuS8eunLJKA+MSJ4K7naQGBJvLE67OBjBQ=="
        );
        let key_raw = STANDARD.decode(&k).unwrap();
        let sig_raw = STANDARD.decode(&s).unwrap();
        let over = |key: &str| sign_edge_over(&author, key);

        // A key with + and / in it, for the URL-safe alphabet.
        let other = SigningKey::from_bytes(&[2; 32]);
        let k2 = public_key_to_base64(other.verifying_key().as_bytes());
        assert_eq!(k2, "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=");

        // The identity point in three encodings; R = identity, s = 0 holds under it for
        // any message, in Go as here (neither side refuses small-order keys).
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut identity_y_plus_p = [0xffu8; 32];
        identity_y_plus_p[0] = 0xee;
        identity_y_plus_p[31] = 0x7f;
        let mut identity_signed = identity;
        identity_signed[31] = 0x80;
        let sig_identity = STANDARD.encode([&identity[..], &[0u8; 32]].concat());

        // y = 2 is not a point of the curve.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        let k_not_a_point = STANDARD.encode(not_a_point);

        // s + L: the same signature with a scalar that is not reduced.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut sig_s_plus_l = sig_raw.clone();
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(sig_raw[32 + i]) + u16::from(L[i]) + carry;
            sig_s_plus_l[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        let mut sig_high_bit = sig_raw.clone();
        sig_high_bit[63] |= 0x80;

        let k31 = STANDARD.encode(&key_raw[..31]);
        let k33 = STANDARD.encode([&key_raw[..], &[0]].concat());
        let k_unpadded = k.trim_end_matches('=').to_owned();
        let k_extra_pad = format!("{k}=");
        let k_space_before = format!(" {k}");
        let k_space_after = format!("{k} ");
        let k_tab_after = format!("{k}\t");
        let k_lf_after = format!("{k}\n");
        let k_crlf_after = format!("{k}\r\n");
        let k_lf_inside = format!("{}\n{}", &k[..20], &k[20..]);
        let k_trailing_bit = with_trailing_bit(&k);
        let k2_url = url_safe(&k2);

        // (case, potpis, kljuc_autora, Go, Rust before this change). The last column is a
        // record only: the loop does not read it, it shows where Rust used to differ.
        #[rustfmt::skip]
        let cases: Vec<(&str, String, String, &str, &str)> = vec![
            ("oba_prazna", "".into(), "".into(), "nepotpisana", "nepotpisana"),
            ("samo_kljuc", "".into(), k.clone(), "kriv:potpis", "nepotpisana"),
            ("samo_potpis", s.clone(), "".into(), "kriv:kljuc", "kriv:kljuc"),
            ("ispravno", s.clone(), k.clone(), "vrijedi", "vrijedi"),
            ("kljuc_razmak_bez_potpisa", "".into(), " ".into(), "kriv:kljuc", "nepotpisana"),
            ("kljuc_novi_red_bez_potpisa", "".into(), "\n".into(), "kriv:kljuc", "nepotpisana"),
            ("potpis_novi_red_bez_kljuca", "\n".into(), "".into(), "kriv:kljuc", "kriv:kljuc"),
            ("kljuc_nije_base64", s.clone(), "nije kljuc".into(), "kriv:kljuc", "kriv:kljuc"),
            ("kljuc_31B", over(&k31), k31.clone(), "kriv:kljuc", "kriv:kljuc"),
            ("kljuc_33B", over(&k33), k33.clone(), "kriv:kljuc", "kriv:kljuc"),
            ("kljuc_bez_paddinga", over(&k_unpadded), k_unpadded.clone(), "kriv:kljuc", "kriv:kljuc"),
            ("kljuc_visak_paddinga", over(&k_extra_pad), k_extra_pad.clone(), "kriv:kljuc", "kriv:kljuc"),
            ("kljuc_razmak_ispred", over(&k_space_before), k_space_before.clone(), "kriv:kljuc", "vrijedi"),
            ("kljuc_razmak_iza", over(&k_space_after), k_space_after.clone(), "kriv:kljuc", "vrijedi"),
            ("kljuc_tab_iza", over(&k_tab_after), k_tab_after.clone(), "kriv:kljuc", "vrijedi"),
            ("kljuc_novi_red_iza", over(&k_lf_after), k_lf_after.clone(), "vrijedi", "vrijedi"),
            ("kljuc_crlf_iza", over(&k_crlf_after), k_crlf_after.clone(), "vrijedi", "vrijedi"),
            ("kljuc_novi_red_u_sredini", over(&k_lf_inside), k_lf_inside.clone(), "vrijedi", "kriv:kljuc"),
            ("kljuc_novi_red_sam_stari_potpis", s.clone(), k_lf_after.clone(), "kriv:potpis", "kriv:potpis"),
            ("kljuc_visak_bitova", over(&k_trailing_bit), k_trailing_bit.clone(), "vrijedi", "kriv:kljuc"),
            ("kljuc_visak_bitova_stari_potpis", s.clone(), k_trailing_bit.clone(), "kriv:potpis", "kriv:kljuc"),
            ("kljuc_url_safe", sign_edge_over(&other, &k2_url), k2_url.clone(), "kriv:kljuc", "kriv:kljuc"),
            ("kljuc_url_safe_kanonski", sign_edge_over(&other, &k2), k2.clone(), "vrijedi", "vrijedi"),
            ("kljuc_nije_tocka", over(&k_not_a_point), k_not_a_point.clone(), "kriv:potpis", "kriv:kljuc"),
            ("kljuc_identitet", sig_identity.clone(), STANDARD.encode(identity), "vrijedi", "vrijedi"),
            ("kljuc_identitet_nekanonski_y", sig_identity.clone(), STANDARD.encode(identity_y_plus_p), "vrijedi", "vrijedi"),
            ("kljuc_identitet_s_predznakom", sig_identity.clone(), STANDARD.encode(identity_signed), "vrijedi", "vrijedi"),
            ("potpis_nije_base64", "nije potpis".into(), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_razmak", " ".into(), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_63B", STANDARD.encode(&sig_raw[..63]), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_65B", STANDARD.encode([&sig_raw[..], &[0]].concat()), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_bez_paddinga", s.trim_end_matches('=').into(), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_visak_paddinga", format!("{s}="), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_razmak_ispred", format!(" {s}"), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_razmak_iza", format!("{s} "), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_novi_red_iza", format!("{s}\n"), k.clone(), "vrijedi", "kriv:potpis"),
            ("potpis_crlf_iza", format!("{s}\r\n"), k.clone(), "vrijedi", "kriv:potpis"),
            ("potpis_novi_red_u_sredini", format!("{}\n{}", &s[..30], &s[30..]), k.clone(), "vrijedi", "kriv:potpis"),
            ("potpis_novi_red_u_paddingu", format!("{}\n=", &s[..s.len() - 1]), k.clone(), "vrijedi", "kriv:potpis"),
            ("potpis_visak_bitova", with_trailing_bit(&s), k.clone(), "vrijedi", "kriv:potpis"),
            ("potpis_url_safe", url_safe(&s), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_nekanonski_s", STANDARD.encode(&sig_s_plus_l), k.clone(), "kriv:potpis", "kriv:potpis"),
            ("potpis_visoki_bit", STANDARD.encode(&sig_high_bit), k.clone(), "kriv:potpis", "kriv:potpis"),
        ];

        let mut wrong = Vec::new();
        for (name, potpis, kljuc, go, _before) in &cases {
            let got = edge_outcome(potpis, kljuc);
            if got != *go {
                wrong.push(format!("{name}: Go {go}, Rust {got}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));

        // Go reads the key's length before the payload and the point after it.
        let not_json = VersionData {
            version_id: "v",
            entity: "e",
            entity_id: "i",
            node_id: "n",
            supersedes: "",
            archived: false,
            channel: "",
            schema_version: 1,
            created_at_unix: 0,
            payload: "nije json",
        };
        for (key, want) in [
            (k31.as_str(), VersionSignatureError::BadAuthorKey),
            (
                k_not_a_point.as_str(),
                VersionSignatureError::PayloadNotJson,
            ),
            (k.as_str(), VersionSignatureError::PayloadNotJson),
        ] {
            assert_eq!(
                verify_version_signature("gocop", &not_json, &s, key),
                Err(want),
                "{key:?}"
            );
        }
    }

    #[test]
    fn signed_version_in_a_delta_keeps_its_signature_and_verifies() {
        let c: Value =
            serde_json::from_str(include_str!("../../../vektori/vektori-razgovora.json")).unwrap();
        let line = c["deltaSPotpisom"].as_str().unwrap();
        let envelope: EnvelopeV1 = serde_json::from_str(line.trim_end()).unwrap();
        let mut delta: DeltaPayload = envelope.parse_payload().unwrap();

        // Read and written again, the delta is the same bytes, signature included.
        let rebuilt = EnvelopeV1::with_payload(
            KIND_V1_DELTA,
            envelope.device_id.as_deref().unwrap(),
            &delta,
        )
        .unwrap();
        assert_eq!(format!("{}\n", to_go_json_string(&rebuilt).unwrap()), line);

        let version = &mut delta.versions[0];
        verify_version_v1("gocop", version).expect("Go's signature verifies in Rust");
        assert_eq!(
            verify_version_v1("drugi", version),
            Err(VersionSignatureError::BadSignature)
        );

        version.archived = !version.archived;
        assert_eq!(
            verify_version_v1("gocop", version),
            Err(VersionSignatureError::BadSignature)
        );
        version.archived = !version.archived;

        version.kljuc_autora = "nije kljuc".to_owned();
        assert_eq!(
            verify_version_v1("gocop", version),
            Err(VersionSignatureError::BadAuthorKey)
        );
        // Only one of the two fields is never unsigned.
        version.potpis.clear();
        assert_eq!(
            verify_version_v1("gocop", version),
            Err(VersionSignatureError::BadAuthorKey)
        );
        version.kljuc_autora.clear();
        assert_eq!(
            verify_version_v1("gocop", version),
            Err(VersionSignatureError::Unsigned)
        );
    }

    /// `created_at` as Go's version reads it (`json.Unmarshal` into the ledger's version,
    /// go1.27.1): the Unix seconds, or `GRESKA` where Go fails to read it. The value is
    /// the JSON text; Rust reads it into the version's text field first, as the
    /// conversation does.
    const CREATED_AT: &[(&str, &str)] = &[
        (r#""2025-10-09T08:54:00Z""#, "1760000040"),
        (r#""2025-10-09T08:53:60Z""#, "GRESKA"),
        (r#""2025-10-09T08:54:00z""#, "GRESKA"),
        (r#""2025-10-09t08:54:00Z""#, "GRESKA"),
        (r#""2025-02-31T00:00:00Z""#, "GRESKA"),
        (r#""2025-04-31T00:00:00Z""#, "GRESKA"),
        (r#""2025-10-09T8:54:00Z""#, "1760000040"),
        (r#""2025-10-09T08:54:00,5Z""#, "1760000040"),
        (r#""2025-10-09T08:54:00.5Z""#, "1760000040"),
        (r#""2025-10-09T08:54:00+24:00""#, "1759913640"),
        (r#""2025-10-09T08:54:00+23:59""#, "1759913700"),
        (r#""2025-10-09T08:54:00Z""#, "1760000040"),
        (r#""2025-10-09 08:54:00Z""#, "GRESKA"),
        ("1760000040", "GRESKA"),
        (r#""""#, "GRESKA"),
    ];

    #[test]
    fn created_at_reads_as_in_go() {
        for (raw, go) in CREATED_AT {
            let rust = serde_json::from_str::<String>(raw)
                .ok()
                .and_then(|text| created_at_unix(&text).ok())
                .map_or_else(|| "GRESKA".to_owned(), |unix| unix.to_string());
            assert_eq!(rust, *go, "{raw}");
        }

        // The signature covers the seconds only, so a time Go does not read must not pass
        // here under a signature made for the same seconds written properly.
        let author = SigningKey::from_bytes(&[1; 32]);
        let k = public_key_to_base64(author.verifying_key().as_bytes());
        let s = sign_edge_over(&author, &k);
        for (created_at, want) in [
            ("2025-10-09T08:53:20Z", Ok(())),
            ("2025-10-09T10:53:20+02:00", Ok(())),
            ("2025-10-09T8:53:20Z", Ok(())),
            ("2025-10-09T08:53:20,5Z", Ok(())),
            (
                "2025-10-09T08:53:20z",
                Err(VersionSignatureError::BadCreatedAt),
            ),
            (
                "2025-10-09t08:53:20Z",
                Err(VersionSignatureError::BadCreatedAt),
            ),
        ] {
            let mut version = edge_version(&s, &k);
            version.created_at = created_at.to_owned();
            assert_eq!(verify_version_v1("gocop", &version), want, "{created_at}");
        }
    }
}
