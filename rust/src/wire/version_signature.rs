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

use crate::identity::{parse_public_key, public_key_to_base64};
use crate::trust::rfc3339_unix::parse_utc;
use crate::wire::conversation_v1::VersionV1;
use crate::wire::go_json::{go_raw_json_vec, to_go_json_vec};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
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
    /// The author's key is not a base64 Ed25519 public key.
    BadAuthorKey,
    /// The signature is not valid for this version under the author's key.
    BadSignature,
    /// The version carries no signature.
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
pub fn verify_version_signature(
    protocol: &str,
    v: &VersionData<'_>,
    signature: &str,
    author_key: &str,
) -> Result<(), VersionSignatureError> {
    let key = parse_public_key(author_key).map_err(|_| VersionSignatureError::BadAuthorKey)?;
    let bytes = version_signing_bytes(protocol, v, author_key)?;
    let signature = STANDARD
        .decode(signature)
        .ok()
        .and_then(|raw| Signature::from_slice(&raw).ok())
        .ok_or(VersionSignatureError::BadSignature)?;
    key.verify(&bytes, &signature)
        .map_err(|_| VersionSignatureError::BadSignature)
}

/// Checks the author's signature of a version as it came in a conversation.
pub fn verify_version_v1(protocol: &str, version: &VersionV1) -> Result<(), VersionSignatureError> {
    if version.potpis.is_empty() {
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
        created_at_unix: parse_utc(&version.created_at)
            .map_err(|_| VersionSignatureError::BadCreatedAt)?,
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
                created_at_unix: parse_utc(input("created_at")).unwrap(),
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
        version.potpis.clear();
        assert_eq!(
            verify_version_v1("gocop", version),
            Err(VersionSignatureError::Unsigned)
        );
    }
}
