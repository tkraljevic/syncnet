use crate::identity::{parse_public_key, parse_public_key_bytes, public_key_to_base64};
use crate::wire::go_base64::decode_std;
use crate::wire::go_json::to_go_json_vec;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_CLOCK_SKEW_SECS: i64 = 3600;
pub const OVLAST_CANONICAL_VERSION: &str = "ovlast/1";
pub const REVOCATION_CANONICAL_VERSION: &str = "opoziv/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    OtherNetwork,
    KeyMismatch,
    BadSignature,
    Expired,
    NotYetValid,
    IssuedInFuture,
    ExceedsAdmitterAuthority,
    IssuerMismatch,
    UnauthorizedSigner,
    Revoked,
    InvalidFormat(String),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherNetwork => write!(f, "other network"),
            Self::KeyMismatch => write!(f, "device key mismatch"),
            Self::BadSignature => write!(f, "invalid signature"),
            Self::Expired => write!(f, "expired"),
            Self::NotYetValid => write!(f, "not yet valid"),
            Self::IssuedInFuture => write!(f, "issued too far in the future"),
            Self::ExceedsAdmitterAuthority => write!(f, "exceeds admitter authority"),
            Self::IssuerMismatch => write!(f, "issuer mismatch"),
            Self::UnauthorizedSigner => write!(f, "unauthorized signer"),
            Self::Revoked => write!(f, "revoked"),
            Self::InvalidFormat(m) => write!(f, "invalid trust record: {m}"),
        }
    }
}

impl std::error::Error for TrustError {}

#[derive(Debug, Clone, Copy)]
pub struct Validity {
    pub issued_at: i64,
    pub valid_for_secs: i64,
}

impl Validity {
    pub fn expires_at(self) -> Result<i64, TrustError> {
        if self.valid_for_secs <= 0 {
            return Err(TrustError::InvalidFormat(
                "validity duration must be positive".into(),
            ));
        }
        self.issued_at
            .checked_add(self.valid_for_secs)
            .ok_or_else(|| TrustError::InvalidFormat("validity expiry out of range".into()))
    }
}

pub struct NetworkKey {
    pub name: String,
    pub public: VerifyingKey,
    private: Option<SigningKey>,
}

impl NetworkKey {
    pub fn from_signing_key(name: impl Into<String>, sk: SigningKey) -> Self {
        let public = sk.verifying_key();
        Self {
            name: name.into(),
            public,
            private: Some(sk),
        }
    }

    pub fn public_only(name: impl Into<String>, public: VerifyingKey) -> Self {
        Self {
            name: name.into(),
            public,
            private: None,
        }
    }

    pub fn can_sign(&self) -> bool {
        self.private.is_some()
    }

    pub fn signing_key(&self) -> Result<&SigningKey, TrustError> {
        self.private.as_ref().ok_or(TrustError::UnauthorizedSigner)
    }

    pub fn public_b64(&self) -> String {
        public_key_to_base64(self.public.as_bytes())
    }

    pub fn issue_ovlast(
        &self,
        device_id: &str,
        device_key: &VerifyingKey,
        issued_by: &str,
        issued_at: i64,
        valid_for_secs: i64,
    ) -> Result<Ovlast, TrustError> {
        let sk = self.signing_key()?;
        let mut o = Ovlast {
            network: self.public_b64(),
            device_id: device_id.to_owned(),
            device_key: public_key_to_base64(device_key.as_bytes()),
            issued_by: issued_by.to_owned(),
            issued_at,
            expires_at: Validity {
                issued_at,
                valid_for_secs,
            }
            .expires_at()?,
            signature: String::new(),
        };
        let sig = sk.sign(&o.signed_bytes());
        o.signature = STANDARD.encode(sig.to_bytes());
        Ok(o)
    }

    pub fn admit_member(
        &self,
        device_id: &str,
        device_key: &VerifyingKey,
        issued_by: &str,
        validity: Validity,
    ) -> Result<Membership, TrustError> {
        let sk = self.signing_key()?;
        let mut m = Membership {
            network: self.public_b64(),
            device_id: device_id.to_owned(),
            device_key: public_key_to_base64(device_key.as_bytes()),
            issued_by: issued_by.to_owned(),
            issued_at: validity.issued_at,
            expires_at: validity.expires_at()?,
            signature: String::new(),
            admitter: None,
        };
        let sig = sk.sign(&m.signed_bytes());
        m.signature = STANDARD.encode(sig.to_bytes());
        Ok(m)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ovlast {
    pub network: String,
    pub device_id: String,
    pub device_key: String,
    pub issued_by: String,
    #[serde(with = "rfc3339_unix")]
    pub issued_at: i64,
    #[serde(with = "rfc3339_unix")]
    pub expires_at: i64,
    pub signature: String,
}

impl Ovlast {
    pub fn signed_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Canonical<'a> {
            v: &'a str,
            network: &'a str,
            device_id: &'a str,
            device_key: &'a str,
            issued_by: &'a str,
            issued_at: i64,
            expires_at: i64,
        }
        to_go_json_vec(&Canonical {
            v: OVLAST_CANONICAL_VERSION,
            network: &self.network,
            device_id: &self.device_id,
            device_key: &self.device_key,
            issued_by: &self.issued_by,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        })
        .expect("canonical ovlast serializes")
    }

    pub fn verify(&self, network_pub: &VerifyingKey, at_unix: i64) -> Result<(), TrustError> {
        if self.network != public_key_to_base64(network_pub.as_bytes()) {
            return Err(TrustError::OtherNetwork);
        }
        verify_ed25519_b64(network_pub, &self.signed_bytes(), &self.signature)?;
        if at_unix < self.issued_at {
            return Err(TrustError::NotYetValid);
        }
        if self.expires_at > 0 && at_unix > self.expires_at {
            return Err(TrustError::Expired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub network: String,
    pub device_id: String,
    pub device_key: String,
    pub issued_by: String,
    #[serde(with = "rfc3339_unix")]
    pub issued_at: i64,
    #[serde(with = "rfc3339_unix")]
    pub expires_at: i64,
    pub signature: String,
    #[serde(
        rename = "primatelj",
        alias = "admitter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub admitter: Option<Ovlast>,
}

impl Membership {
    pub fn signed_bytes(&self) -> Vec<u8> {
        if let Some(ref ovlast) = self.admitter {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct CanonicalV2<'a> {
                v: u8,
                network: &'a str,
                device_id: &'a str,
                device_key: &'a str,
                issued_by: &'a str,
                issued_at: i64,
                expires_at: i64,
                ovlast: &'a str,
            }
            to_go_json_vec(&CanonicalV2 {
                v: 2,
                network: &self.network,
                device_id: &self.device_id,
                device_key: &self.device_key,
                issued_by: &self.issued_by,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                ovlast: &ovlast.signature,
            })
            .expect("canonical membership v2 serializes")
        } else {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct CanonicalV1<'a> {
                v: u8,
                network: &'a str,
                device_id: &'a str,
                device_key: &'a str,
                issued_by: &'a str,
                issued_at: i64,
                expires_at: i64,
            }
            to_go_json_vec(&CanonicalV1 {
                v: 1,
                network: &self.network,
                device_id: &self.device_id,
                device_key: &self.device_key,
                issued_by: &self.issued_by,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            })
            .expect("canonical membership v1 serializes")
        }
    }

    pub fn admit_as(
        admitter_sk: &SigningKey,
        ovlast: Ovlast,
        device_id: &str,
        device_key: &VerifyingKey,
        validity: Validity,
    ) -> Result<Self, TrustError> {
        let issued_at = validity.issued_at;
        let admitter_pub_b64 = public_key_to_base64(admitter_sk.verifying_key().as_bytes());
        if admitter_pub_b64 != ovlast.device_key {
            return Err(TrustError::UnauthorizedSigner);
        }
        if issued_at < ovlast.issued_at || (ovlast.expires_at > 0 && issued_at > ovlast.expires_at)
        {
            return Err(TrustError::Expired);
        }
        let mut exp = validity.expires_at()?;
        if ovlast.expires_at > 0 && exp > ovlast.expires_at {
            exp = ovlast.expires_at;
        }
        let issued_by = ovlast.device_id.clone();
        let mut m = Self {
            network: ovlast.network.clone(),
            device_id: device_id.to_owned(),
            device_key: public_key_to_base64(device_key.as_bytes()),
            issued_by,
            issued_at,
            expires_at: exp,
            signature: String::new(),
            admitter: Some(ovlast),
        };
        let sig = admitter_sk.sign(&m.signed_bytes());
        m.signature = STANDARD.encode(sig.to_bytes());
        Ok(m)
    }

    pub fn verify(
        &self,
        network_pub: &VerifyingKey,
        device_key: &VerifyingKey,
        now_unix: i64,
    ) -> Result<(), TrustError> {
        if self.network != public_key_to_base64(network_pub.as_bytes()) {
            return Err(TrustError::OtherNetwork);
        }
        if self.device_key != public_key_to_base64(device_key.as_bytes()) {
            return Err(TrustError::KeyMismatch);
        }
        let signer = verify_admitter_chain(
            network_pub,
            self.admitter.as_ref(),
            &self.issued_by,
            self.issued_at,
            self.expires_at,
            now_unix,
        )?;
        verify_ed25519_b64(&signer, &self.signed_bytes(), &self.signature)?;
        if self.expires_at > 0 && now_unix > self.expires_at {
            return Err(TrustError::Expired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Revocation {
    pub id: String,
    #[serde(rename = "vrsta", alias = "kind")]
    pub kind: String,
    #[serde(rename = "nodeId", alias = "targetId")]
    pub target_id: String,
    pub public_key: String,
    #[serde(with = "rfc3339_unix")]
    pub issued_at: i64,
    #[serde(rename = "opozvanoAt", alias = "revokedAt", with = "rfc3339_unix")]
    pub revoked_at: i64,
    #[serde(rename = "opozvao", alias = "revokedBy")]
    pub revoked_by: String,
    #[serde(rename = "potpisnik", alias = "signerKey")]
    pub signer_key: String,
    #[serde(rename = "potpis", alias = "signature")]
    pub signature: String,
}

impl Revocation {
    pub fn scope(&self) -> Result<&str, TrustError> {
        let trimmed = self.kind.trim();
        if trimmed.is_empty() {
            return Err(TrustError::InvalidFormat("empty revocation kind".into()));
        }
        match trimmed {
            "clanstvo" | "membership" => Ok("membership"),
            other => Ok(other),
        }
    }

    pub fn signed_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Canonical<'a> {
            v: &'a str,
            vrsta: &'a str,
            node_id: &'a str,
            public_key: &'a str,
            issued_at: i64,
            opozvano_at: i64,
            opozvao: &'a str,
            potpisnik: &'a str,
        }
        to_go_json_vec(&Canonical {
            v: REVOCATION_CANONICAL_VERSION,
            vrsta: &self.kind,
            node_id: &self.target_id,
            public_key: &self.public_key,
            issued_at: self.issued_at,
            opozvano_at: self.revoked_at,
            opozvao: &self.revoked_by,
            potpisnik: &self.signer_key,
        })
        .expect("canonical revocation serializes")
    }

    /// The id is made from the signature's bytes, read as Go reads them: a text that
    /// reads to the same bytes gives the same id. A signature that does not read is a bad
    /// signature (Go then takes the revocation as not signed).
    pub fn compute_id(&self) -> Result<String, TrustError> {
        let sig = decode_std(&self.signature).map_err(|_| TrustError::BadSignature)?;
        let digest = Sha256::digest(&sig);
        Ok(format!(
            "{}:{}:{}:{}",
            self.kind,
            self.public_key,
            self.issued_at,
            hex::encode(&digest[..8])
        ))
    }

    pub fn sign(mut self, sk: &SigningKey) -> Self {
        self.signer_key = public_key_to_base64(sk.verifying_key().as_bytes());
        let sig = sk.sign(&self.signed_bytes());
        self.signature = STANDARD.encode(sig.to_bytes());
        self.id = self.compute_id().expect("fresh signature is valid base64");
        self
    }

    /// Says whether the revocation holds on its own: its id comes from its content and
    /// signature, and the signature holds under the key named as its signer. Whether that
    /// key may revoke is for the caller to decide.
    ///
    /// The signer's key is read as Go reads it and must stand exactly as Go writes that
    /// key (canonical base64): Go takes a revocation as signed by a key only then. The
    /// revoked key (`public_key`) is not read, as in Go: a revocation revokes only a key
    /// written the same (`revokes`), so one with any other text revokes nothing. Compare
    /// `public_key` only as text, as `revokes` does, never by the bytes it reads to.
    pub fn verify_self(&self) -> Result<VerifyingKey, TrustError> {
        self.scope()?;
        if self.target_id.is_empty() || self.issued_at < 0 || self.revoked_at < self.issued_at {
            return Err(TrustError::InvalidFormat(
                "invalid revocation target or timestamps".into(),
            ));
        }
        let signer =
            parse_public_key_bytes(&self.signer_key).map_err(|_| TrustError::BadSignature)?;
        let expected_id = self.compute_id()?;
        if self.id != expected_id {
            return Err(TrustError::InvalidFormat(
                "invalid revocation id".to_owned(),
            ));
        }
        if public_key_to_base64(&signer) != self.signer_key {
            return Err(TrustError::BadSignature);
        }
        let signer = VerifyingKey::from_bytes(&signer).map_err(|_| TrustError::BadSignature)?;
        verify_ed25519_b64(&signer, &self.signed_bytes(), &self.signature)?;
        Ok(signer)
    }

    /// Compares the revoked key as text. `subject_pub_b64` must be the canonical text of
    /// the key (`public_key_to_base64` of the key's bytes), never the text a record
    /// carried: Go reads a key with `\n` in it or with extra bits in its last character as
    /// the same key, so a record's own text can differ from the one the revocation names.
    pub fn revokes(&self, subject_pub_b64: &str, issued_at: i64) -> bool {
        self.scope() == Ok("membership")
            && self.public_key == subject_pub_b64
            && issued_at <= self.issued_at
    }
}

/// A signed version in a shape of the Rust implementation only (`<protocol>-ver-v1|[...]`).
/// The Go implementation does not read it. The author's signature both implementations
/// share is in [`crate::wire::version_signature`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVersionEnvelope {
    pub version_id: String,
    pub entity: String,
    pub entity_id: String,
    pub node_id: String,
    pub supersedes: String,
    pub archived: bool,
    pub channel: String,
    pub created_at: String,
    pub created_at_unix: i64,
    pub schema_version: u32,
    /// The author's key as the record carries it. Several texts read to the same key
    /// (`\n` anywhere, extra bits in the last character), so to compare, map or revoke by
    /// the author take `public_key_to_base64` of the key `verify_signature` returns.
    pub author_pub_key: String,
    pub grant_ref: String,
    pub payload: String,
    pub signature: String,
}

impl SignedVersionEnvelope {
    pub fn canonical_signing_bytes(&self, protocol: &str) -> Vec<u8> {
        let fields = (
            self.schema_version,
            &self.entity,
            &self.entity_id,
            &self.version_id,
            &self.node_id,
            &self.supersedes,
            self.archived,
            &self.channel,
            &self.created_at,
            self.created_at_unix,
            &self.author_pub_key,
            &self.grant_ref,
            &self.payload,
        );
        let mut out = format!("{protocol}-ver-v1|").into_bytes();
        out.extend(serde_json::to_vec(&fields).expect("version fields serialize"));
        out
    }

    pub fn sign(mut self, protocol: &str, sk: &SigningKey) -> Self {
        self.author_pub_key = public_key_to_base64(sk.verifying_key().as_bytes());
        let sig = sk.sign(&self.canonical_signing_bytes(protocol));
        self.signature = STANDARD.encode(sig.to_bytes());
        self
    }

    /// The author's key is read as Go reads the author's key of the shared signature
    /// ([`crate::wire::version_signature`]): a key that does not read is an invalid record
    /// (a bad author key there), and one that reads but is not a point is a bad signature.
    pub fn verify_signature(&self, protocol: &str) -> Result<VerifyingKey, TrustError> {
        let key = parse_public_key_bytes(&self.author_pub_key)
            .map_err(|_| TrustError::InvalidFormat("invalid author key".into()))?;
        let vk = VerifyingKey::from_bytes(&key).map_err(|_| TrustError::BadSignature)?;
        verify_ed25519_b64(
            &vk,
            &self.canonical_signing_bytes(protocol),
            &self.signature,
        )?;
        Ok(vk)
    }
}

pub fn verify_admitter_chain(
    network_pub: &VerifyingKey,
    admitter: Option<&Ovlast>,
    issued_by: &str,
    issued_at: i64,
    expires_at: i64,
    now_unix: i64,
) -> Result<VerifyingKey, TrustError> {
    // PROTOKOL §7: `issuedAt` may run up to one hour ahead of the verifier's clock.
    if issued_at > now_unix.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(TrustError::IssuedInFuture);
    }
    if expires_at != 0 && expires_at < issued_at {
        return Err(TrustError::InvalidFormat(
            "expires_at precedes issued_at".into(),
        ));
    }
    let Some(ovlast) = admitter else {
        return Ok(*network_pub);
    };
    ovlast.verify(network_pub, issued_at)?;
    if ovlast.expires_at > 0 && (expires_at == 0 || expires_at > ovlast.expires_at) {
        return Err(TrustError::ExceedsAdmitterAuthority);
    }
    if ovlast.device_id != issued_by {
        return Err(TrustError::IssuerMismatch);
    }
    // As in Go: a key that does not read is a bad signature, and so is one that reads but
    // is not a point (Go finds that out when it verifies the signature under it).
    parse_public_key(&ovlast.device_key).map_err(|_| TrustError::BadSignature)
}

/// The signature is read as Go reads it (`base64.StdEncoding`, see
/// [`crate::wire::go_base64`]): no trimming, `\r` and `\n` skipped, extra bits in the last
/// character not checked, and exactly 64 bytes.
pub fn verify_ed25519_b64(vk: &VerifyingKey, msg: &[u8], sig_b64: &str) -> Result<(), TrustError> {
    let sig_bytes = decode_std(sig_b64).map_err(|_| TrustError::BadSignature)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| TrustError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig).map_err(|_| TrustError::BadSignature)
}

pub mod rfc3339_unix {
    use serde::{Deserializer, Serializer, de};

    pub fn format_utc(unix: i64) -> String {
        let days = unix.div_euclid(86_400);
        let secs_of_day = unix.rem_euclid(86_400);
        let hour = secs_of_day / 3600;
        let min = (secs_of_day % 3600) / 60;
        let sec = secs_of_day % 60;

        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = (yoe as i64) + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = y + if m <= 2 { 1 } else { 0 };

        format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
    }

    pub fn parse_utc(s: &str) -> Result<i64, String> {
        const DIGITS: [usize; 14] = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
        let b = s.as_bytes();
        // Untrusted input: all-ASCII keeps every byte slice below on a char boundary,
        // and explicit digit checks stop `str::parse` from accepting signs like "+1".
        if !s.is_ascii()
            || b.len() < 20
            || DIGITS.iter().any(|&i| !b[i].is_ascii_digit())
            || b[4] != b'-'
            || b[7] != b'-'
            || (b[10] != b'T' && b[10] != b't')
            || b[13] != b':'
            || b[16] != b':'
        {
            return Err("invalid RFC 3339 timestamp".into());
        }
        let year: i64 = s[0..4].parse().map_err(|_| "invalid year")?;
        let month: u32 = s[5..7].parse().map_err(|_| "invalid month")?;
        let day: u32 = s[8..10].parse().map_err(|_| "invalid day")?;
        let hour: i64 = s[11..13].parse().map_err(|_| "invalid hour")?;
        let min: i64 = s[14..16].parse().map_err(|_| "invalid minute")?;
        let sec: i64 = s[17..19].parse().map_err(|_| "invalid second")?;
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || min > 59
            || sec > 60
        {
            return Err("timestamp component out of range".into());
        }

        let mut rest = &s[19..];
        if let Some(after_dot) = rest.strip_prefix('.') {
            let digits = after_dot.bytes().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 {
                return Err("empty fractional seconds".into());
            }
            rest = &after_dot[digits..];
        }

        let offset_secs: i64 = if rest == "Z" || rest == "z" {
            0
        } else if (rest.starts_with('+') || rest.starts_with('-')) && rest.len() == 6 {
            let sign = if rest.starts_with('+') { 1 } else { -1 };
            let ob = rest.as_bytes();
            if ob[3] != b':' || ![1, 2, 4, 5].iter().all(|&i| ob[i].is_ascii_digit()) {
                return Err("invalid timezone offset".into());
            }
            let oh: i64 = rest[1..3].parse().map_err(|_| "invalid offset hour")?;
            let om: i64 = rest[4..6].parse().map_err(|_| "invalid offset minute")?;
            if oh > 23 || om > 59 {
                return Err("timezone offset out of range".into());
            }
            sign * (oh * 3600 + om * 60)
        } else {
            return Err("missing or invalid timezone".into());
        };

        let days = days_from_civil(year, month, day);
        Ok(days * 86_400 + hour * 3600 + min * 60 + sec - offset_secs)
    }

    fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
        let y = y - if m <= 2 { 1 } else { 0 };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as u64;
        let m = m as u64;
        let d = d as u64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + (doe as i64) - 719_468
    }

    pub fn serialize<S: Serializer>(unix: &i64, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format_utc(*unix))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<i64, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = i64;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("RFC 3339 timestamp string or unix seconds")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<i64, E> {
                parse_utc(v).map_err(de::Error::custom)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<i64, E> {
                Ok(v)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<i64, E> {
                i64::try_from(v).map_err(|_| de::Error::custom("unix timestamp overflow"))
            }
        }
        de.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{build_self_signed_cert_der, generate_signing_key, verify_peer_cert_der};

    #[test]
    fn rfc3339_rejects_non_ascii_and_signed_fields_without_panicking() {
        use rfc3339_unix::parse_utc;
        assert_eq!(parse_utc("2025-10-09T08:53:20Z"), Ok(1_760_000_000));
        assert_eq!(parse_utc("2025-10-09T10:53:20+02:00"), Ok(1_760_000_000));
        assert_eq!(parse_utc("2025-10-09T08:53:20.5Z"), Ok(1_760_000_000));
        for bad in [
            "2024-01-01T00:00:0éZ",
            "2024-01-01T00:00:00+0é00",
            "2024-01-01T00:00:00+01é0",
            "202é-01-01T00:00:00Z",
            "2024-+1-01T00:00:00Z",
            "2024-01-01T-1:00:00Z",
            "2024-01-01T00:00:00+-1:00",
            "2024-01-01T00:00:00.é",
        ] {
            assert!(parse_utc(bad).is_err(), "{bad}");
        }
        let json = r#"{"issuedAt":"2024-01-01T00:00:0éZ"}"#;
        #[derive(Deserialize)]
        struct T {
            #[serde(rename = "issuedAt", with = "rfc3339_unix")]
            _issued_at: i64,
        }
        assert!(serde_json::from_str::<T>(json).is_err());
    }
    use crate::tls::{alpn_proba, alpn_sig, alpn_web};

    #[test]
    fn membership_ovlast_and_revocation_chain() {
        let net_sk = generate_signing_key();
        let net = NetworkKey::from_signing_key("Family", net_sk.clone());

        let admin_sk = generate_signing_key();
        let admin_vk = admin_sk.verifying_key();
        let member_sk = generate_signing_key();
        let member_vk = member_sk.verifying_key();

        let now = 1_760_000_000i64;
        let ovlast = net
            .issue_ovlast("admin-1", &admin_vk, "root", now, 3600)
            .expect("ovlast");
        ovlast
            .verify(&net.public, now + 100)
            .expect("verify ovlast");

        let mem = Membership::admit_as(
            &admin_sk,
            ovlast,
            "fam-1",
            &member_vk,
            Validity {
                issued_at: now + 10,
                valid_for_secs: 1800,
            },
        )
        .expect("admit_as");
        mem.verify(&net.public, &member_vk, now + 500)
            .expect("verify membership");

        let rev = Revocation {
            id: String::new(),
            kind: "clanstvo".to_owned(),
            target_id: "fam-1".to_owned(),
            public_key: public_key_to_base64(member_vk.as_bytes()),
            issued_at: now + 20,
            revoked_at: now + 30,
            revoked_by: "root".to_owned(),
            signer_key: String::new(),
            signature: String::new(),
        }
        .sign(&net_sk);
        let signer = rev.verify_self().expect("verify rev");
        assert_eq!(signer, net.public);
        assert!(rev.revokes(&public_key_to_base64(member_vk.as_bytes()), mem.issued_at));

        let app_rev = Revocation {
            kind: "list_grant".into(),
            target_id: "g-1".into(),
            ..rev.clone()
        }
        .sign(&net_sk);
        app_rev.verify_self().unwrap();
        assert!(
            !app_rev.revokes(&public_key_to_base64(member_vk.as_bytes()), mem.issued_at),
            "an app-specific revocation does not revoke a device key"
        );
    }

    #[test]
    fn rejects_membership_exceeding_ovlast_or_wrong_key() {
        let net_sk = generate_signing_key();
        let net = NetworkKey::from_signing_key("Family", net_sk);
        let other_sk = generate_signing_key();
        let member_sk = generate_signing_key();
        let member_vk = member_sk.verifying_key();

        let now = 1_760_000_000i64;
        let mem = net
            .admit_member(
                "dev-1",
                &member_vk,
                "root",
                Validity {
                    issued_at: now,
                    valid_for_secs: 600,
                },
            )
            .expect("admit");

        assert_eq!(
            mem.verify(&net.public, &other_sk.verifying_key(), now + 10),
            Err(TrustError::KeyMismatch)
        );
        assert_eq!(
            mem.verify(&other_sk.verifying_key(), &member_vk, now + 10),
            Err(TrustError::OtherNetwork)
        );
        assert_eq!(
            mem.verify(&net.public, &member_vk, now + 601),
            Err(TrustError::Expired)
        );
    }

    #[test]
    fn signed_version_binds_routing_metadata_and_unambiguous_field_boundaries() {
        let sk = generate_signing_key();
        let v = SignedVersionEnvelope {
            version_id: "019a9254-0000-7000-8000-000000000001".into(),
            entity: "shopping_lists".into(),
            entity_id: "list|one".into(),
            node_id: "device-a".into(),
            supersedes: String::new(),
            archived: false,
            channel: "list:list|one".into(),
            created_at: "2026-11-17T00:00:00Z".into(),
            created_at_unix: 1_794_873_600,
            schema_version: 1,
            author_pub_key: String::new(),
            grant_ref: "grant-a".into(),
            payload: r#"{"name":"<Subota> & nedjelja"}"#.into(),
            signature: String::new(),
        }
        .sign("list2cart", &sk);
        assert!(v.verify_signature("list2cart").is_ok());
        assert_eq!(
            v.verify_signature("gocop"),
            Err(TrustError::BadSignature),
            "protocol domain separation must prevent cross-protocol replay"
        );
        let mut changed = v.clone();
        changed.node_id = "device-b".into();
        assert_eq!(
            changed.verify_signature("list2cart"),
            Err(TrustError::BadSignature)
        );
        changed = v.clone();
        changed.created_at = "2020-01-01T00:00:00Z".into();
        assert_eq!(
            changed.verify_signature("list2cart"),
            Err(TrustError::BadSignature)
        );
        changed = v.clone();
        changed.entity = "shopping_lists|list".into();
        changed.entity_id = "one".into();
        assert_ne!(
            v.canonical_signing_bytes("list2cart"),
            changed.canonical_signing_bytes("list2cart")
        );
        assert_eq!(
            changed.verify_signature("list2cart"),
            Err(TrustError::BadSignature)
        );
    }

    #[test]
    fn root_signed_future_memberships_and_invalid_lifetimes_are_rejected() {
        let net = NetworkKey::from_signing_key("test", generate_signing_key());
        let device = generate_signing_key().verifying_key();
        let now = 1_760_000_000;
        let future = net
            .admit_member(
                "dev",
                &device,
                "root",
                Validity {
                    issued_at: now + MAX_CLOCK_SKEW_SECS + 1,
                    valid_for_secs: 60,
                },
            )
            .unwrap();
        assert_eq!(
            future.verify(&net.public, &device, now),
            Err(TrustError::IssuedInFuture)
        );
        // Admitter's clock a few minutes fast: still within the one-hour allowance.
        for ahead in [5, MAX_CLOCK_SKEW_SECS] {
            let slightly_ahead = net
                .admit_member(
                    "dev",
                    &device,
                    "root",
                    Validity {
                        issued_at: now + ahead,
                        valid_for_secs: 3600,
                    },
                )
                .unwrap();
            assert_eq!(slightly_ahead.verify(&net.public, &device, now), Ok(()));
        }
        for validity in [
            Validity {
                issued_at: now,
                valid_for_secs: -1,
            },
            Validity {
                issued_at: i64::MAX,
                valid_for_secs: 1,
            },
        ] {
            assert!(net.admit_member("dev", &device, "root", validity).is_err());
        }
    }

    #[test]
    fn gocop_wire_vectors_match_byte_for_byte() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../vektori/vektori-zice.json"))
                .expect("vektori-zice.json");
        let ulaz = &v["ulaz"];
        let protocol = ulaz["protokol"].as_str().unwrap();
        let now = ulaz["vrijeme"].as_i64().unwrap();

        let seed_a: [u8; 32] = hex::decode(ulaz["sjemeA"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let seed_b: [u8; 32] = hex::decode(ulaz["sjemeB"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let seed_net: [u8; 32] = hex::decode(ulaz["sjemeMreze"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        let sk_a = SigningKey::from_bytes(&seed_a);
        let sk_b = SigningKey::from_bytes(&seed_b);
        let sk_net = SigningKey::from_bytes(&seed_net);
        let net = NetworkKey::from_signing_key("test", sk_net.clone());

        assert_eq!(net.public_b64(), ulaz["kljucMreze"].as_str().unwrap());
        assert_eq!(
            public_key_to_base64(sk_a.verifying_key().as_bytes()),
            ulaz["kljucA"].as_str().unwrap()
        );
        assert_eq!(
            public_key_to_base64(sk_b.verifying_key().as_bytes()),
            ulaz["kljucB"].as_str().unwrap()
        );

        // ALPN
        assert_eq!(
            alpn_sig(protocol),
            v["alpn"]["signal"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            alpn_web(protocol),
            v["alpn"]["web"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            alpn_proba(protocol),
            v["alpn"]["proba"].as_str().unwrap().as_bytes()
        );

        // Ovlast
        let ovlast = net
            .issue_ovlast("admin-1", &sk_a.verifying_key(), "root", now, 3600)
            .unwrap();
        assert_eq!(
            String::from_utf8(ovlast.signed_bytes()).unwrap(),
            v["ovlast"]["bajtovi"].as_str().unwrap()
        );
        assert_eq!(ovlast.signature, v["ovlast"]["potpis"].as_str().unwrap());
        assert_eq!(
            serde_json::to_string(&ovlast).unwrap(),
            v["ovlast"]["zapis"].as_str().unwrap()
        );
        ovlast.verify(&net.public, now).unwrap();

        // Membership v1 (signed by network key)
        let mem_v1 = net
            .admit_member(
                "admin-1",
                &sk_a.verifying_key(),
                "root",
                Validity {
                    issued_at: now,
                    valid_for_secs: 3600,
                },
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(mem_v1.signed_bytes()).unwrap(),
            v["clanstvoKljucemMreze"]["bajtovi"].as_str().unwrap()
        );
        assert_eq!(
            mem_v1.signature,
            v["clanstvoKljucemMreze"]["potpis"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_string(&mem_v1).unwrap(),
            v["clanstvoKljucemMreze"]["zapis"].as_str().unwrap()
        );
        mem_v1
            .verify(&net.public, &sk_a.verifying_key(), now)
            .unwrap();

        // Membership v2 (signed by admitter with ovlast)
        let mem_v2 = Membership::admit_as(
            &sk_a,
            ovlast.clone(),
            "racunalo-b",
            &sk_b.verifying_key(),
            Validity {
                issued_at: now,
                valid_for_secs: 1800,
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(mem_v2.signed_bytes()).unwrap(),
            v["clanstvoOdPrimatelja"]["bajtovi"].as_str().unwrap()
        );
        assert_eq!(
            mem_v2.signature,
            v["clanstvoOdPrimatelja"]["potpis"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_string(&mem_v2).unwrap(),
            v["clanstvoOdPrimatelja"]["zapis"].as_str().unwrap()
        );
        mem_v2
            .verify(&net.public, &sk_b.verifying_key(), now)
            .unwrap();

        // Certificate credentials SAN round-trip
        #[derive(Serialize)]
        struct Creds<'a> {
            clanstvo: &'a Membership,
            ovlast: &'a Ovlast,
        }
        let creds_json = serde_json::to_vec(&Creds {
            clanstvo: &mem_v1,
            ovlast: &ovlast,
        })
        .unwrap();
        assert_eq!(
            String::from_utf8(creds_json.clone()).unwrap(),
            v["vjerodajnice"].as_str().unwrap()
        );
        let cert_der = build_self_signed_cert_der(&sk_a, protocol, Some(&creds_json)).unwrap();
        let verified = verify_peer_cert_der(&cert_der, protocol).unwrap();
        assert_eq!(verified.credentials.as_deref(), Some(creds_json.as_slice()));

        // Revocation
        let rev = Revocation {
            id: String::new(),
            kind: "clanstvo".into(),
            target_id: "racunalo-b".into(),
            public_key: public_key_to_base64(sk_b.verifying_key().as_bytes()),
            issued_at: now,
            revoked_at: now + 60,
            revoked_by: "root".into(),
            signer_key: String::new(),
            signature: String::new(),
        }
        .sign(&sk_net);
        assert_eq!(
            String::from_utf8(rev.signed_bytes()).unwrap(),
            v["opoziv"]["bajtovi"].as_str().unwrap()
        );
        assert_eq!(rev.signature, v["opoziv"]["potpis"].as_str().unwrap());
        assert_eq!(rev.id, v["oznakaOpoziva"].as_str().unwrap());
        assert_eq!(
            serde_json::to_string(&rev).unwrap(),
            v["opoziv"]["zapis"].as_str().unwrap()
        );
        assert_eq!(rev.verify_self().unwrap(), net.public);
    }

    #[test]
    fn gocop_special_chars_vectors_match_byte_for_byte() {
        use crate::wire::go_json::to_go_json_string;

        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../vektori/vektori-zice.json"))
                .expect("vektori-zice.json");
        let ulaz = &v["ulaz"];
        let pz = &v["posebniZnakovi"];
        let ime = pz["ime"].as_str().unwrap();
        let now = ulaz["vrijeme"].as_i64().unwrap();

        let seed_a: [u8; 32] = hex::decode(ulaz["sjemeA"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let seed_net: [u8; 32] = hex::decode(ulaz["sjemeMreze"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sk_a = SigningKey::from_bytes(&seed_a);
        let sk_net = SigningKey::from_bytes(&seed_net);
        let net = NetworkKey::from_signing_key("test", sk_net);

        let ovlast = net
            .issue_ovlast(ime, &sk_a.verifying_key(), ime, now, 3600)
            .unwrap();
        assert_eq!(
            String::from_utf8(ovlast.signed_bytes()).unwrap(),
            pz["ovlast"]["bajtovi"].as_str().unwrap()
        );
        assert_eq!(ovlast.signature, pz["ovlast"]["potpis"].as_str().unwrap());
        assert_eq!(
            to_go_json_string(&ovlast).unwrap(),
            pz["ovlast"]["zapis"].as_str().unwrap()
        );
        ovlast.verify(&net.public, now).unwrap();

        let clanstvo = net
            .admit_member(
                ime,
                &sk_a.verifying_key(),
                ime,
                Validity {
                    issued_at: now,
                    valid_for_secs: 3600,
                },
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(clanstvo.signed_bytes()).unwrap(),
            pz["clanstvo"]["bajtovi"].as_str().unwrap()
        );
        assert_eq!(
            clanstvo.signature,
            pz["clanstvo"]["potpis"].as_str().unwrap()
        );
        assert_eq!(
            to_go_json_string(&clanstvo).unwrap(),
            pz["clanstvo"]["zapis"].as_str().unwrap()
        );
        clanstvo
            .verify(&net.public, &sk_a.verifying_key(), now)
            .unwrap();
    }

    mod key_edges {
        use super::*;
        use crate::identity::key_edges::{KeyEdge, assert_edges_as_in_go, edge_signer};

        const AT: i64 = 1_760_000_000;

        fn b64(vk: &VerifyingKey) -> String {
            public_key_to_base64(vk.as_bytes())
        }

        fn member() -> SigningKey {
            SigningKey::from_bytes(&[5; 32])
        }

        /// A membership issued by an admitter whose key in the ovlast is the edge.
        fn membership_outcome(edge: &KeyEdge) -> String {
            let net = SigningKey::from_bytes(&[9; 32]);
            let mut ovlast = Ovlast {
                network: b64(&net.verifying_key()),
                device_id: "primatelj-1".into(),
                device_key: edge.key.clone(),
                issued_by: "admin-1".into(),
                issued_at: AT,
                expires_at: AT + 48 * 3600,
                signature: String::new(),
            };
            ovlast.signature = STANDARD.encode(net.sign(&ovlast.signed_bytes()).to_bytes());
            let mut m = Membership {
                network: ovlast.network.clone(),
                device_id: "clan-1".into(),
                device_key: b64(&member().verifying_key()),
                issued_by: "primatelj-1".into(),
                issued_at: AT,
                expires_at: AT + 24 * 3600,
                signature: String::new(),
                admitter: Some(ovlast),
            };
            m.signature = STANDARD.encode(edge.signer.sign(&m.signed_bytes()));
            match m.verify(&net.verifying_key(), &member().verifying_key(), AT + 100) {
                Ok(()) => "vrijedi".into(),
                Err(TrustError::BadSignature) => "kriv:potpis".into(),
                Err(e) => format!("drugo:{e}"),
            }
        }

        /// The admitter's key in the ovlast is read as Go reads it when it checks who
        /// signed a membership: a key that does not read and a key that is not a point
        /// are both a bad signature.
        #[test]
        fn admitter_key_in_ovlast_reads_as_in_go() {
            #[rustfmt::skip]
            let table = [
                ("ispravno", "vrijedi", "vrijedi"),
                ("prazno", "kriv:potpis", "kriv:potpis"),
                ("samo_razmak", "kriv:potpis", "kriv:potpis"),
                ("nije_base64", "kriv:potpis", "kriv:potpis"),
                ("31B", "kriv:potpis", "kriv:potpis"),
                ("33B", "kriv:potpis", "kriv:potpis"),
                ("bez_paddinga", "kriv:potpis", "kriv:potpis"),
                ("visak_paddinga", "kriv:potpis", "kriv:potpis"),
                ("razmak_ispred", "kriv:potpis", "vrijedi"),
                ("razmak_iza", "kriv:potpis", "vrijedi"),
                ("tab_iza", "kriv:potpis", "vrijedi"),
                ("novi_red_ispred", "vrijedi", "vrijedi"),
                ("novi_red_iza", "vrijedi", "vrijedi"),
                ("crlf_iza", "vrijedi", "vrijedi"),
                ("novi_red_u_sredini", "vrijedi", "kriv:potpis"),
                ("visak_bitova", "vrijedi", "kriv:potpis"),
                ("url_safe", "kriv:potpis", "kriv:potpis"),
                ("url_safe_kanonski", "vrijedi", "vrijedi"),
                ("nije_tocka", "kriv:potpis", "kriv:potpis"),
                ("identitet", "vrijedi", "vrijedi"),
                ("identitet_nekanonski_y", "vrijedi", "vrijedi"),
                ("identitet_s_predznakom", "vrijedi", "vrijedi"),
                ("red2_R_identitet", "vrijedi", "vrijedi"),
                ("red2_R_tocka", "vrijedi", "vrijedi"),
            ];
            assert_edges_as_in_go(&table, membership_outcome);
        }

        fn revocation(signer_key: &str, subject: &str, signer: &KeyEdge) -> Revocation {
            let mut r = Revocation {
                id: String::new(),
                kind: "clanstvo".into(),
                target_id: "cvor-1".into(),
                public_key: subject.into(),
                issued_at: AT,
                revoked_at: AT + 3600,
                revoked_by: "admin-1".into(),
                signer_key: signer_key.into(),
                signature: String::new(),
            };
            r.signature = STANDARD.encode(signer.signer.sign(&r.signed_bytes()));
            r.id = r.compute_id().unwrap();
            r
        }

        fn self_valid(r: &Revocation) -> String {
            match r.verify_self() {
                Ok(_) => "ispravan".into(),
                Err(_) => "neispravan".into(),
            }
        }

        /// The signer of a revocation is read as Go reads it, and must stand in the
        /// revocation exactly as Go writes that key: Go takes a revocation as signed by a
        /// key only when the text is that key's canonical base64.
        #[test]
        fn revocation_signer_reads_as_in_go() {
            let subject = b64(&member().verifying_key());
            #[rustfmt::skip]
            let table = [
                ("ispravno", "ispravan", "ispravan"),
                ("prazno", "neispravan", "neispravan"),
                ("samo_razmak", "neispravan", "neispravan"),
                ("nije_base64", "neispravan", "neispravan"),
                ("31B", "neispravan", "neispravan"),
                ("33B", "neispravan", "neispravan"),
                ("bez_paddinga", "neispravan", "neispravan"),
                ("visak_paddinga", "neispravan", "neispravan"),
                ("razmak_ispred", "neispravan", "ispravan"),
                ("razmak_iza", "neispravan", "ispravan"),
                ("tab_iza", "neispravan", "ispravan"),
                ("novi_red_ispred", "neispravan", "ispravan"),
                ("novi_red_iza", "neispravan", "ispravan"),
                ("crlf_iza", "neispravan", "ispravan"),
                ("novi_red_u_sredini", "neispravan", "neispravan"),
                ("visak_bitova", "neispravan", "neispravan"),
                ("url_safe", "neispravan", "neispravan"),
                ("url_safe_kanonski", "ispravan", "ispravan"),
                ("nije_tocka", "neispravan", "neispravan"),
                ("identitet", "ispravan", "ispravan"),
                ("identitet_nekanonski_y", "ispravan", "ispravan"),
                ("identitet_s_predznakom", "ispravan", "ispravan"),
                ("red2_R_identitet", "ispravan", "ispravan"),
                ("red2_R_tocka", "neispravan", "neispravan"),
            ];
            assert_edges_as_in_go(&table, |edge| {
                self_valid(&revocation(&edge.key, &subject, edge))
            });
        }

        /// Go does not read the revoked key at all when it checks a revocation on its own:
        /// any text is the subject, and a revocation revokes only a key written the same.
        #[test]
        fn revocation_subject_is_not_read_as_in_go() {
            let signer = KeyEdge {
                name: "potpisnik",
                key: b64(&edge_signer().verifying_key()),
                signer: crate::identity::key_edges::EdgeSigner::Key(edge_signer()),
            };
            #[rustfmt::skip]
            let table = [
                ("ispravno", "ispravan", "ispravan"),
                ("prazno", "ispravan", "neispravan"),
                ("samo_razmak", "ispravan", "neispravan"),
                ("nije_base64", "ispravan", "neispravan"),
                ("31B", "ispravan", "neispravan"),
                ("33B", "ispravan", "neispravan"),
                ("bez_paddinga", "ispravan", "neispravan"),
                ("visak_paddinga", "ispravan", "neispravan"),
                ("razmak_ispred", "ispravan", "neispravan"),
                ("razmak_iza", "ispravan", "neispravan"),
                ("tab_iza", "ispravan", "neispravan"),
                ("novi_red_ispred", "ispravan", "neispravan"),
                ("novi_red_iza", "ispravan", "neispravan"),
                ("crlf_iza", "ispravan", "neispravan"),
                ("novi_red_u_sredini", "ispravan", "neispravan"),
                ("visak_bitova", "ispravan", "neispravan"),
                ("url_safe", "ispravan", "neispravan"),
                ("url_safe_kanonski", "ispravan", "ispravan"),
                ("nije_tocka", "ispravan", "neispravan"),
                ("identitet", "ispravan", "ispravan"),
                ("identitet_nekanonski_y", "ispravan", "ispravan"),
                ("identitet_s_predznakom", "ispravan", "ispravan"),
                ("red2_R_identitet", "ispravan", "ispravan"),
                ("red2_R_tocka", "ispravan", "ispravan"),
            ];
            assert_edges_as_in_go(&table, |edge| {
                self_valid(&revocation(&signer.key, &edge.key, &signer))
            });
        }

        /// The older envelope is read by Rust only. Its author's key is read as Go reads
        /// the author's key of the signature both share (`wire::version_signature`); the Go
        /// column is that one. `-` where the signed bytes decide and differ from Go's. A
        /// key that does not read is `kriv:kljuc` (an invalid record here), one that is not
        /// a point `kriv:potpis`. The Rust column used `kriv:potpis` for both.
        #[test]
        fn envelope_author_reads_as_the_shared_author_key() {
            #[rustfmt::skip]
            let table = [
                ("ispravno", "vrijedi", "vrijedi"),
                ("prazno", "kriv:kljuc", "kriv:potpis"),
                ("samo_razmak", "kriv:kljuc", "kriv:potpis"),
                ("nije_base64", "kriv:kljuc", "kriv:potpis"),
                ("31B", "kriv:kljuc", "kriv:potpis"),
                ("33B", "kriv:kljuc", "kriv:potpis"),
                ("bez_paddinga", "kriv:kljuc", "kriv:potpis"),
                ("visak_paddinga", "kriv:kljuc", "kriv:potpis"),
                ("razmak_ispred", "kriv:kljuc", "vrijedi"),
                ("razmak_iza", "kriv:kljuc", "vrijedi"),
                ("tab_iza", "kriv:kljuc", "vrijedi"),
                ("novi_red_ispred", "vrijedi", "vrijedi"),
                ("novi_red_iza", "vrijedi", "vrijedi"),
                ("crlf_iza", "vrijedi", "vrijedi"),
                ("novi_red_u_sredini", "vrijedi", "kriv:potpis"),
                ("visak_bitova", "vrijedi", "kriv:potpis"),
                ("url_safe", "kriv:kljuc", "kriv:potpis"),
                ("url_safe_kanonski", "vrijedi", "vrijedi"),
                ("nije_tocka", "kriv:potpis", "kriv:potpis"),
                ("identitet", "vrijedi", "vrijedi"),
                ("identitet_nekanonski_y", "vrijedi", "vrijedi"),
                ("identitet_s_predznakom", "vrijedi", "vrijedi"),
                ("red2_R_identitet", "-", "vrijedi"),
                ("red2_R_tocka", "-", "vrijedi"),
            ];
            assert_edges_as_in_go(&table, |edge| {
                let mut v = SignedVersionEnvelope {
                    version_id: "v1".into(),
                    entity: "users".into(),
                    entity_id: "korisnik-1".into(),
                    node_id: "admin-1".into(),
                    supersedes: String::new(),
                    archived: false,
                    channel: String::new(),
                    created_at: "2025-10-09T08:53:20Z".into(),
                    created_at_unix: AT,
                    schema_version: 1,
                    author_pub_key: edge.key.clone(),
                    grant_ref: String::new(),
                    payload: "{}".into(),
                    signature: String::new(),
                };
                v.signature =
                    STANDARD.encode(edge.signer.sign(&v.canonical_signing_bytes("gocop")));
                match v.verify_signature("gocop") {
                    Ok(_) => "vrijedi".into(),
                    Err(TrustError::InvalidFormat(_)) => "kriv:kljuc".into(),
                    Err(TrustError::BadSignature) => "kriv:potpis".into(),
                    Err(e) => format!("drugo:{e}"),
                }
            });
        }
    }

    mod signature_edges {
        use super::*;
        use crate::identity::key_edges::with_trailing_bit;

        const AT: i64 = 1_760_000_000;

        fn b64(vk: &VerifyingKey) -> String {
            public_key_to_base64(vk.as_bytes())
        }

        fn net() -> SigningKey {
            SigningKey::from_bytes(&[9; 32])
        }

        fn member() -> SigningKey {
            SigningKey::from_bytes(&[5; 32])
        }

        fn signer() -> SigningKey {
            SigningKey::from_bytes(&[1; 32])
        }

        /// The edges of a signature's text, built from its 64 canonical bytes, with the
        /// same names as in the Go probe.
        fn edges(raw: &[u8; 64]) -> Vec<(&'static str, String)> {
            let s = STANDARD.encode(raw);
            // s + L: the same signature with a scalar that is not reduced.
            const L: [u8; 32] = [
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
            ];
            let mut s_plus_l = *raw;
            let mut carry = 0u16;
            for i in 0..32 {
                let sum = u16::from(raw[32 + i]) + u16::from(L[i]) + carry;
                s_plus_l[32 + i] = sum as u8;
                carry = sum >> 8;
            }
            let mut high_bit = *raw;
            high_bit[63] |= 0x80;
            vec![
                ("ispravno", s.clone()),
                ("prazno", String::new()),
                ("samo_razmak", " ".into()),
                ("nije_base64", "nije potpis".into()),
                ("63B", STANDARD.encode(&raw[..63])),
                ("65B", STANDARD.encode([&raw[..], &[0]].concat())),
                ("bez_paddinga", s.trim_end_matches('=').into()),
                ("visak_paddinga", format!("{s}=")),
                ("razmak_ispred", format!(" {s}")),
                ("razmak_iza", format!("{s} ")),
                ("tab_iza", format!("{s}\t")),
                ("novi_red_ispred", format!("\n{s}")),
                ("novi_red_iza", format!("{s}\n")),
                ("crlf_iza", format!("{s}\r\n")),
                ("novi_red_u_sredini", format!("{}\n{}", &s[..30], &s[30..])),
                ("novi_red_u_paddingu", format!("{}\n=", &s[..s.len() - 1])),
                ("visak_bitova", with_trailing_bit(&s)),
                ("url_safe", s.replace('+', "-").replace('/', "_")),
                ("nekanonski_s", STANDARD.encode(s_plus_l)),
                ("visoki_bit", STANDARD.encode(high_bit)),
            ]
        }

        /// Runs `outcome` over every edge of `raw` and fails with each edge where it is
        /// not what Go gives. `table` is `(edge, Go, Rust before)`; the last column is a
        /// record only.
        fn assert_signature_edges_as_in_go(
            table: &[(&str, &str, &str)],
            raw: &[u8; 64],
            mut outcome: impl FnMut(&str) -> String,
        ) {
            let edges = edges(raw);
            let mut wrong = Vec::new();
            for (name, text) in &edges {
                let Some((_, go, _before)) = table.iter().find(|row| row.0 == *name) else {
                    wrong.push(format!("{name}: no row in the table"));
                    continue;
                };
                let got = outcome(text);
                if got != *go {
                    wrong.push(format!("{name}: Go {go}, Rust {got}"));
                }
            }
            for (name, _, _) in table {
                if !edges.iter().any(|e| e.0 == *name) {
                    wrong.push(format!("{name}: no such edge"));
                }
            }
            assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        }

        fn sig_of(text: &str) -> [u8; 64] {
            STANDARD.decode(text).unwrap().try_into().unwrap()
        }

        fn verdict(r: Result<(), TrustError>) -> String {
            match r {
                Ok(()) => "vrijedi".into(),
                Err(TrustError::BadSignature) => "kriv:potpis".into(),
                Err(e) => format!("drugo:{e}"),
            }
        }

        /// What Go gives for a membership, an ovlast and the shared version signature
        /// (the three read a signature the same way): Go's `base64.StdEncoding` and then
        /// the 64 bytes of Ed25519.
        #[rustfmt::skip]
        const SIGNED: [(&str, &str, &str); 20] = [
            ("ispravno", "vrijedi", "vrijedi"),
            ("prazno", "kriv:potpis", "kriv:potpis"),
            ("samo_razmak", "kriv:potpis", "kriv:potpis"),
            ("nije_base64", "kriv:potpis", "kriv:potpis"),
            ("63B", "kriv:potpis", "kriv:potpis"),
            ("65B", "kriv:potpis", "kriv:potpis"),
            ("bez_paddinga", "kriv:potpis", "kriv:potpis"),
            ("visak_paddinga", "kriv:potpis", "kriv:potpis"),
            ("razmak_ispred", "kriv:potpis", "vrijedi"),
            ("razmak_iza", "kriv:potpis", "vrijedi"),
            ("tab_iza", "kriv:potpis", "vrijedi"),
            ("novi_red_ispred", "vrijedi", "vrijedi"),
            ("novi_red_iza", "vrijedi", "vrijedi"),
            ("crlf_iza", "vrijedi", "vrijedi"),
            ("novi_red_u_sredini", "vrijedi", "kriv:potpis"),
            ("novi_red_u_paddingu", "vrijedi", "kriv:potpis"),
            ("visak_bitova", "vrijedi", "kriv:potpis"),
            ("url_safe", "kriv:potpis", "kriv:potpis"),
            ("nekanonski_s", "kriv:potpis", "kriv:potpis"),
            ("visoki_bit", "kriv:potpis", "kriv:potpis"),
        ];

        /// The signature of a membership the network key signed is read as Go reads it.
        #[test]
        fn membership_signature_reads_as_in_go() {
            let mut m = Membership {
                network: b64(&net().verifying_key()),
                device_id: "clan-1".into(),
                device_key: b64(&member().verifying_key()),
                issued_by: "admin-1".into(),
                issued_at: AT,
                expires_at: AT + 24 * 3600,
                signature: String::new(),
                admitter: None,
            };
            let raw = net().sign(&m.signed_bytes()).to_bytes();
            // The signature Go prints for the same membership.
            assert_eq!(
                raw,
                sig_of(
                    "L7PO8Xy8U4flarX9thC28+fDPKt1qM2C/8Nr0JGaRNO7hXaS/TMbiUZ9IH/LFNW+Vz9vBt/2I9jdUf/cieexDg=="
                )
            );
            assert_signature_edges_as_in_go(&SIGNED, &raw, |text| {
                m.signature = text.into();
                verdict(m.verify(&net().verifying_key(), &member().verifying_key(), AT + 100))
            });
        }

        /// The signature of an ovlast is read as Go reads it.
        #[test]
        fn ovlast_signature_reads_as_in_go() {
            let mut o = Ovlast {
                network: b64(&net().verifying_key()),
                device_id: "primatelj-1".into(),
                device_key: b64(&signer().verifying_key()),
                issued_by: "admin-1".into(),
                issued_at: AT,
                expires_at: AT + 48 * 3600,
                signature: String::new(),
            };
            let raw = net().sign(&o.signed_bytes()).to_bytes();
            assert_eq!(
                raw,
                sig_of(
                    "rdUnuNOl877eDNRNe+ygVKX7y9SNs3dMBlw+Ty3BHEA4zO5e86onv4L4iMNs6zNK8itchFYSNoPOIjRP3APKBA=="
                )
            );
            assert_signature_edges_as_in_go(&SIGNED, &raw, |text| {
                o.signature = text.into();
                verdict(o.verify(&net().verifying_key(), AT + 100))
            });
        }

        /// The signature of a revocation is read as Go reads it, both for its id and for
        /// the check that the signer signed it. The id is made from the edge's text, as
        /// the one who wrote it would make it.
        #[test]
        fn revocation_signature_reads_as_in_go() {
            let mut r = Revocation {
                id: String::new(),
                kind: "clanstvo".into(),
                target_id: "cvor-1".into(),
                public_key: b64(&member().verifying_key()),
                issued_at: AT,
                revoked_at: AT + 3600,
                revoked_by: "admin-1".into(),
                signer_key: b64(&signer().verifying_key()),
                signature: String::new(),
            };
            let raw = signer().sign(&r.signed_bytes()).to_bytes();
            assert_eq!(
                raw,
                sig_of(
                    "ipQlrR8K+8NMe6gvXG1u90Dgi1v4AFqKvuvV/KjeVZgzH9ABguHZxBS5sAOcWysNTkBV/Wwc3gGe0VwYijWFDw=="
                )
            );
            r.signature = STANDARD.encode(raw);
            let canonical_id = r.compute_id().unwrap();
            #[rustfmt::skip]
            let table = [
                ("ispravno", "ispravan", "ispravan"),
                ("prazno", "neispravan", "neispravan"),
                ("samo_razmak", "neispravan", "neispravan"),
                ("nije_base64", "neispravan", "neispravan"),
                ("63B", "neispravan", "neispravan"),
                ("65B", "neispravan", "neispravan"),
                ("bez_paddinga", "neispravan", "neispravan"),
                ("visak_paddinga", "neispravan", "neispravan"),
                ("razmak_ispred", "neispravan", "neispravan"),
                ("razmak_iza", "neispravan", "neispravan"),
                ("tab_iza", "neispravan", "neispravan"),
                ("novi_red_ispred", "ispravan", "neispravan"),
                ("novi_red_iza", "ispravan", "neispravan"),
                ("crlf_iza", "ispravan", "neispravan"),
                ("novi_red_u_sredini", "ispravan", "neispravan"),
                ("novi_red_u_paddingu", "ispravan", "neispravan"),
                ("visak_bitova", "ispravan", "neispravan"),
                ("url_safe", "neispravan", "neispravan"),
                ("nekanonski_s", "neispravan", "neispravan"),
                ("visoki_bit", "neispravan", "neispravan"),
            ];
            assert_signature_edges_as_in_go(&table, &raw, |text| {
                r.signature = text.into();
                r.id = r.compute_id().unwrap_or_default();
                match r.verify_self() {
                    Ok(_) => {
                        // As in Go: a text that reads to the same bytes gives the same id.
                        assert_eq!(r.id, canonical_id);
                        "ispravan".into()
                    }
                    Err(_) => "neispravan".into(),
                }
            });
        }

        /// The older envelope reads its signature as the shared version signature is read
        /// (the Go column is that one, over its own signed bytes).
        #[test]
        fn envelope_signature_reads_as_the_shared_signature() {
            let mut v = SignedVersionEnvelope {
                version_id: "v1".into(),
                entity: "users".into(),
                entity_id: "korisnik-1".into(),
                node_id: "admin-1".into(),
                supersedes: String::new(),
                archived: false,
                channel: String::new(),
                created_at: "2025-10-09T08:53:20Z".into(),
                created_at_unix: AT,
                schema_version: 1,
                author_pub_key: String::new(),
                grant_ref: String::new(),
                payload: "{}".into(),
                signature: String::new(),
            }
            .sign("gocop", &signer());
            let raw = sig_of(&v.signature);
            assert_signature_edges_as_in_go(&SIGNED, &raw, |text| {
                v.signature = text.into();
                verdict(v.verify_signature("gocop").map(|_| ()))
            });
        }
    }
}
