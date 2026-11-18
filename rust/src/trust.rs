use crate::identity::{parse_public_key, public_key_to_base64};
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
        serde_json::to_vec(&Canonical {
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
            serde_json::to_vec(&CanonicalV2 {
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
            serde_json::to_vec(&CanonicalV1 {
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
        serde_json::to_vec(&Canonical {
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

    pub fn compute_id(&self) -> Result<String, TrustError> {
        let sig = STANDARD
            .decode(&self.signature)
            .map_err(|_| TrustError::BadSignature)?;
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

    pub fn verify_self(&self) -> Result<VerifyingKey, TrustError> {
        self.scope()?;
        let subject = parse_public_key(&self.public_key).map_err(|_| TrustError::BadSignature)?;
        if public_key_to_base64(subject.as_bytes()) != self.public_key
            || self.target_id.is_empty()
            || self.issued_at < 0
            || self.revoked_at < self.issued_at
        {
            return Err(TrustError::InvalidFormat(
                "invalid revocation subject or timestamps".into(),
            ));
        }
        let signer = parse_public_key(&self.signer_key).map_err(|_| TrustError::BadSignature)?;
        let expected_id = self.compute_id()?;
        if self.id != expected_id {
            return Err(TrustError::InvalidFormat(
                "invalid revocation id".to_owned(),
            ));
        }
        verify_ed25519_b64(&signer, &self.signed_bytes(), &self.signature)?;
        Ok(signer)
    }

    pub fn revokes(&self, subject_pub_b64: &str, issued_at: i64) -> bool {
        self.scope() == Ok("membership")
            && self.public_key == subject_pub_b64
            && issued_at <= self.issued_at
    }
}

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

    pub fn verify_signature(&self, protocol: &str) -> Result<VerifyingKey, TrustError> {
        let vk = parse_public_key(&self.author_pub_key).map_err(|_| TrustError::BadSignature)?;
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
    if issued_at > now_unix.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(TrustError::IssuedInFuture);
    }
    if issued_at > now_unix {
        return Err(TrustError::NotYetValid);
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
    parse_public_key(&ovlast.device_key).map_err(|_| TrustError::BadSignature)
}

pub fn verify_ed25519_b64(vk: &VerifyingKey, msg: &[u8], sig_b64: &str) -> Result<(), TrustError> {
    let sig_bytes = STANDARD
        .decode(sig_b64.trim())
        .map_err(|_| TrustError::BadSignature)?;
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
        let b = s.as_bytes();
        if b.len() < 20
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
            if &rest[3..4] != ":" {
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
}
