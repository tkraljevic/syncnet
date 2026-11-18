use crate::identity::{parse_public_key, public_key_to_base64};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_CLOCK_SKEW_SECS: i64 = 3600;
pub const OVLAST_CANONICAL_VERSION: &str = "ovlast/1";
pub const REVOCATION_CANONICAL_VERSION: &str = "opoziv/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    OwnDevice,
    FamilyMember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListPermission {
    Read,
    Write,
}

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
            Self::OtherNetwork => write!(f, "potvrda pripada drugoj mrezi"),
            Self::KeyMismatch => write!(f, "potvrda glasi na drugi kljuc uredjaja"),
            Self::BadSignature => write!(f, "potpis potvrde ne vrijedi"),
            Self::Expired => write!(f, "potvrda je istekla"),
            Self::NotYetValid => write!(f, "potvrda jos nije vazeca"),
            Self::IssuedInFuture => write!(f, "potvrda je izdana previse u buducnosti"),
            Self::ExceedsAdmitterAuthority => write!(f, "potvrda prelazi ovlast izdavatelja"),
            Self::IssuerMismatch => write!(f, "izdavatelj ne odgovara ovlasti"),
            Self::UnauthorizedSigner => write!(f, "potpisnik nije ovlasten za ovu radnju"),
            Self::Revoked => write!(f, "kljuc ili ovlast je opozvana"),
            Self::InvalidFormat(m) => write!(f, "neispravan zapis povjerenja: {m}"),
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
    fn expires_at(self) -> Result<i64, TrustError> {
        if self.valid_for_secs <= 0 {
            return Err(TrustError::InvalidFormat(
                "trajanje mora biti pozitivno".into(),
            ));
        }
        self.issued_at
            .checked_add(self.valid_for_secs)
            .ok_or_else(|| TrustError::InvalidFormat("rok valjanosti je izvan raspona".into()))
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
        let sk = self
            .private
            .as_ref()
            .ok_or(TrustError::UnauthorizedSigner)?;
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
        role: MemberRole,
        principal_id: &str,
        issued_by: &str,
        validity: Validity,
    ) -> Result<Membership, TrustError> {
        let sk = self
            .private
            .as_ref()
            .ok_or(TrustError::UnauthorizedSigner)?;
        let mut m = Membership {
            network: self.public_b64(),
            device_id: device_id.to_owned(),
            device_key: public_key_to_base64(device_key.as_bytes()),
            role,
            principal_id: principal_id.to_owned(),
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

    pub fn issue_list_grant(
        &self,
        grant_id: &str,
        list_sync_id: &str,
        recipient_key: &VerifyingKey,
        permission: ListPermission,
        issued_by: &str,
        validity: Validity,
    ) -> Result<ListGrant, TrustError> {
        let sk = self
            .private
            .as_ref()
            .ok_or(TrustError::UnauthorizedSigner)?;
        let mut g = ListGrant {
            network: self.public_b64(),
            grant_id: grant_id.to_owned(),
            list_sync_id: list_sync_id.to_owned(),
            recipient_pub_key: public_key_to_base64(recipient_key.as_bytes()),
            permission,
            issued_by: issued_by.to_owned(),
            issued_at: validity.issued_at,
            expires_at: validity.expires_at()?,
            signature: String::new(),
            admitter: None,
        };
        let sig = sk.sign(&g.signed_bytes());
        g.signature = STANDARD.encode(sig.to_bytes());
        Ok(g)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ovlast {
    pub network: String,
    pub device_id: String,
    pub device_key: String,
    pub issued_by: String,
    pub issued_at: i64,
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
    pub role: MemberRole,
    pub principal_id: String,
    pub issued_by: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
                role: MemberRole,
                principal_id: &'a str,
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
                role: self.role,
                principal_id: &self.principal_id,
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
                role: MemberRole,
                principal_id: &'a str,
                issued_by: &'a str,
                issued_at: i64,
                expires_at: i64,
            }
            serde_json::to_vec(&CanonicalV1 {
                v: 1,
                network: &self.network,
                device_id: &self.device_id,
                device_key: &self.device_key,
                role: self.role,
                principal_id: &self.principal_id,
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
        role: MemberRole,
        principal_id: &str,
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
            role,
            principal_id: principal_id.to_owned(),
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
pub struct ListGrant {
    pub network: String,
    pub grant_id: String,
    pub list_sync_id: String,
    pub recipient_pub_key: String,
    pub permission: ListPermission,
    pub issued_by: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitter: Option<Ovlast>,
}

impl ListGrant {
    pub fn signed_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Canonical<'a> {
            v: &'a str,
            network: &'a str,
            grant_id: &'a str,
            list_sync_id: &'a str,
            recipient_pub_key: &'a str,
            permission: ListPermission,
            issued_by: &'a str,
            issued_at: i64,
            expires_at: i64,
            ovlast: &'a str,
        }
        let ovlast_sig = self
            .admitter
            .as_ref()
            .map(|o| o.signature.as_str())
            .unwrap_or("");
        serde_json::to_vec(&Canonical {
            v: "listgrant/1",
            network: &self.network,
            grant_id: &self.grant_id,
            list_sync_id: &self.list_sync_id,
            recipient_pub_key: &self.recipient_pub_key,
            permission: self.permission,
            issued_by: &self.issued_by,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            ovlast: ovlast_sig,
        })
        .expect("canonical listgrant serializes")
    }

    pub fn verify(
        &self,
        network_pub: &VerifyingKey,
        recipient_key: &VerifyingKey,
        now_unix: i64,
    ) -> Result<(), TrustError> {
        if self.network != public_key_to_base64(network_pub.as_bytes()) {
            return Err(TrustError::OtherNetwork);
        }
        if self.recipient_pub_key != public_key_to_base64(recipient_key.as_bytes()) {
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
    pub kind: String,
    pub target_id: String,
    pub public_key: String,
    pub issued_at: i64,
    pub revoked_at: i64,
    pub revoked_by: String,
    pub signer_key: String,
    pub signature: String,
}

impl Revocation {
    pub fn scope(&self) -> Result<&'static str, TrustError> {
        match self.kind.as_str() {
            "clanstvo" | "membership" => Ok("membership"),
            "list_grant" => Ok("list_grant"),
            "ovlast" => Ok("ovlast"),
            _ => Err(TrustError::InvalidFormat("nepoznata vrsta opoziva".into())),
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
                "neispravan predmet ili vrijeme opoziva".into(),
            ));
        }
        let signer = parse_public_key(&self.signer_key).map_err(|_| TrustError::BadSignature)?;
        let expected_id = self.compute_id()?;
        if self.id != expected_id {
            return Err(TrustError::InvalidFormat(
                "neispravan ID opoziva".to_owned(),
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
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        // A JSON tuple is unambiguous even when identifiers contain separators.
        // Bind *all* routing and identity metadata, not only the displayed payload.
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
        let mut out = b"list2cart-ver-v1|".to_vec();
        out.extend(serde_json::to_vec(&fields).expect("version fields serialize"));
        out
    }

    pub fn sign(mut self, sk: &SigningKey) -> Self {
        self.author_pub_key = public_key_to_base64(sk.verifying_key().as_bytes());
        let sig = sk.sign(&self.canonical_signing_bytes());
        self.signature = STANDARD.encode(sig.to_bytes());
        self
    }

    pub fn verify_signature(&self) -> Result<VerifyingKey, TrustError> {
        let vk = parse_public_key(&self.author_pub_key).map_err(|_| TrustError::BadSignature)?;
        verify_ed25519_b64(&vk, &self.canonical_signing_bytes(), &self.signature)?;
        Ok(vk)
    }
}

fn verify_admitter_chain(
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
        return Err(TrustError::InvalidFormat("rok je prije izdavanja".into()));
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

fn verify_ed25519_b64(vk: &VerifyingKey, msg: &[u8], sig_b64: &str) -> Result<(), TrustError> {
    let sig_bytes = STANDARD
        .decode(sig_b64.trim())
        .map_err(|_| TrustError::BadSignature)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| TrustError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig).map_err(|_| TrustError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{generate_signing_key, principal_id_from_key};

    #[test]
    fn membership_ovlast_grant_and_revocation_chain() {
        let net_sk = generate_signing_key();
        let net = NetworkKey::from_signing_key("Obitelj", net_sk.clone());

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

        let principal = principal_id_from_key(net.public.as_bytes());
        let mem = Membership::admit_as(
            &admin_sk,
            ovlast,
            "fam-1",
            &member_vk,
            MemberRole::FamilyMember,
            &principal,
            Validity {
                issued_at: now + 10,
                valid_for_secs: 1800,
            },
        )
        .expect("admit_as");
        mem.verify(&net.public, &member_vk, now + 500)
            .expect("verify membership");

        let grant = net
            .issue_list_grant(
                "g-1",
                "list-uuid-1",
                &member_vk,
                ListPermission::Write,
                "root",
                Validity {
                    issued_at: now,
                    valid_for_secs: 3600,
                },
            )
            .expect("grant");
        grant
            .verify(&net.public, &member_vk, now + 100)
            .expect("verify grant");

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
        let grant_rev = Revocation {
            kind: "list_grant".into(),
            target_id: "g-1".into(),
            ..rev.clone()
        }
        .sign(&net_sk);
        grant_rev.verify_self().unwrap();
        assert!(
            !grant_rev.revokes(&public_key_to_base64(member_vk.as_bytes()), mem.issued_at),
            "a grant revocation does not revoke a device key"
        );
    }

    #[test]
    fn rejects_membership_exceeding_ovlast_or_wrong_key() {
        let net_sk = generate_signing_key();
        let net = NetworkKey::from_signing_key("Obitelj", net_sk);
        let other_sk = generate_signing_key();
        let member_sk = generate_signing_key();
        let member_vk = member_sk.verifying_key();

        let now = 1_760_000_000i64;
        let mem = net
            .admit_member(
                "dev-1",
                &member_vk,
                MemberRole::OwnDevice,
                "p-1",
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
        .sign(&sk);
        assert!(v.verify_signature().is_ok());
        let mut changed = v.clone();
        changed.node_id = "device-b".into();
        assert_eq!(changed.verify_signature(), Err(TrustError::BadSignature));
        changed = v.clone();
        changed.created_at = "2020-01-01T00:00:00Z".into();
        assert_eq!(changed.verify_signature(), Err(TrustError::BadSignature));
        changed = v.clone();
        changed.entity = "shopping_lists|list".into();
        changed.entity_id = "one".into();
        assert_ne!(
            v.canonical_signing_bytes(),
            changed.canonical_signing_bytes()
        );
        assert_eq!(changed.verify_signature(), Err(TrustError::BadSignature));
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
                MemberRole::OwnDevice,
                "p",
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
            assert!(
                net.admit_member("dev", &device, MemberRole::OwnDevice, "p", "root", validity)
                    .is_err()
            );
        }
    }
}
