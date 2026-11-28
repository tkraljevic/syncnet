use crate::identity::{parse_public_key, parse_public_key_bytes, public_key_to_base64};
use crate::wire::go_base64::decode_std;
use crate::wire::go_json::to_go_json_vec;
use crate::wire::go_object::{Field, Kind, Schema, go_struct};
use crate::wire::go_time::GoTime;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_CLOCK_SKEW_SECS: i64 = 3600;
pub const OVLAST_CANONICAL_VERSION: &str = "ovlast/1";
pub const REVOCATION_CANONICAL_VERSION: &str = "opoziv/1";
/// The kind (`vrsta`) of a revocation that revokes a membership.
pub const REVOCATION_KIND_MEMBERSHIP: &str = "clanstvo";
/// The kind (`vrsta`) of a revocation that revokes an ovlast.
pub const REVOCATION_KIND_OVLAST: &str = "ovlast";

/// Go's zero time (`0001-01-01T00:00:00Z`, what Go writes for a time never set) in Unix
/// seconds. It is how no expiry is written on the wire and in the signed bytes. In code
/// no expiry is [`Expiry::NEVER`], not this number. Any other time is a time, 1970 (0)
/// and earlier ones too: Go takes them as long past.
pub const GO_ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// When an ovlast or a membership stops holding (`expiresAt`).
///
/// On the wire and in the signed bytes `expiresAt` is a time, and only Go's zero time
/// ([`GO_ZERO_TIME_UNIX`]) means no expiry (PROTOKOL §7). `0` is 1970 and has long
/// passed. A bare number is not an expiry, so code that hands over `0` meaning "no
/// expiry" does not compile:
///
/// ```compile_fail
/// use syncnet::trust::verify_admitter_chain;
/// let network = syncnet::identity::generate_signing_key().verifying_key();
/// let now = 1_760_000_000;
/// let _ = verify_admitter_chain(&network, None, "root", now, 0, now);
/// ```
///
/// No expiry has to be said, and a time has to be said as one:
///
/// ```
/// use syncnet::trust::{Expiry, verify_admitter_chain};
/// let network = syncnet::identity::generate_signing_key().verifying_key();
/// let now = 1_760_000_000;
/// assert!(verify_admitter_chain(&network, None, "root", now, Expiry::NEVER, now).is_ok());
/// assert!(Expiry::from_wire_unix(0).is_expired_at(now));
/// assert!(!Expiry::NEVER.is_expired_at(i64::MAX));
/// ```
///
/// The value is the wire's `expiresAt` and nothing else, so no expiry has one form
/// only: [`Expiry::NEVER`] and `Expiry::from_wire_unix(GO_ZERO_TIME_UNIX)` are the same
/// value. Read the time with [`Expiry::last_second`], which gives `None` for no expiry.
///
/// A time read from the wire keeps the part of a second it was written with
/// ([`Expiry::nanos`]), as Go keeps it: the signature covers whole seconds only, but Go
/// compares two records' times in full, so here they are compared the same way. Go and
/// Rust write whole seconds; a part of a second comes only from a record written by
/// hand or changed on the way.
///
/// There is no `From<i64>` and no serde of its own: a number becomes an expiry only
/// through [`Expiry::from_wire_unix`], and a record says how it writes one (the records
/// here use [`rfc3339_unix::expiry`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Expiry(i64, u32);

impl Expiry {
    /// No expiry. Written as Go's zero time.
    pub const NEVER: Self = Self(GO_ZERO_TIME_UNIX, 0);

    /// The expiry a wire or signed `expiresAt` stands for: exactly
    /// [`GO_ZERO_TIME_UNIX`] is no expiry, anything else is that time, 0 too (1970).
    ///
    /// Only for a number written as the wire writes it. A record of your own where 0
    /// means no expiry must turn its 0 into [`Expiry::NEVER`] itself; read through here
    /// that 0 is 1970, and a record that should have no expiry passes the admitter's
    /// limit and holds for ever.
    pub const fn from_wire_unix(unix: i64) -> Self {
        Self(unix, 0)
    }

    /// A time as read from the wire, with its part of a second.
    pub(crate) const fn from_go_time(t: GoTime) -> Self {
        Self(t.unix, t.nanos)
    }

    /// The `expiresAt` signed, and written on the wire with [`Expiry::nanos`]:
    /// [`GO_ZERO_TIME_UNIX`] for no expiry. `Expiry::from_wire_unix(e.wire_unix()) == e`
    /// when `e.nanos()` is 0.
    pub const fn wire_unix(self) -> i64 {
        self.0
    }

    /// The part of a second past [`Expiry::wire_unix`] the record was written with, in
    /// nanoseconds; 0 for a record Go or Rust issued. It is not signed.
    pub const fn nanos(self) -> u32 {
        self.1
    }

    /// The time as Go compares it.
    const fn instant(self) -> Instant {
        (self.0, self.1)
    }

    /// Whether it has passed at `at`, compared in full as Go compares it.
    fn passed_at(self, at: Instant) -> bool {
        !self.is_never() && at > self.instant()
    }

    /// Whether a record with this expiry runs longer than one with `limit`, as Go asks it:
    /// no expiry runs longer than any time, and no limit is never exceeded.
    fn runs_longer_than(self, limit: Self) -> bool {
        !limit.is_never() && (self.is_never() || self.instant() > limit.instant())
    }

    /// The last second it holds (Unix seconds), or `None` for no expiry.
    pub const fn last_second(self) -> Option<i64> {
        if self.is_never() { None } else { Some(self.0) }
    }

    /// Whether this is no expiry.
    pub const fn is_never(self) -> bool {
        self.0 == GO_ZERO_TIME_UNIX && self.1 == 0
    }

    /// Whether it has passed at `at_unix` (a whole second, as the clock is read here).
    /// The expiry second itself still holds, with any part of a second.
    pub const fn is_expired_at(self, at_unix: i64) -> bool {
        match self.last_second() {
            Some(last) => at_unix > last,
            None => false,
        }
    }
}

/// A time as Go compares two of them: Unix seconds, then the nanoseconds past them.
type Instant = (i64, u32);

impl fmt::Debug for Expiry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.last_second() {
            None => f.write_str("Expiry::NEVER"),
            Some(unix) if self.1 == 0 => write!(f, "Expiry({unix})"),
            Some(unix) => write!(f, "Expiry({unix}.{:09})", self.1),
        }
    }
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
    /// The admitter's ovlast does not hold at the membership's `issuedAt`: the reason the
    /// ovlast's own check gave. Go gives the same kind here as for the other rules on the
    /// admitter (`ExceedsAdmitterAuthority`, `IssuedInFuture`), not that of the membership.
    AdmitterOvlast(Box<TrustError>),
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
            Self::AdmitterOvlast(e) => write!(f, "admitter's ovlast does not hold: {e}"),
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
    /// `issued_at + valid_for_secs`, read as the wire reads it.
    pub fn expires_at(self) -> Result<Expiry, TrustError> {
        if self.valid_for_secs <= 0 {
            return Err(TrustError::InvalidFormat(
                "validity duration must be positive".into(),
            ));
        }
        self.issued_at
            .checked_add(self.valid_for_secs)
            .map(Expiry::from_wire_unix)
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
            issued_at_nanos: 0,
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
            issued_at_nanos: 0,
            expires_at: validity.expires_at()?,
            signature: String::new(),
            admitter: None,
        };
        let sig = sk.sign(&m.signed_bytes());
        m.signature = STANDARD.encode(sig.to_bytes());
        Ok(m)
    }
}

/// Read as Go reads it (see [`crate::wire::go_object`] and [`rfc3339_unix`]): field names
/// in any ASCII case, the last of a repeated field, and a missing field, or `null`, as
/// Go's empty value: an empty text, and Go's zero time for a time, so a missing
/// `expiresAt` is no expiry. The signature then decides, as in Go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ovlast {
    pub network: String,
    pub device_id: String,
    pub device_key: String,
    pub issued_by: String,
    pub issued_at: i64,
    /// The part of a second past `issued_at` the record was written with, in
    /// nanoseconds, as Go keeps it (see [`Expiry`]). 0 for a record Go or Rust issued; it
    /// is not signed, but Go compares it.
    pub issued_at_nanos: u32,
    pub expires_at: Expiry,
    pub signature: String,
}

/// An ovlast as the wire carries it, its times in full.
#[derive(Serialize, Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase")]
struct OvlastWire {
    #[serde(default)]
    network: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    device_key: String,
    #[serde(default)]
    issued_by: String,
    #[serde(default = "go_zero_time", with = "rfc3339_unix::time")]
    issued_at: GoTime,
    #[serde(default = "no_expiry", with = "rfc3339_unix::expiry")]
    expires_at: Expiry,
    #[serde(default)]
    signature: String,
}

/// Go's field names (`json` tags) of an ovlast.
pub(crate) const OVLAST_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("network"),
        Field::value("deviceId"),
        Field::value("deviceKey"),
        Field::value("issuedBy"),
        Field::time("issuedAt"),
        Field::time("expiresAt"),
        Field::value("signature"),
    ],
    baseline: &[],
};
go_struct!(OvlastWire, OVLAST_SCHEMA);

impl From<OvlastWire> for Ovlast {
    fn from(w: OvlastWire) -> Self {
        Self {
            network: w.network,
            device_id: w.device_id,
            device_key: w.device_key,
            issued_by: w.issued_by,
            issued_at: w.issued_at.unix,
            issued_at_nanos: w.issued_at.nanos,
            expires_at: w.expires_at,
            signature: w.signature,
        }
    }
}

impl From<&Ovlast> for OvlastWire {
    fn from(o: &Ovlast) -> Self {
        Self {
            network: o.network.clone(),
            device_id: o.device_id.clone(),
            device_key: o.device_key.clone(),
            issued_by: o.issued_by.clone(),
            issued_at: o.issued_at(),
            expires_at: o.expires_at,
            signature: o.signature.clone(),
        }
    }
}

impl Serialize for Ovlast {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        <OvlastWire as Serialize>::serialize(&OvlastWire::from(self), s)
    }
}

impl<'de> Deserialize<'de> for Ovlast {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // The trait's reader (Go's rules), not the derive's own `OvlastWire::deserialize`.
        <OvlastWire as Deserialize>::deserialize(d).map(Self::from)
    }
}

fn go_zero_time() -> GoTime {
    GoTime {
        unix: GO_ZERO_TIME_UNIX,
        nanos: 0,
    }
}

fn no_expiry() -> Expiry {
    Expiry::NEVER
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
            expires_at: self.expires_at.wire_unix(),
        })
        .expect("canonical ovlast serializes")
    }

    /// Whether the ovlast holds at `at_unix`, a whole second. The ovlast's own times are
    /// compared in full, as Go compares them: one issued at `at_unix` and a half does not
    /// hold yet at `at_unix`.
    pub fn verify(&self, network_pub: &VerifyingKey, at_unix: i64) -> Result<(), TrustError> {
        self.verify_at(network_pub, (at_unix, 0))
    }

    fn verify_at(&self, network_pub: &VerifyingKey, at: Instant) -> Result<(), TrustError> {
        if self.network != public_key_to_base64(network_pub.as_bytes()) {
            return Err(TrustError::OtherNetwork);
        }
        verify_ed25519_b64(network_pub, &self.signed_bytes(), &self.signature)?;
        if at < (self.issued_at, self.issued_at_nanos) {
            return Err(TrustError::NotYetValid);
        }
        if self.expires_at.passed_at(at) {
            return Err(TrustError::Expired);
        }
        Ok(())
    }

    fn issued_at(&self) -> GoTime {
        GoTime {
            unix: self.issued_at,
            nanos: self.issued_at_nanos,
        }
    }
}

/// Read as Go reads it, as [`Ovlast`] is. The admitter's ovlast is read only under Go's
/// name `primatelj`; objects given for it more than once add up, and `null` clears it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub network: String,
    pub device_id: String,
    pub device_key: String,
    pub issued_by: String,
    pub issued_at: i64,
    /// The part of a second past `issued_at`, as in [`Ovlast::issued_at_nanos`].
    pub issued_at_nanos: u32,
    pub expires_at: Expiry,
    pub signature: String,
    pub admitter: Option<Ovlast>,
}

/// A membership as the wire carries it, its times in full.
#[derive(Serialize, Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase")]
struct MembershipWire {
    #[serde(default)]
    network: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    device_key: String,
    #[serde(default)]
    issued_by: String,
    #[serde(default = "go_zero_time", with = "rfc3339_unix::time")]
    issued_at: GoTime,
    #[serde(default = "no_expiry", with = "rfc3339_unix::expiry")]
    expires_at: Expiry,
    #[serde(default)]
    signature: String,
    #[serde(rename = "primatelj", default, skip_serializing_if = "Option::is_none")]
    admitter: Option<Ovlast>,
}

/// Go's field names (`json` tags) of a membership.
pub(crate) const MEMBERSHIP_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("network"),
        Field::value("deviceId"),
        Field::value("deviceKey"),
        Field::value("issuedBy"),
        Field::time("issuedAt"),
        Field::time("expiresAt"),
        Field::value("signature"),
        Field::new("primatelj", Kind::Struct),
    ],
    baseline: &[],
};
go_struct!(MembershipWire, MEMBERSHIP_SCHEMA);

impl From<MembershipWire> for Membership {
    fn from(w: MembershipWire) -> Self {
        Self {
            network: w.network,
            device_id: w.device_id,
            device_key: w.device_key,
            issued_by: w.issued_by,
            issued_at: w.issued_at.unix,
            issued_at_nanos: w.issued_at.nanos,
            expires_at: w.expires_at,
            signature: w.signature,
            admitter: w.admitter,
        }
    }
}

impl From<&Membership> for MembershipWire {
    fn from(m: &Membership) -> Self {
        Self {
            network: m.network.clone(),
            device_id: m.device_id.clone(),
            device_key: m.device_key.clone(),
            issued_by: m.issued_by.clone(),
            issued_at: GoTime {
                unix: m.issued_at,
                nanos: m.issued_at_nanos,
            },
            expires_at: m.expires_at,
            signature: m.signature.clone(),
            admitter: m.admitter.clone(),
        }
    }
}

impl Serialize for Membership {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        <MembershipWire as Serialize>::serialize(&MembershipWire::from(self), s)
    }
}

impl<'de> Deserialize<'de> for Membership {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // The trait's reader (Go's rules), not the derive's own `MembershipWire::deserialize`.
        <MembershipWire as Deserialize>::deserialize(d).map(Self::from)
    }
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
                expires_at: self.expires_at.wire_unix(),
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
                expires_at: self.expires_at.wire_unix(),
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
        // As Go: the ovlast's own times count in full, the membership's are whole seconds.
        if (issued_at, 0) < (ovlast.issued_at, ovlast.issued_at_nanos)
            || ovlast.expires_at.is_expired_at(issued_at)
        {
            return Err(TrustError::Expired);
        }
        let mut exp = validity.expires_at()?;
        if exp.runs_longer_than(ovlast.expires_at) {
            exp = ovlast.expires_at;
        }
        let issued_by = ovlast.device_id.clone();
        let mut m = Self {
            network: ovlast.network.clone(),
            device_id: device_id.to_owned(),
            device_key: public_key_to_base64(device_key.as_bytes()),
            issued_by,
            issued_at,
            issued_at_nanos: 0,
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
        let signer = admitter_chain(
            network_pub,
            self.admitter.as_ref(),
            &self.issued_by,
            (self.issued_at, self.issued_at_nanos),
            self.expires_at,
            now_unix,
        )?;
        verify_ed25519_b64(&signer, &self.signed_bytes(), &self.signature)?;
        if self.expires_at.is_expired_at(now_unix) {
            return Err(TrustError::Expired);
        }
        Ok(())
    }
}

/// Read as Go reads it, as [`Ovlast`] is, and only under Go's field names: `kind`,
/// `targetId`, `revokedAt`, `revokedBy`, `signerKey` and `signature` name nothing in Go,
/// so a revocation written with them reads as one with those fields empty, whose
/// signature does not hold.
///
/// Its times keep the part of a second they were written with (`issued_at_nanos`,
/// `revoked_at_nanos`) and are written back with it, as Go writes them. The signature and
/// the id cover whole seconds only, and Go decides on whole seconds too (a revocation
/// revokes what was issued up to its second), so the part of a second changes no outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub id: String,
    pub kind: String,
    pub target_id: String,
    pub public_key: String,
    pub issued_at: i64,
    /// The part of a second past `issued_at`, in nanoseconds; 0 for a revocation Go or
    /// Rust signed. Not signed.
    pub issued_at_nanos: u32,
    pub revoked_at: i64,
    /// The part of a second past `revoked_at`, as `issued_at_nanos`.
    pub revoked_at_nanos: u32,
    pub revoked_by: String,
    pub signer_key: String,
    pub signature: String,
}

/// A revocation as the wire carries it, its times in full.
#[derive(Serialize, Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase")]
struct RevocationWire {
    #[serde(default)]
    id: String,
    #[serde(rename = "vrsta", default)]
    kind: String,
    #[serde(rename = "nodeId", default)]
    target_id: String,
    #[serde(default)]
    public_key: String,
    #[serde(default = "go_zero_time", with = "rfc3339_unix::time")]
    issued_at: GoTime,
    #[serde(
        rename = "opozvanoAt",
        default = "go_zero_time",
        with = "rfc3339_unix::time"
    )]
    revoked_at: GoTime,
    #[serde(rename = "opozvao", default)]
    revoked_by: String,
    #[serde(rename = "potpisnik", default)]
    signer_key: String,
    #[serde(rename = "potpis", default)]
    signature: String,
}

/// Go's field names (`json` tags) of a revocation.
pub(crate) const REVOCATION_SCHEMA: Schema = Schema {
    fields: &[
        Field::value("id"),
        Field::value("vrsta"),
        Field::value("nodeId"),
        Field::value("publicKey"),
        Field::time("issuedAt"),
        Field::time("opozvanoAt"),
        Field::value("opozvao"),
        Field::value("potpisnik"),
        Field::value("potpis"),
    ],
    baseline: &[],
};
go_struct!(RevocationWire, REVOCATION_SCHEMA);

impl From<RevocationWire> for Revocation {
    fn from(w: RevocationWire) -> Self {
        Self {
            id: w.id,
            kind: w.kind,
            target_id: w.target_id,
            public_key: w.public_key,
            issued_at: w.issued_at.unix,
            issued_at_nanos: w.issued_at.nanos,
            revoked_at: w.revoked_at.unix,
            revoked_at_nanos: w.revoked_at.nanos,
            revoked_by: w.revoked_by,
            signer_key: w.signer_key,
            signature: w.signature,
        }
    }
}

impl From<&Revocation> for RevocationWire {
    fn from(r: &Revocation) -> Self {
        Self {
            id: r.id.clone(),
            kind: r.kind.clone(),
            target_id: r.target_id.clone(),
            public_key: r.public_key.clone(),
            issued_at: GoTime {
                unix: r.issued_at,
                nanos: r.issued_at_nanos,
            },
            revoked_at: GoTime {
                unix: r.revoked_at,
                nanos: r.revoked_at_nanos,
            },
            revoked_by: r.revoked_by.clone(),
            signer_key: r.signer_key.clone(),
            signature: r.signature.clone(),
        }
    }
}

impl Serialize for Revocation {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        <RevocationWire as Serialize>::serialize(&RevocationWire::from(self), s)
    }
}

impl<'de> Deserialize<'de> for Revocation {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // The trait's reader (Go's rules), not the derive's own `RevocationWire::deserialize`.
        <RevocationWire as Deserialize>::deserialize(d).map(Self::from)
    }
}

/// What a revocation revokes, after its kind (`vrsta`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationScope<'a> {
    /// Exactly [`REVOCATION_KIND_MEMBERSHIP`].
    Membership,
    /// Exactly [`REVOCATION_KIND_OVLAST`].
    Ovlast,
    /// Any other kind, as written: one the application gives its own meaning, or one
    /// that revokes nothing.
    Other(&'a str),
}

impl Revocation {
    /// The kind is compared as written, as Go compares it: only `clanstvo` revokes a
    /// membership and only `ovlast` an ovlast. ` clanstvo`, `Clanstvo` or `membership`
    /// revoke neither (measured in Go); such a revocation can still be valid on its own
    /// (`verify_self`), it just revokes nothing Go knows.
    pub fn scope(&self) -> RevocationScope<'_> {
        match self.kind.as_str() {
            REVOCATION_KIND_MEMBERSHIP => RevocationScope::Membership,
            REVOCATION_KIND_OVLAST => RevocationScope::Ovlast,
            other => RevocationScope::Other(other),
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
    ///
    /// Nothing else is asked, as in Go (PROTOKOL §7: on arrival only the id and the
    /// signature): any kind, an empty `target_id`, any times. What the revocation revokes
    /// is for `revokes` and the caller.
    pub fn verify_self(&self) -> Result<VerifyingKey, TrustError> {
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
        self.scope() == RevocationScope::Membership
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

/// The key that may sign a membership: the network key, or the admitter whose ovlast the
/// membership carries. The rules and their order are Go's (PROTOKOL §7): they are for a
/// membership an admitter signed only, so one the network key signed has none of them.
/// The admitter's ovlast must hold at `issued_at`, the membership must not run longer than
/// the ovlast (one with no expiry runs longer than any ovlast that has one), `issued_at`
/// may run up to one hour ahead of the verifier's clock, and `issued_by` must be the
/// ovlast's device. Go does not ask that `expires_at` come after `issued_at`.
///
/// `expires_at` is the record's own expiry. A record that keeps it as a number reads it
/// with [`Expiry::from_wire_unix`] only when the number is the wire's (Go's zero time for
/// no expiry). A record where 0 means no expiry must pass [`Expiry::NEVER`] for its 0:
/// read as a wire number, 0 is 1970, earlier than any ovlast's limit, and the record
/// would pass here and then never expire.
///
/// `issued_at` is a whole second. The times of the ovlast and `expires_at` are compared
/// in full, as Go compares them ([`Expiry`]).
pub fn verify_admitter_chain(
    network_pub: &VerifyingKey,
    admitter: Option<&Ovlast>,
    issued_by: &str,
    issued_at: i64,
    expires_at: Expiry,
    now_unix: i64,
) -> Result<VerifyingKey, TrustError> {
    admitter_chain(
        network_pub,
        admitter,
        issued_by,
        (issued_at, 0),
        expires_at,
        now_unix,
    )
}

fn admitter_chain(
    network_pub: &VerifyingKey,
    admitter: Option<&Ovlast>,
    issued_by: &str,
    issued_at: Instant,
    expires_at: Expiry,
    now_unix: i64,
) -> Result<VerifyingKey, TrustError> {
    let Some(ovlast) = admitter else {
        return Ok(*network_pub);
    };
    ovlast
        .verify_at(network_pub, issued_at)
        .map_err(|e| TrustError::AdmitterOvlast(Box::new(e)))?;
    if expires_at.runs_longer_than(ovlast.expires_at) {
        return Err(TrustError::ExceedsAdmitterAuthority);
    }
    if issued_at > (now_unix.saturating_add(MAX_CLOCK_SKEW_SECS), 0) {
        return Err(TrustError::IssuedInFuture);
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
    use crate::wire::go_time::{self, GoTime};
    use serde::{Deserialize, Deserializer, Serializer, de};
    use serde_json::value::RawValue;

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

    /// A time as Go writes one (`time.RFC3339Nano` in UTC): the part of a second with
    /// the trailing zeros left out, and none at all for a whole second.
    pub fn format_utc_nanos(unix: i64, nanos: u32) -> String {
        let whole = format_utc(unix);
        if nanos == 0 {
            return whole;
        }
        let fraction = format!("{nanos:09}");
        format!(
            "{}.{}Z",
            &whole[..whole.len() - 1],
            fraction.trim_end_matches('0')
        )
    }

    /// Unix seconds (rounded down) of a time as Go reads one ([`go_time::parse`]).
    pub fn parse_utc(s: &str) -> Result<i64, String> {
        go_time::parse(s.as_bytes())
            .map(|t| t.unix)
            .ok_or_else(|| format!("invalid RFC 3339 timestamp {s:?}"))
    }

    /// Writes `text` for a time at `unix`, or fails as Go's `json.Marshal` does when the
    /// year in UTC is outside 0 to 9999: Go has no text for such a time, and the text
    /// written here would be read by neither side.
    fn write_go_time<S: Serializer>(unix: i64, text: String, ser: S) -> Result<S::Ok, S::Error> {
        // 0000-01-01T00:00:00Z to 9999-12-31T23:59:59Z; a part of a second stays in the year.
        if !(-62_167_219_200..=253_402_300_799).contains(&unix) {
            return Err(serde::ser::Error::custom(
                "vrijeme izvan godina 0 do 9999 ne može se zapisati",
            ));
        }
        ser.serialize_str(&text)
    }

    pub fn serialize<S: Serializer>(unix: &i64, ser: S) -> Result<S::Ok, S::Error> {
        write_go_time(*unix, format_utc(*unix), ser)
    }

    /// An [`Expiry`](super::Expiry) as the wire writes it: a time, Go's zero time for no
    /// expiry. It reads what [`rfc3339_unix::deserialize`](deserialize) reads, takes the
    /// seconds as [`Expiry::from_wire_unix`](super::Expiry::from_wire_unix) does, and keeps
    /// the part of a second, which it also writes back as Go does.
    ///
    /// Go's zero time with a part of a second (`0001-01-01T00:00:00.5Z`) is refused as a
    /// bad record. Go takes it as an expiry in year 1, so as long past for any check after
    /// year 1, and only a record issued in year 1 or earlier could still hold there. Its
    /// signed bytes are those of a record with no expiry (the signature covers whole
    /// seconds), so read here it would be no expiry. Only the value a record keeps is
    /// refused: one that a later repeat of the field overwrites is read as Go reads it.
    pub mod expiry {
        use super::super::{Expiry, GO_ZERO_TIME_UNIX};
        use crate::wire::go_object;
        use serde::{Deserializer, Serializer, de};

        pub fn serialize<S: Serializer>(expiry: &Expiry, ser: S) -> Result<S::Ok, S::Error> {
            let unix = expiry.wire_unix();
            super::write_go_time(unix, super::format_utc_nanos(unix, expiry.nanos()), ser)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Expiry, D::Error> {
            match super::read(de)? {
                Some(t)
                    if t.unix == GO_ZERO_TIME_UNIX
                        && t.nanos != 0
                        && !go_object::checking_repeat() =>
                {
                    Err(de::Error::custom(
                        "expiresAt: nulto vrijeme s dijelom sekunde",
                    ))
                }
                Some(t) => Ok(Expiry::from_go_time(t)),
                None => Ok(Expiry::NEVER),
            }
        }
    }

    /// A time with its part of a second, read and written as Go does: `null` is Go's
    /// zero time.
    pub(crate) mod time {
        use crate::wire::go_time::GoTime;
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(t: &GoTime, ser: S) -> Result<S::Ok, S::Error> {
            super::write_go_time(t.unix, super::format_utc_nanos(t.unix, t.nanos), ser)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<GoTime, D::Error> {
            Ok(super::read(de)?.unwrap_or(GoTime {
                unix: super::super::GO_ZERO_TIME_UNIX,
                nanos: 0,
            }))
        }
    }

    fn read<'de, D: Deserializer<'de>>(de: D) -> Result<Option<GoTime>, D::Error> {
        let raw = Box::<RawValue>::deserialize(de)?;
        go_time::from_json(raw.get()).map_err(de::Error::custom)
    }

    /// A time read as Go's `time.Time` reads it from JSON ([`go_time`]): a JSON string only,
    /// never a number, in whole seconds (rounded down). `null` is Go's zero time, the time
    /// of a record that never set it.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<i64, D::Error> {
        Ok(read(de)?.map_or(super::GO_ZERO_TIME_UNIX, |t| t.unix))
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
            issued_at_nanos: 0,
            revoked_at_nanos: 0,
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

    /// Which kind revokes what, as the Go probe measured it: a revocation of each kind,
    /// signed by the network key, received as another member's version. Go compares the
    /// kind as written, so only `clanstvo` takes the membership away and only `ovlast`
    /// the ovlast; every one of them is valid on its own. The third column is Rust
    /// before, when the kind was trimmed and `membership` stood for `clanstvo`.
    #[test]
    fn revocation_kind_as_in_go() {
        let net_sk = SigningKey::from_bytes(&[11; 32]);
        let member = SigningKey::from_bytes(&[12; 32]).verifying_key();
        let member_b64 = public_key_to_base64(member.as_bytes());
        let issued_at = 1_760_000_000i64;
        #[rustfmt::skip]
        let table = [
            ("clanstvo", "clanstvo", "clanstvo"),
            (" clanstvo", "nista", "clanstvo"),
            ("clanstvo ", "nista", "clanstvo"),
            ("clanstvo\n", "nista", "clanstvo"),
            ("Clanstvo", "nista", "nista"),
            ("CLANSTVO", "nista", "nista"),
            ("membership", "nista", "clanstvo"),
            ("ovlast", "ovlast", "ovlast"),
            ("Ovlast", "nista", "nista"),
            (" ovlast", "nista", "ovlast"),
            ("", "nista", "greska"),
            ("list_grant", "nista", "nista"),
            ("clanstvo:", "nista", "nista"),
        ];
        crate::go_table::assert_rows_as_in_go(&table, |kind| {
            let rev = Revocation {
                id: String::new(),
                kind: kind.to_owned(),
                target_id: "clan-1".to_owned(),
                public_key: member_b64.clone(),
                issued_at: issued_at + 2,
                revoked_at: issued_at + 2,
                issued_at_nanos: 0,
                revoked_at_nanos: 0,
                revoked_by: "cvor-a".to_owned(),
                signer_key: String::new(),
                signature: String::new(),
            }
            .sign(&net_sk);
            assert_eq!(rev.verify_self(), Ok(net_sk.verifying_key()), "{kind:?}");
            match (rev.revokes(&member_b64, issued_at), rev.scope()) {
                (true, RevocationScope::Membership) => "clanstvo".to_owned(),
                (false, RevocationScope::Ovlast) => "ovlast".into(),
                (false, RevocationScope::Other(k)) => {
                    assert_eq!(k, kind);
                    "nista".into()
                }
                other => panic!("{kind:?}: {other:?}"),
            }
        });
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
    fn root_signed_future_memberships_hold_and_invalid_lifetimes_are_not_issued() {
        let net = NetworkKey::from_signing_key("test", generate_signing_key());
        let device = generate_signing_key().verifying_key();
        let now = 1_760_000_000;
        // The one-hour limit is for a membership an admitter signed (PROTOKOL §7); one the
        // network key signed holds however far ahead it was issued, as in Go.
        for ahead in [5, MAX_CLOCK_SKEW_SECS, MAX_CLOCK_SKEW_SECS + 1, 10 * 86_400] {
            let ahead_of_now = net
                .admit_member(
                    "dev",
                    &device,
                    "root",
                    Validity {
                        issued_at: now + ahead,
                        valid_for_secs: 60,
                    },
                )
                .unwrap();
            assert_eq!(ahead_of_now.verify(&net.public, &device, now), Ok(()));
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
            issued_at_nanos: 0,
            revoked_at_nanos: 0,
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
                issued_at_nanos: 0,
                expires_at: Expiry::from_wire_unix(AT + 48 * 3600),
                signature: String::new(),
            };
            ovlast.signature = STANDARD.encode(net.sign(&ovlast.signed_bytes()).to_bytes());
            let mut m = Membership {
                network: ovlast.network.clone(),
                device_id: "clan-1".into(),
                device_key: b64(&member().verifying_key()),
                issued_by: "primatelj-1".into(),
                issued_at: AT,
                issued_at_nanos: 0,
                expires_at: Expiry::from_wire_unix(AT + 24 * 3600),
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
                issued_at_nanos: 0,
                revoked_at_nanos: 0,
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
                issued_at_nanos: 0,
                expires_at: Expiry::from_wire_unix(AT + 24 * 3600),
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
                issued_at_nanos: 0,
                expires_at: Expiry::from_wire_unix(AT + 48 * 3600),
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
                issued_at_nanos: 0,
                revoked_at_nanos: 0,
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

    /// The rules on a membership, an ovlast and a revocation, and their order, as the Go
    /// probe measured them. The Rust column is the check before: the one-hour limit for
    /// every membership and first of all, `expiresAt` before `issuedAt` turned away, 0
    /// (1970) taken as no expiry, an ovlast that does not hold given the membership's
    /// kinds, and a revocation asked for a kind, a node, and times in order.
    mod go_rules {
        use super::*;
        use crate::go_table::assert_rows_as_in_go;

        const AT: i64 = 1_760_000_000;
        const DAY: i64 = 86_400;
        const Z: i64 = GO_ZERO_TIME_UNIX;

        fn key(b: u8) -> SigningKey {
            SigningKey::from_bytes(&[b; 32])
        }

        fn b64(sk: &SigningKey) -> String {
            public_key_to_base64(sk.verifying_key().as_bytes())
        }

        /// A case; `None` is the default: an ovlast for [AT-1d, AT+2d], a membership for
        /// [AT, AT+1d], checked at AT.
        #[derive(Default)]
        struct Case {
            admitter: bool,
            o_issued: Option<i64>,
            o_expires: Option<i64>,
            m_issued: Option<i64>,
            m_expires: Option<i64>,
            now: Option<i64>,
            issued_by: Option<&'static str>,
            o_other_network: bool,
            o_bad_signature: bool,
            m_bad_signature: bool,
            other_network: bool,
            other_key: bool,
        }

        fn case(name: &str) -> Case {
            let a = Case {
                admitter: true,
                ..Case::default()
            };
            let r = Case::default();
            match name {
                "r_ispravno" => r,
                "r_buducnost_1h" => Case {
                    m_issued: Some(AT + 3600),
                    ..r
                },
                "r_buducnost_1h1s" => Case {
                    m_issued: Some(AT + 3601),
                    ..r
                },
                "r_buducnost_10d" => Case {
                    m_issued: Some(AT + 10 * DAY),
                    m_expires: Some(AT + 20 * DAY),
                    ..r
                },
                "r_istek_prije_izdanja" => Case {
                    m_issued: Some(AT + 100),
                    m_expires: Some(AT + 50),
                    ..r
                },
                "r_istek_prije_izdanja_istekao" => Case {
                    m_expires: Some(AT - 10),
                    ..r
                },
                "r_bez_isteka" => Case {
                    m_expires: Some(Z),
                    ..r
                },
                "r_izdano_nula_bez_isteka" => Case {
                    m_issued: Some(Z),
                    m_expires: Some(Z),
                    ..r
                },
                "r_istek_1970" => Case {
                    m_issued: Some(0),
                    m_expires: Some(0),
                    ..r
                },
                "r_istek_1970_izdano_sad" => Case {
                    m_expires: Some(0),
                    ..r
                },
                "r_istek_negativan" => Case {
                    m_issued: Some(-2000),
                    m_expires: Some(-1000),
                    ..r
                },
                "r_istek_tocno_sad" => Case {
                    m_issued: Some(AT - 10),
                    m_expires: Some(AT),
                    ..r
                },
                "r_istek_sekundu_prije" => Case {
                    m_issued: Some(AT - 10),
                    m_expires: Some(AT - 1),
                    ..r
                },
                "r_druga_mreza" => Case {
                    other_network: true,
                    ..r
                },
                "r_drugi_kljuc" => Case {
                    other_key: true,
                    ..r
                },
                "r_krivi_potpis" => Case {
                    m_bad_signature: true,
                    ..r
                },
                "r_buducnost_krivi_potpis" => Case {
                    m_issued: Some(AT + 3601),
                    m_bad_signature: true,
                    ..r
                },
                "a_ispravno" => a,
                "a_buducnost_1h" => Case {
                    m_issued: Some(AT + 3600),
                    ..a
                },
                "a_buducnost_1h1s" => Case {
                    m_issued: Some(AT + 3601),
                    ..a
                },
                "a_buducnost_ovlast_istekla" => Case {
                    o_expires: Some(AT + 3600),
                    m_issued: Some(AT + 7200),
                    m_expires: Some(AT + 3600),
                    ..a
                },
                "a_buducnost_dulje" => Case {
                    m_issued: Some(AT + 3601),
                    m_expires: Some(AT + 3 * DAY),
                    ..a
                },
                "a_buducnost_krivi_izdavatelj" => Case {
                    m_issued: Some(AT + 3601),
                    issued_by: Some("netko"),
                    ..a
                },
                "a_buducnost_krivi_potpis" => Case {
                    m_issued: Some(AT + 3601),
                    m_bad_signature: true,
                    ..a
                },
                "a_buducnost_ovlast_krivi_potpis" => Case {
                    m_issued: Some(AT + 3601),
                    o_bad_signature: true,
                    ..a
                },
                "a_istek_prije_izdanja" => Case {
                    m_issued: Some(AT + 100),
                    m_expires: Some(AT + 50),
                    ..a
                },
                "a_istek_prije_izdanja_istekao" => Case {
                    m_expires: Some(AT - 10),
                    ..a
                },
                "a_bez_isteka" => Case {
                    m_expires: Some(Z),
                    ..a
                },
                "a_bez_isteka_ovlast_bez_isteka" => Case {
                    o_expires: Some(Z),
                    m_expires: Some(Z),
                    ..a
                },
                "a_ovlast_bez_isteka" => Case {
                    o_expires: Some(Z),
                    ..a
                },
                "a_ovlast_istek_1970" => Case {
                    o_issued: Some(-DAY),
                    o_expires: Some(0),
                    m_expires: Some(0),
                    ..a
                },
                "a_ovlast_istek_1970_clanstvo_1970" => Case {
                    o_issued: Some(-DAY),
                    o_expires: Some(0),
                    m_issued: Some(0),
                    m_expires: Some(0),
                    ..a
                },
                "a_clanstvo_istek_1970" => Case {
                    m_expires: Some(0),
                    ..a
                },
                "a_izdano_prije_ovlasti" => Case {
                    m_issued: Some(AT - DAY - 1),
                    ..a
                },
                "a_izdano_kad_ovlast" => Case {
                    m_issued: Some(AT - DAY),
                    ..a
                },
                "a_izdano_kad_ovlast_istjece" => Case {
                    m_issued: Some(AT + 2 * DAY),
                    m_expires: Some(AT + 2 * DAY),
                    now: Some(AT + 2 * DAY),
                    ..a
                },
                "a_izdano_nakon_ovlasti" => Case {
                    m_issued: Some(AT + 2 * DAY + 1),
                    m_expires: Some(AT + 2 * DAY + 1),
                    now: Some(AT + 2 * DAY),
                    ..a
                },
                "a_istek_kao_ovlast" => Case {
                    m_expires: Some(AT + 2 * DAY),
                    ..a
                },
                "a_istek_sekundu_dulje" => Case {
                    m_expires: Some(AT + 2 * DAY + 1),
                    ..a
                },
                "a_krivi_izdavatelj" => Case {
                    issued_by: Some("netko"),
                    ..a
                },
                "a_ovlast_druga_mreza" => Case {
                    o_other_network: true,
                    ..a
                },
                "a_ovlast_krivi_potpis" => Case {
                    o_bad_signature: true,
                    ..a
                },
                "a_clanstvo_krivi_potpis" => Case {
                    m_bad_signature: true,
                    ..a
                },
                "a_isteklo" => Case {
                    now: Some(AT + DAY + 1),
                    ..a
                },
                "a_druga_mreza" => Case {
                    other_network: true,
                    ..a
                },
                "a_drugi_kljuc" => Case {
                    other_key: true,
                    ..a
                },
                _ => panic!("no case {name}"),
            }
        }

        fn signed(sk: &SigningKey, msg: &[u8], bad: bool) -> String {
            let mut sig = sk.sign(msg).to_bytes();
            if bad {
                sig[0] ^= 1;
            }
            STANDARD.encode(sig)
        }

        fn membership_outcome(name: &str) -> String {
            let c = case(name);
            let (net, admitter, member, other) = (key(9), key(7), key(5), key(6));
            let ovlast = c.admitter.then(|| {
                let mut o = Ovlast {
                    network: b64(if c.o_other_network { &other } else { &net }),
                    device_id: "primatelj-1".into(),
                    device_key: b64(&admitter),
                    issued_by: "admin".into(),
                    issued_at: c.o_issued.unwrap_or(AT - DAY),
                    issued_at_nanos: 0,
                    expires_at: Expiry::from_wire_unix(c.o_expires.unwrap_or(AT + 2 * DAY)),
                    signature: String::new(),
                };
                o.signature = signed(&net, &o.signed_bytes(), c.o_bad_signature);
                o
            });
            let mut m = Membership {
                network: b64(&net),
                device_id: "clan-1".into(),
                device_key: b64(&member),
                issued_by: c
                    .issued_by
                    .unwrap_or(if c.admitter { "primatelj-1" } else { "root" })
                    .into(),
                issued_at: c.m_issued.unwrap_or(AT),
                issued_at_nanos: 0,
                expires_at: Expiry::from_wire_unix(c.m_expires.unwrap_or(AT + DAY)),
                signature: String::new(),
                admitter: ovlast,
            };
            let signer = if c.admitter { &admitter } else { &net };
            m.signature = signed(signer, &m.signed_bytes(), c.m_bad_signature);
            let network = if c.other_network { &other } else { &net };
            let device = if c.other_key { &other } else { &member };
            let got = m.verify(
                &network.verifying_key(),
                &device.verifying_key(),
                c.now.unwrap_or(AT),
            );
            match got {
                Ok(()) => "vrijedi".into(),
                Err(TrustError::AdmitterOvlast(e)) => match *e {
                    TrustError::OtherNetwork => "ovlast:mreza".into(),
                    TrustError::BadSignature => "ovlast:potpis".into(),
                    TrustError::NotYetValid | TrustError::Expired => "ovlast:vrijeme".into(),
                    e => format!("ovlast:drugo:{e}"),
                },
                Err(TrustError::ExceedsAdmitterAuthority) => "ovlast:dulje".into(),
                Err(TrustError::IssuedInFuture) => "ovlast:buducnost".into(),
                Err(TrustError::IssuerMismatch) => "potpis:izdao".into(),
                Err(TrustError::BadSignature) => "potpis".into(),
                Err(TrustError::Expired) => "istek".into(),
                Err(TrustError::OtherNetwork) => "mreza".into(),
                Err(TrustError::KeyMismatch) => "kljuc".into(),
                Err(TrustError::NotYetValid) => "nije_jos".into(),
                Err(TrustError::InvalidFormat(_)) => "oblik".into(),
                Err(e) => format!("drugo:{e}"),
            }
        }

        /// Go's kinds: `ovlast:*` is the admitter's rules (Go gives one kind for all, the
        /// part after `:` is its message), `potpis:izdao` the signature kind with the
        /// message that names the issuer, which Rust keeps as a kind of its own.
        #[test]
        fn membership_chain_as_in_go() {
            #[rustfmt::skip]
            let table = [
                ("r_ispravno", "vrijedi", "vrijedi"),
                ("r_buducnost_1h", "vrijedi", "vrijedi"),
                ("r_buducnost_1h1s", "vrijedi", "ovlast:buducnost"),
                ("r_buducnost_10d", "vrijedi", "ovlast:buducnost"),
                ("r_istek_prije_izdanja", "vrijedi", "oblik"),
                ("r_istek_prije_izdanja_istekao", "istek", "oblik"),
                ("r_bez_isteka", "vrijedi", "oblik"),
                ("r_izdano_nula_bez_isteka", "vrijedi", "vrijedi"),
                ("r_istek_1970", "istek", "vrijedi"),
                ("r_istek_1970_izdano_sad", "istek", "vrijedi"),
                ("r_istek_negativan", "istek", "vrijedi"),
                ("r_istek_tocno_sad", "vrijedi", "vrijedi"),
                ("r_istek_sekundu_prije", "istek", "istek"),
                ("r_druga_mreza", "mreza", "mreza"),
                ("r_drugi_kljuc", "kljuc", "kljuc"),
                ("r_krivi_potpis", "potpis", "potpis"),
                ("r_buducnost_krivi_potpis", "potpis", "ovlast:buducnost"),
                ("a_ispravno", "vrijedi", "vrijedi"),
                ("a_buducnost_1h", "vrijedi", "vrijedi"),
                ("a_buducnost_1h1s", "ovlast:buducnost", "ovlast:buducnost"),
                ("a_buducnost_ovlast_istekla", "ovlast:vrijeme", "ovlast:buducnost"),
                ("a_buducnost_dulje", "ovlast:dulje", "ovlast:buducnost"),
                ("a_buducnost_krivi_izdavatelj", "ovlast:buducnost", "ovlast:buducnost"),
                ("a_buducnost_krivi_potpis", "ovlast:buducnost", "ovlast:buducnost"),
                ("a_buducnost_ovlast_krivi_potpis", "ovlast:potpis", "ovlast:buducnost"),
                ("a_istek_prije_izdanja", "vrijedi", "oblik"),
                ("a_istek_prije_izdanja_istekao", "istek", "oblik"),
                ("a_bez_isteka", "ovlast:dulje", "oblik"),
                ("a_bez_isteka_ovlast_bez_isteka", "vrijedi", "oblik"),
                ("a_ovlast_bez_isteka", "vrijedi", "vrijedi"),
                ("a_ovlast_istek_1970", "ovlast:vrijeme", "vrijedi"),
                ("a_ovlast_istek_1970_clanstvo_1970", "istek", "vrijedi"),
                ("a_clanstvo_istek_1970", "istek", "ovlast:dulje"),
                ("a_izdano_prije_ovlasti", "ovlast:vrijeme", "nije_jos"),
                ("a_izdano_kad_ovlast", "vrijedi", "vrijedi"),
                ("a_izdano_kad_ovlast_istjece", "vrijedi", "vrijedi"),
                ("a_izdano_nakon_ovlasti", "ovlast:vrijeme", "istek"),
                ("a_istek_kao_ovlast", "vrijedi", "vrijedi"),
                ("a_istek_sekundu_dulje", "ovlast:dulje", "ovlast:dulje"),
                ("a_krivi_izdavatelj", "potpis:izdao", "potpis:izdao"),
                ("a_ovlast_druga_mreza", "ovlast:mreza", "mreza"),
                ("a_ovlast_krivi_potpis", "ovlast:potpis", "potpis"),
                ("a_clanstvo_krivi_potpis", "potpis", "potpis"),
                ("a_isteklo", "istek", "istek"),
                ("a_druga_mreza", "mreza", "mreza"),
                ("a_drugi_kljuc", "kljuc", "kljuc"),
            ];
            assert_rows_as_in_go(&table, membership_outcome);
        }

        /// Go writes no expiry as its zero time, and Rust reads that text as
        /// `GO_ZERO_TIME_UNIX` and writes it back the same.
        #[test]
        fn go_zero_time_is_no_expiry() {
            assert_eq!(
                rfc3339_unix::parse_utc("0001-01-01T00:00:00Z"),
                Ok(GO_ZERO_TIME_UNIX)
            );
            assert_eq!(
                rfc3339_unix::format_utc(GO_ZERO_TIME_UNIX),
                "0001-01-01T00:00:00Z"
            );
        }

        fn revocation_outcome(name: &str) -> String {
            let net = key(9);
            let mut r = Revocation {
                id: String::new(),
                kind: "clanstvo".into(),
                target_id: "cvor-1".into(),
                public_key: b64(&key(5)),
                issued_at: AT,
                revoked_at: AT + 3600,
                issued_at_nanos: 0,
                revoked_at_nanos: 0,
                revoked_by: "admin-1".into(),
                signer_key: String::new(),
                signature: String::new(),
            };
            match name {
                "ispravno" | "oznaka_druga" | "oznaka_prazna" => {}
                "vrsta_prazna" => r.kind = String::new(),
                "vrsta_razmak" => r.kind = " ".into(),
                "vrsta_nepoznata" => r.kind = "nesto".into(),
                "cvor_prazan" => r.target_id = String::new(),
                "kljuc_prazan" => r.public_key = String::new(),
                "izdano_negativno" => r.issued_at = -1,
                "izdano_nula_go" => r.issued_at = Z,
                "izdano_1970" => r.issued_at = 0,
                "opozvano_prije_izdanja" => r.revoked_at = AT - 1,
                "opozvano_nula_go" => r.revoked_at = Z,
                "opozvao_prazan" => r.revoked_by = String::new(),
                "sve_prazno" => {
                    r = Revocation {
                        id: String::new(),
                        kind: String::new(),
                        target_id: String::new(),
                        public_key: String::new(),
                        issued_at: Z,
                        revoked_at: Z,
                        issued_at_nanos: 0,
                        revoked_at_nanos: 0,
                        revoked_by: String::new(),
                        signer_key: String::new(),
                        signature: String::new(),
                    }
                }
                _ => panic!("no case {name}"),
            }
            let mut r = r.sign(&net);
            match name {
                "oznaka_druga" => r.id.push('x'),
                "oznaka_prazna" => r.id.clear(),
                _ => {}
            }
            match r.verify_self() {
                Ok(_) => "ispravan".into(),
                Err(_) => "neispravan".into(),
            }
        }

        #[test]
        fn revocation_on_its_own_as_in_go() {
            #[rustfmt::skip]
            let table = [
                ("ispravno", "ispravan", "ispravan"),
                ("vrsta_prazna", "ispravan", "neispravan"),
                ("vrsta_razmak", "ispravan", "neispravan"),
                ("vrsta_nepoznata", "ispravan", "ispravan"),
                ("cvor_prazan", "ispravan", "neispravan"),
                ("kljuc_prazan", "ispravan", "ispravan"),
                ("izdano_negativno", "ispravan", "neispravan"),
                ("izdano_nula_go", "ispravan", "neispravan"),
                ("izdano_1970", "ispravan", "ispravan"),
                ("opozvano_prije_izdanja", "ispravan", "neispravan"),
                ("opozvano_nula_go", "ispravan", "neispravan"),
                ("opozvao_prazan", "ispravan", "ispravan"),
                ("sve_prazno", "ispravan", "neispravan"),
                ("oznaka_druga", "neispravan", "neispravan"),
                ("oznaka_prazna", "neispravan", "neispravan"),
            ];
            assert_rows_as_in_go(&table, revocation_outcome);
        }
    }

    /// `expiresAt` as a type of its own: no expiry is said as `Expiry::NEVER`, and the
    /// wire and the signed bytes stay as Go writes them.
    mod expiry {
        use super::*;
        use crate::wire::go_json::to_go_json_string;

        const AT: i64 = 1_760_000_000;
        const DAY: i64 = 86_400;

        fn key(b: u8) -> SigningKey {
            SigningKey::from_bytes(&[b; 32])
        }

        fn b64(sk: &SigningKey) -> String {
            public_key_to_base64(sk.verifying_key().as_bytes())
        }

        fn ovlast(expires_at: Expiry) -> Ovlast {
            let mut o = Ovlast {
                network: b64(&key(9)),
                device_id: "primatelj-1".into(),
                device_key: b64(&key(7)),
                issued_by: "admin".into(),
                issued_at: AT - DAY,
                issued_at_nanos: 0,
                expires_at,
                signature: String::new(),
            };
            o.signature = STANDARD.encode(key(9).sign(&o.signed_bytes()).to_bytes());
            o
        }

        /// A membership for `key(5)` signed by the network key, or by the admitter when
        /// `admitter` is given.
        fn membership(expires_at: Expiry, admitter: Option<Ovlast>) -> Membership {
            let signer = if admitter.is_some() { key(7) } else { key(9) };
            let mut m = Membership {
                network: b64(&key(9)),
                device_id: "clan-1".into(),
                device_key: b64(&key(5)),
                issued_by: if admitter.is_some() {
                    "primatelj-1"
                } else {
                    "root"
                }
                .into(),
                issued_at: AT,
                issued_at_nanos: 0,
                expires_at,
                signature: String::new(),
                admitter,
            };
            m.signature = STANDARD.encode(signer.sign(&m.signed_bytes()).to_bytes());
            m
        }

        fn verify(m: &Membership, now: i64) -> Result<(), TrustError> {
            m.verify(&key(9).verifying_key(), &key(5).verifying_key(), now)
        }

        #[test]
        fn no_expiry_is_go_zero_time_in_signed_bytes_and_on_the_wire() {
            assert_eq!(Expiry::from_wire_unix(GO_ZERO_TIME_UNIX), Expiry::NEVER);
            assert_eq!(Expiry::NEVER.wire_unix(), GO_ZERO_TIME_UNIX);
            assert_eq!(Expiry::NEVER.last_second(), None);
            assert!(Expiry::NEVER.is_never());
            assert_eq!(format!("{:?}", Expiry::NEVER), "Expiry::NEVER");

            let m = membership(Expiry::NEVER, None);
            let signed = String::from_utf8(m.signed_bytes()).unwrap();
            assert!(
                signed.ends_with(r#""issuedAt":1760000000,"expiresAt":-62135596800}"#),
                "{signed}"
            );
            let wire = serde_json::to_string(&m).unwrap();
            assert!(
                wire.contains(r#""expiresAt":"0001-01-01T00:00:00Z""#),
                "{wire}"
            );

            let back: Membership = serde_json::from_str(&wire).unwrap();
            assert_eq!(back.expires_at, Expiry::NEVER);
            assert_eq!(back.signed_bytes(), m.signed_bytes());
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
            assert_eq!(verify(&back, i64::MAX), Ok(()));
        }

        #[test]
        fn zero_is_1970_and_has_expired() {
            let zero = Expiry::from_wire_unix(0);
            assert_eq!(zero.last_second(), Some(0));
            assert!(!zero.is_never());
            assert!(zero.is_expired_at(1));
            assert!(!zero.is_expired_at(0));
            assert_eq!(format!("{zero:?}"), "Expiry(0)");

            let m = membership(zero, None);
            let signed = String::from_utf8(m.signed_bytes()).unwrap();
            assert!(signed.ends_with(r#""expiresAt":0}"#), "{signed}");
            let wire = serde_json::to_string(&m).unwrap();
            assert!(
                wire.contains(r#""expiresAt":"1970-01-01T00:00:00Z""#),
                "{wire}"
            );
            assert_eq!(verify(&m, AT), Err(TrustError::Expired));

            // A time is only ever a text, as in Go: a record that carries 0, or any other
            // number, as its expiry does not read.
            let as_number =
                wire.replace(r#""expiresAt":"1970-01-01T00:00:00Z""#, r#""expiresAt":0"#);
            assert!(serde_json::from_str::<Membership>(&as_number).is_err());

            let o = ovlast(zero);
            assert_eq!(
                o.verify(&key(9).verifying_key(), AT),
                Err(TrustError::Expired)
            );
        }

        /// The case behind the type: a record of its own (as an application keeps one)
        /// where 0 means no expiry. Before, it could hand 0 on as a number; then the chain
        /// took 0 as 1970, earlier than any ovlast, and the record held for ever. Now it
        /// has to say `NEVER`, and that is refused.
        #[test]
        fn no_expiry_membership_from_expiring_admitter_is_refused() {
            let limit = AT + 2 * DAY;
            let expiring = ovlast(Expiry::from_wire_unix(limit));
            let net = key(9).verifying_key();
            let chain = |expires_at| {
                verify_admitter_chain(&net, Some(&expiring), "primatelj-1", AT, expires_at, AT)
            };
            assert_eq!(
                chain(Expiry::NEVER),
                Err(TrustError::ExceedsAdmitterAuthority)
            );
            assert_eq!(
                chain(Expiry::from_wire_unix(GO_ZERO_TIME_UNIX)),
                Err(TrustError::ExceedsAdmitterAuthority)
            );
            assert_eq!(
                chain(Expiry::from_wire_unix(limit)),
                Ok(key(7).verifying_key())
            );
            assert_eq!(
                chain(Expiry::from_wire_unix(limit + 1)),
                Err(TrustError::ExceedsAdmitterAuthority)
            );

            let m = membership(Expiry::NEVER, Some(expiring.clone()));
            assert_eq!(verify(&m, AT), Err(TrustError::ExceedsAdmitterAuthority));

            // An ovlast with no expiry lets a membership with no expiry through.
            let m = membership(Expiry::NEVER, Some(ovlast(Expiry::NEVER)));
            assert_eq!(verify(&m, AT), Ok(()));
        }

        /// The admitter never issues for longer than its ovlast holds.
        #[test]
        fn admit_as_is_cut_to_the_ovlast() {
            let admit = |ovlast_expiry| {
                Membership::admit_as(
                    &key(7),
                    ovlast(ovlast_expiry),
                    "clan-1",
                    &key(5).verifying_key(),
                    Validity {
                        issued_at: AT,
                        valid_for_secs: 10 * DAY,
                    },
                )
                .unwrap()
                .expires_at
            };
            assert_eq!(
                admit(Expiry::from_wire_unix(AT + 2 * DAY)),
                Expiry::from_wire_unix(AT + 2 * DAY)
            );
            assert_eq!(admit(Expiry::NEVER), Expiry::from_wire_unix(AT + 10 * DAY));
        }

        /// A validity is read as the wire reads its sum, as before the type: a sum that
        /// falls exactly on Go's zero time is no expiry.
        #[test]
        fn validity_is_read_as_the_wire_reads_it() {
            let validity = |issued_at, valid_for_secs| {
                Validity {
                    issued_at,
                    valid_for_secs,
                }
                .expires_at()
            };
            assert_eq!(validity(AT, DAY), Ok(Expiry::from_wire_unix(AT + DAY)));
            assert_eq!(validity(GO_ZERO_TIME_UNIX - 10, 10), Ok(Expiry::NEVER));
            assert!(validity(i64::MAX, 1).is_err());
            assert!(validity(AT, 0).is_err());
        }

        /// Read from the vectors and written back, every record gives Go's bytes again:
        /// the signed bytes, the signature, and the record itself.
        #[test]
        fn wire_vectors_read_back_to_the_same_bytes() {
            let v: serde_json::Value =
                serde_json::from_str(include_str!("../../vektori/vektori-zice.json"))
                    .expect("vektori-zice.json");
            let net = parse_public_key(v["ulaz"]["kljucMreze"].as_str().unwrap()).unwrap();
            let now = v["ulaz"]["vrijeme"].as_i64().unwrap();
            let text = |path: &[&str]| {
                path.iter()
                    .fold(&v, |v, p| &v[*p])
                    .as_str()
                    .unwrap()
                    .to_owned()
            };

            for (path, special) in [
                (&["ovlast"][..], false),
                (&["posebniZnakovi", "ovlast"], true),
            ] {
                let zapis = text(&[path, &["zapis"]].concat());
                let o: Ovlast = serde_json::from_str(&zapis).unwrap();
                assert!(!o.expires_at.is_never(), "{path:?}");
                assert_eq!(
                    String::from_utf8(o.signed_bytes()).unwrap(),
                    text(&[path, &["bajtovi"]].concat())
                );
                let back = if special {
                    to_go_json_string(&o).unwrap()
                } else {
                    serde_json::to_string(&o).unwrap()
                };
                assert_eq!(back, zapis, "{path:?}");
                o.verify(&net, now).unwrap();
            }

            for (path, special) in [
                (&["clanstvoKljucemMreze"][..], false),
                (&["clanstvoOdPrimatelja"], false),
                (&["posebniZnakovi", "clanstvo"], true),
            ] {
                let zapis = text(&[path, &["zapis"]].concat());
                let m: Membership = serde_json::from_str(&zapis).unwrap();
                assert!(!m.expires_at.is_never(), "{path:?}");
                assert_eq!(
                    String::from_utf8(m.signed_bytes()).unwrap(),
                    text(&[path, &["bajtovi"]].concat())
                );
                let back = if special {
                    to_go_json_string(&m).unwrap()
                } else {
                    serde_json::to_string(&m).unwrap()
                };
                assert_eq!(back, zapis, "{path:?}");
                let device = parse_public_key(&m.device_key).unwrap();
                m.verify(&net, &device, now).unwrap();
            }
        }
    }
}

/// Ovlast, membership and revocation read as Go reads them. The Go column is go1.27.1
/// through `json.Unmarshal` into the Go side's structs, written as the tests here write
/// the Rust result.
#[cfg(test)]
mod records_as_in_go {
    use super::*;

    fn ovlast(o: &Ovlast) -> String {
        format!(
            "net={:?} dev={:?} key={:?} by={:?} iss={} exp={} zero={} sig={:?}",
            o.network,
            o.device_id,
            o.device_key,
            o.issued_by,
            o.issued_at,
            o.expires_at.wire_unix(),
            o.expires_at.is_never(),
            o.signature
        )
    }

    fn read(kind: &str, text: &str) -> Option<String> {
        match kind {
            "o" => serde_json::from_str::<Ovlast>(text).ok().map(|o| ovlast(&o)),
            "m" => serde_json::from_str::<Membership>(text).ok().map(|m| {
                let admitter = m
                    .admitter
                    .as_ref()
                    .map_or("nil".to_owned(), |o| format!("{{{}}}", ovlast(o)));
                format!(
                    "net={:?} dev={:?} key={:?} by={:?} iss={} exp={} zero={} sig={:?} prim={admitter}",
                    m.network,
                    m.device_id,
                    m.device_key,
                    m.issued_by,
                    m.issued_at,
                    m.expires_at.wire_unix(),
                    m.expires_at.is_never(),
                    m.signature
                )
            }),
            _ => serde_json::from_str::<Revocation>(text).ok().map(|r| {
                format!(
                    "id={:?} vrsta={:?} node={:?} pk={:?} iss={} opoz={} opozvao={:?} potpisnik={:?} potpis={:?}",
                    r.id,
                    r.kind,
                    r.target_id,
                    r.public_key,
                    r.issued_at,
                    r.revoked_at,
                    r.revoked_by,
                    r.signer_key,
                    r.signature
                )
            }),
        }
    }

    /// (record: `o` ovlast, `m` membership, `r` revocation; JSON text; what Go reads;
    /// what Rust does). Rust: `isto` reads the same, `GRESKA` refuses where Go reads.
    ///
    /// Rust refuses in one case only: a kept `expiresAt` that is Go's zero time with a
    /// part of a second (Go: `zero=false`) is a bad record (see
    /// [`rfc3339_unix::expiry`]). A lone surrogate escape (`\ud800`) is U+FFFD, as in Go
    /// ([`crate::wire::go_text`]).
    ///
    /// Rows checked against Go besides these: 10,000 and 12,000 random records with keys
    /// in other cases, with `K`/`ſ`, the old Rust names, repeats, `null` and bad values;
    /// all read the same, but for the zero time with a part of a second.
    const EDGES: &[(&str, &str, &str, &str)] = &[
        // A control character written as it is in a key is an error, as in Go; as an
        // escape it is a key that names no field.
        ("o", "{\"deviceId\":\"d\",\"a\u{1}b\":1}", "GRESKA", "isto"),
        ("r", "{\"vrsta\":\"x\",\"a\nb\":1}", "GRESKA", "isto"),
        ("m", "{\"primatelj\":{\"\u{4}\":1}}", "GRESKA", "isto"),
        (
            "r",
            r#"{"vrsta":"x","a\u0001b":1,"\u0000":2}"#,
            r#"id="" vrsta="x" node="" pk="" iss=-62135596800 opoz=-62135596800 opozvao="" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "r",
            r#"{"vrsta":"\ud800"}"#,
            r#"id="" vrsta="�" node="" pk="" iss=-62135596800 opoz=-62135596800 opozvao="" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "r",
            r#"{"vrsta":"a\udc00b"}"#,
            r#"id="" vrsta="a�b" node="" pk="" iss=-62135596800 opoz=-62135596800 opozvao="" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "o",
            r#"{"deviceId":"😀"}"#,
            r#"net="" dev="😀" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="""#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"network":"\ud800"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="�" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "r",
            r#"{"kind":"clanstvo","vrsta":"ovlast"}"#,
            r#"id="" vrsta="ovlast" node="" pk="" iss=-62135596800 opoz=-62135596800 opozvao="" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "r",
            r#"{"kind":"clanstvo"}"#,
            r#"id="" vrsta="" node="" pk="" iss=-62135596800 opoz=-62135596800 opozvao="" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "m",
            r#"{"admitter":{"network":"n"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim=nil"#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"network":"n"},"primatelj":{"deviceId":"d"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="n" dev="d" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"network":"n"},"primatelj":null}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim=nil"#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":null,"primatelj":{"deviceId":"d"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="" dev="d" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "m",
            r#"{"PRIMATELJ":{"NETWORK":"n","network":"m"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="m" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"expiresAt":"0001-01-01T00:00:00.5Z"},"primatelj":{"expiresAt":"2025-10-09T08:53:20Z"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="" dev="" key="" by="" iss=-62135596800 exp=1760000000 zero=false sig=""}"#,
            "isto",
        ),
        (
            "m",
            r#"{"expiresAt":"0001-01-01T00:00:00.5Z","expiresAt":"2025-10-09T08:53:20Z"}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=1760000000 zero=false sig="" prim=nil"#,
            "isto",
        ),
        (
            "m",
            r#"{"expiresAt":"2025-10-09T08:53:20Z","expiresAt":null}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=1760000000 zero=false sig="" prim=nil"#,
            "isto",
        ),
        (
            "m",
            r#"{"expiresAt":"bad","expiresAt":"2025-10-09T08:53:20Z"}"#,
            "GRESKA",
            "isto",
        ),
        ("m", r#"{"expiresAt":1760000000}"#, "GRESKA", "isto"),
        ("r", r#"{"issuedAt":1760000000}"#, "GRESKA", "isto"),
        (
            "r",
            r#"{"opozvanoAt":"2025-10-09T08:53:20Z","revokedAt":"x"}"#,
            r#"id="" vrsta="" node="" pk="" iss=-62135596800 opoz=1760000000 opozvao="" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "o",
            r#"{"issuedAt":"0001-01-01T00:00:00.5Z"}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="""#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"expiresAt":"0001-01-01T00:00:00.5Z"},"primatelj":null}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim=nil"#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"expiresAt":"0001-01-01T00:00:00.5Z"},"primatelj":null,"primatelj":{"network":"n"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="n" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"expiresAt":"bad"},"primatelj":null}"#,
            "GRESKA",
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"expiresAt":"2025-10-09T08:53:20Z"},"primatelj":{"expiresAt":"0001-01-01T00:00:00.5Z"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=false sig=""}"#,
            "GRESKA",
        ),
        (
            "m",
            r#"{"primatelj":{"expiresAt":"0001-01-01T00:00:00.5Z"},"primatelj":{"network":"n"}}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="n" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=false sig=""}"#,
            "GRESKA",
        ),
        (
            "m",
            r#"{"expiresAt":"0001-01-01T00:00:00.5Z","EXPIRESAT":null}"#,
            r#"net="" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=false sig="" prim=nil"#,
            "GRESKA",
        ),
        (
            "o",
            r#"{"networK":"b","expiresAt":null,"EXPIRESAT":"0001-01-01T00:00:00Z","signature":null,"expireſAt":"0001-01-01T00:00:00Z","issuedAt":"2025-10-09T08:53:20Z","issuedBy":null,"issuedAt":"2025-10-09T08:53:20.9+01:00","deviceKey":null}"#,
            r#"net="b" dev="" key="" by="" iss=1759996400 exp=-62135596800 zero=true sig="""#,
            "isto",
        ),
        (
            "o",
            r#"{"deviceKey":"\u0041","issuedAt":"0001-01-01T00:00:00Z","NETWORK":"a","expireſAt":null,"deviceId":"b","EXPIRESAT":null,"deviceId":"a","NETWORK":"\u0041"}"#,
            r#"net="A" dev="a" key="A" by="" iss=-62135596800 exp=-62135596800 zero=true sig="""#,
            "isto",
        ),
        (
            "o",
            r#"{"iſſuedBy":null,"networK":"\u0041","issuedBy":"a","deviceKey":"b","ſignature":null,"deviceId":"","ISSUEDAT":"2025-10-09T08:53:20.9+01:00","iſſuedAt":"0001-01-01T00:00:00.5Z"}"#,
            r#"net="A" dev="" key="b" by="a" iss=-62135596800 exp=-62135596800 zero=true sig="""#,
            "isto",
        ),
        (
            "m",
            r#"{"signature":"b","PRIMATELJ":{"ISSUEDAT":"0001-01-01T00:00:00.5Z"},"EXPIRESAT":"0001-01-01T00:00:00Z","primatelj":null,"expireſAt":"0001-01-01T00:00:00Z","networK":"a","signature":"","primatelj":{"iſſuedAt":"2025-10-09T08:53:20.9+01:00"}}"#,
            r#"net="a" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig="" prim={net="" dev="" key="" by="" iss=1759996400 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "m",
            r#"{"iſſuedBy":"a","signature":"b","primatelj":null,"deviceKey":null,"primatelj":{"deviceId":"\u0041"},"primatelj":{"NETWORK":"\u0041","issuedBy":"b"}}"#,
            r#"net="" dev="" key="" by="a" iss=-62135596800 exp=-62135596800 zero=true sig="b" prim={net="A" dev="A" key="" by="b" iss=-62135596800 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "m",
            r#"{"primatelj":{"deviceKey":null,"issuedAt":"2025-10-09T08:53:20Z","network":""},"primatelj":null,"EXPIRESAT":"2025-10-09T08:53:20Z","primatelj":{"DEVICEKEY":"a"},"issuedAt":null,"primatelj":{"network":"a","deviceKey":"","network":"\u0041","signature":""},"iſſuedAt":"2025-10-09T08:53:20Z"}"#,
            r#"net="" dev="" key="" by="" iss=1760000000 exp=1760000000 zero=false sig="" prim={net="A" dev="" key="" by="" iss=-62135596800 exp=-62135596800 zero=true sig=""}"#,
            "isto",
        ),
        (
            "r",
            r#"{"issuedAt":null,"vrsta":"b","potpisnik":"a","potpiſ":"\u0041","id":"a","POTPISNIK":"","vrsta":"a","id":null,"potpis":"\u0041","opozvao":"","nodeId":null,"id":"a","issuedAt":"2025-10-09T08:53:20Z","publicKey":"a"}"#,
            r#"id="a" vrsta="a" node="" pk="a" iss=1760000000 opoz=-62135596800 opozvao="" potpisnik="" potpis="A""#,
            "isto",
        ),
        (
            "r",
            r#"{"KIND":"\u0041","SIGNERKEY":"a","iſſuedAt":"0001-01-01T00:00:00.5Z","OPOZVANOAT":"0001-01-01T00:00:00.5Z","kind":"b","ſignerKey":null,"vrſta":"a","kind":null,"opozvanoAt":"2025-10-09T08:53:20Z","id":"\u0041","opozvao":"\u0041","opozvanoAt":"0001-01-01T00:00:00Z"}"#,
            r#"id="A" vrsta="a" node="" pk="" iss=-62135596800 opoz=-62135596800 opozvao="A" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "r",
            r#"{"vrsta":null,"POTPIS":null,"signerKey":"a","iſſuedAt":"2025-10-09T08:53:20.9+01:00","POTPISNIK":"a","publicKey":"\u0041","potpisnik":"a","nodeId":null,"potpisnik":"a","opozvao":"b","potpiſniK":"","OPOZVAO":""}"#,
            r#"id="" vrsta="" node="" pk="A" iss=1759996400 opoz=-62135596800 opozvao="" potpisnik="" potpis="""#,
            "isto",
        ),
        (
            "o",
            r#"{"ISSUEDBY":true,"expiresAt":"bad"}"#,
            "GRESKA",
            "isto",
        ),
        (
            "o",
            r#"{"issuedBy":"a","DEVICEID":"b","deviceId":true}"#,
            "GRESKA",
            "isto",
        ),
        (
            "m",
            r#"{"ISSUEDAT":"2025-10-09t08:53:20Z","network":true}"#,
            "GRESKA",
            "isto",
        ),
        (
            "m",
            r#"{"issuedBy":"","expiresat":null,"network":true}"#,
            "GRESKA",
            "isto",
        ),
        (
            "r",
            r#"{"id":true,"iD":true,"potpiſniK":"","potpis":true}"#,
            "GRESKA",
            "isto",
        ),
        (
            "r",
            r#"{"id":null,"potpisx":"","nodeId":1,"nodeid":"a"}"#,
            "GRESKA",
            "isto",
        ),
    ];

    /// What Go (go1.27.1) writes and takes. A revocation it signs over whole seconds, and
    /// the same one with a part of a second added on the way: Go still takes it as valid
    /// on its own, with the same id, and writes the times back in full (`json.Marshal`
    /// after `.UTC()`, as it stores them). Rust does the same.
    const GO_REVOCATION: &str = r#"{"id":"clanstvo:pk:1760000000:142e0c655ee4b74f","vrsta":"clanstvo","nodeId":"uredaj","publicKey":"pk","issuedAt":"2025-10-09T08:53:20Z","opozvanoAt":"2025-10-09T08:54:20Z","opozvao":"admin","potpisnik":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","potpis":"txKWoyQ8GlnzZJBgmSMUEvWFsOVW7IMxuC9qJMNtx6IvEMIZmkYRbyY9dHeHGpP/OF+2w1CPLxiRrOSprKwrCg=="}"#;
    const GO_REVOCATION_PARTS: &[(&str, &str)] = &[
        (
            r#"{"id":"clanstvo:pk:1760000000:142e0c655ee4b74f","vrsta":"clanstvo","nodeId":"uredaj","publicKey":"pk","issuedAt":"2025-10-09T08:53:20.25Z","opozvanoAt":"2025-10-09T10:54:20.5+02:00","opozvao":"admin","potpisnik":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","potpis":"txKWoyQ8GlnzZJBgmSMUEvWFsOVW7IMxuC9qJMNtx6IvEMIZmkYRbyY9dHeHGpP/OF+2w1CPLxiRrOSprKwrCg=="}"#,
            r#"{"id":"clanstvo:pk:1760000000:142e0c655ee4b74f","vrsta":"clanstvo","nodeId":"uredaj","publicKey":"pk","issuedAt":"2025-10-09T08:53:20.25Z","opozvanoAt":"2025-10-09T08:54:20.5Z","opozvao":"admin","potpisnik":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","potpis":"txKWoyQ8GlnzZJBgmSMUEvWFsOVW7IMxuC9qJMNtx6IvEMIZmkYRbyY9dHeHGpP/OF+2w1CPLxiRrOSprKwrCg=="}"#,
        ),
        (
            r#"{"id":"clanstvo:pk:1760000000:142e0c655ee4b74f","vrsta":"clanstvo","nodeId":"uredaj","publicKey":"pk","issuedAt":"2025-10-09T08:53:20.999999999Z","opozvanoAt":"2025-10-09T08:54:20Z","opozvao":"admin","potpisnik":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","potpis":"txKWoyQ8GlnzZJBgmSMUEvWFsOVW7IMxuC9qJMNtx6IvEMIZmkYRbyY9dHeHGpP/OF+2w1CPLxiRrOSprKwrCg=="}"#,
            r#"{"id":"clanstvo:pk:1760000000:142e0c655ee4b74f","vrsta":"clanstvo","nodeId":"uredaj","publicKey":"pk","issuedAt":"2025-10-09T08:53:20.999999999Z","opozvanoAt":"2025-10-09T08:54:20Z","opozvao":"admin","potpisnik":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","potpis":"txKWoyQ8GlnzZJBgmSMUEvWFsOVW7IMxuC9qJMNtx6IvEMIZmkYRbyY9dHeHGpP/OF+2w1CPLxiRrOSprKwrCg=="}"#,
        ),
    ];

    #[test]
    fn revocation_times_keep_their_part_of_a_second() {
        let whole: Revocation = serde_json::from_str(GO_REVOCATION).unwrap();
        assert!(whole.verify_self().is_ok());
        assert_eq!(to_go_json_vec(&whole).unwrap(), GO_REVOCATION.as_bytes());
        for (wire, go_writes) in GO_REVOCATION_PARTS {
            let r: Revocation = serde_json::from_str(wire).unwrap();
            assert!(r.verify_self().is_ok(), "{wire}");
            assert_eq!(r.signed_bytes(), whole.signed_bytes());
            assert_eq!(r.compute_id(), whole.compute_id());
            assert_eq!(
                String::from_utf8(to_go_json_vec(&r).unwrap()).unwrap(),
                *go_writes
            );
        }
        let r: Revocation = serde_json::from_str(GO_REVOCATION_PARTS[0].0).unwrap();
        assert_eq!(
            (r.issued_at, r.issued_at_nanos),
            (1_760_000_000, 250_000_000)
        );
        assert_eq!(
            (r.revoked_at, r.revoked_at_nanos),
            (1_760_000_060, 500_000_000)
        );
        // Go decides on whole seconds: what was issued in that second is revoked.
        assert!(r.revokes("pk", 1_760_000_000));
        assert!(!r.revokes("pk", 1_760_000_001));
    }

    /// Go signs a revocation whose kind holds U+FFFD and writes it as its three bytes.
    /// On the way it can come as a lone surrogate escape or as a byte that is not UTF-8:
    /// Go reads both as U+FFFD and takes the revocation as valid on its own, as it takes
    /// an ovlast with `\ud800` in its device. The signed bytes in Rust are Go's.
    const GO_FFFD_REVOCATION: &str = r#"{"id":"a�b:pk:1760000000:5d389d2469242027","vrsta":"a�b","nodeId":"uredaj","publicKey":"pk","issuedAt":"2025-10-09T08:53:20Z","opozvanoAt":"2025-10-09T08:53:20Z","opozvao":"admin","potpisnik":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","potpis":"Pp8hoPmdQnFG6yaxatQ0oa5D/ImXbS6qTzoP5/QTahJzSXXS08vrjACqD0OCddn1vBSvgUYlGdzUG+ZZgNsFDQ=="}"#;
    const GO_LONE_SURROGATE_REVOCATION: &str = r#"{"id":"a\udc00b:pk:1760000000:5d389d2469242027","vrsta":"a�b","nodeId":"uredaj","publicKey":"pk","issuedAt":"2025-10-09T08:53:20Z","opozvanoAt":"2025-10-09T08:53:20Z","opozvao":"admin","potpisnik":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","potpis":"Pp8hoPmdQnFG6yaxatQ0oa5D/ImXbS6qTzoP5/QTahJzSXXS08vrjACqD0OCddn1vBSvgUYlGdzUG+ZZgNsFDQ=="}"#;
    const GO_LONE_SURROGATE_OVLAST: &str = r#"{"network":"/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=","deviceId":"\ud800","deviceKey":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=","issuedBy":"korijen","issuedAt":"2025-10-09T08:53:20Z","expiresAt":"2025-10-09T09:53:20Z","signature":"4cI8bFR31vn0QgYNTIf6eg2twTRpKeBYtq3cF8o6cKhYmrSjii6c8UijxAb+I/Im53Uh6XnQacf9qE0a3c42DQ=="}"#;

    #[test]
    fn text_go_reads_as_fffd_keeps_the_signature() {
        let go: Revocation = serde_json::from_str(GO_FFFD_REVOCATION).unwrap();
        assert!(go.verify_self().is_ok());
        assert_eq!(go.kind, "a\u{FFFD}b");
        let lone: Revocation = serde_json::from_str(GO_LONE_SURROGATE_REVOCATION).unwrap();
        let not_utf8 = GO_FFFD_REVOCATION
            .as_bytes()
            .windows(3)
            .position(|w| w == "\u{FFFD}".as_bytes())
            .map(|i| {
                let mut b = GO_FFFD_REVOCATION.as_bytes().to_vec();
                b.splice(i..i + 3, [0xff]);
                b
            })
            .unwrap();
        let not_utf8: Revocation = crate::wire::go_text::from_slice(&not_utf8).unwrap();
        for r in [&lone, &not_utf8] {
            assert_eq!(r, &go);
            assert!(r.verify_self().is_ok());
        }
        assert!(serde_json::from_slice::<Revocation>(GO_FFFD_REVOCATION.as_bytes()).is_ok());

        let o: Ovlast = serde_json::from_str(GO_LONE_SURROGATE_OVLAST).unwrap();
        assert_eq!(o.device_id, "\u{FFFD}");
        let network = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert_eq!(o.verify(&network, 1_760_000_060), Ok(()));
    }

    /// (record, time field, time on the wire, what Go's `json.Marshal` writes for it).
    /// Go column: go1.27.1, `json.Unmarshal` and then `json.Marshal` of the record with
    /// its times in UTC. Go reads all of these, but writes a time only in years 0 to 9999
    /// in UTC; for any other, `json.Marshal` fails (`MARSHALERR`).
    const TIMES_GO_WRITES: &[(&str, &str, &str, &str)] = &[
        ("o", "issuedAt", "9999-12-31T23:59:59-01:00", "MARSHALERR"),
        (
            "o",
            "expiresAt",
            "9999-12-31T23:59:59.5-01:00",
            "MARSHALERR",
        ),
        ("o", "expiresAt", "0000-01-01T00:00:00+01:00", "MARSHALERR"),
        (
            "m",
            "issuedAt",
            "0000-01-01T00:00:00.25+00:01",
            "MARSHALERR",
        ),
        ("p", "issuedAt", "9999-12-31T23:59:59-01:00", "MARSHALERR"),
        ("r", "issuedAt", "0000-01-01T00:00:00+01:00", "MARSHALERR"),
        (
            "r",
            "opozvanoAt",
            "9999-12-31T23:59:59.5-01:00",
            "MARSHALERR",
        ),
        (
            "o",
            "issuedAt",
            "9999-12-31T23:59:59+00:00",
            "9999-12-31T23:59:59Z",
        ),
        (
            "o",
            "expiresAt",
            "0000-01-01T00:00:00Z",
            "0000-01-01T00:00:00Z",
        ),
        (
            "r",
            "opozvanoAt",
            "9999-12-31T23:59:59+00:00",
            "9999-12-31T23:59:59Z",
        ),
        (
            "r",
            "issuedAt",
            "0000-01-01T00:00:00Z",
            "0000-01-01T00:00:00Z",
        ),
    ];

    #[test]
    fn times_outside_years_go_writes_fail_to_write() {
        const O: &str = r#"{"network":"n","deviceId":"d","deviceKey":"k","issuedBy":"b","issuedAt":"2026-01-01T00:00:00Z","expiresAt":"2027-01-01T00:00:00Z","signature":"s"}"#;
        const R: &str = r#"{"id":"i","vrsta":"ovlast","nodeId":"n","publicKey":"p","issuedAt":"2026-01-01T00:00:00Z","opozvanoAt":"2026-01-02T00:00:00Z","opozvao":"o","potpisnik":"q","potpis":"AA=="}"#;
        for (record, field, wire, go) in TIMES_GO_WRITES {
            let set = |text: &str| {
                let start = text.find(&format!("\"{field}\":\"")).unwrap() + field.len() + 4;
                let end = start + text[start..].find('"').unwrap();
                format!("{}{wire}{}", &text[..start], &text[end..])
            };
            let written = match *record {
                "o" => to_go_json_vec(&serde_json::from_str::<Ovlast>(&set(O)).unwrap()),
                "m" | "p" => {
                    let (m, p) = if *record == "m" {
                        (set(O), O.to_owned())
                    } else {
                        (O.to_owned(), set(O))
                    };
                    let text = format!("{},\"primatelj\":{p}}}", &m[..m.len() - 1]);
                    to_go_json_vec(&serde_json::from_str::<Membership>(&text).unwrap())
                }
                _ => to_go_json_vec(&serde_json::from_str::<Revocation>(&set(R)).unwrap()),
            };
            match written {
                Ok(text) => {
                    let text = String::from_utf8(text).unwrap();
                    assert!(text.contains(&format!("\"{field}\":\"{go}\"")), "{text}");
                }
                Err(_) => assert_eq!(*go, "MARSHALERR", "{record} {field} {wire}"),
            }
        }
    }

    #[test]
    fn records_read_as_in_go() {
        for (kind, text, go, rust) in EDGES {
            let got = read(kind, text);
            if *go == "GRESKA" || *rust == "GRESKA" {
                assert_eq!(got, None, "{kind} {text}");
            } else {
                assert_eq!(got.as_deref(), Some(*go), "{kind} {text}");
            }
        }
    }

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    /// A revocation Go signs and writes, with one field name changed. Go column: whether
    /// Go, after `json.Unmarshal`, takes the revocation as valid on its own (id and
    /// signature, as `verify_self`). Before, Rust read the old names as aliases, so with
    /// `kind` it took a revocation Go does not.
    #[test]
    fn revocation_under_other_names_as_in_go() {
        let r = Revocation {
            id: String::new(),
            kind: REVOCATION_KIND_MEMBERSHIP.into(),
            target_id: "n".into(),
            public_key: "pk".into(),
            issued_at: 1_760_000_000,
            revoked_at: 1_760_000_100,
            issued_at_nanos: 0,
            revoked_at_nanos: 0,
            revoked_by: "o".into(),
            signer_key: String::new(),
            signature: String::new(),
        }
        .sign(&key(31));
        let text = serde_json::to_string(&r).unwrap();
        assert_eq!(
            text,
            r#"{"id":"clanstvo:pk:1760000000:199d9933bd356472","vrsta":"clanstvo","nodeId":"n","publicKey":"pk","issuedAt":"2025-10-09T08:53:20Z","opozvanoAt":"2025-10-09T08:55:00Z","opozvao":"o","potpisnik":"QwRr/kCSs+lJlOraFdzCDYqqB7ZY/TlU644O+4vcpd4=","potpis":"zIus5D/X56UMUxjJnWYbHRi2X/Dg++Pz44RGkiAJiQBH5FuL2WCNltY8uRDcRQrLGvc7KPxEVHbIKwx/xk3sBA=="}"#,
            "the text Go writes"
        );
        for (from, to, go) in [
            ("", "", true),
            ("\"vrsta\"", "\"kind\"", false),
            ("\"vrsta\"", "\"VRSTA\"", true),
            ("\"vrsta\"", "\"vr\u{17F}ta\"", true),
            ("\"nodeId\"", "\"targetId\"", false),
            ("\"opozvanoAt\"", "\"revokedAt\"", false),
            ("\"opozvao\"", "\"revokedBy\"", false),
            ("\"potpisnik\"", "\"signerKey\"", false),
            ("\"potpis\"", "\"signature\"", false),
        ] {
            let text = if from.is_empty() {
                text.clone()
            } else {
                text.replacen(from, to, 1)
            };
            let back: Revocation = serde_json::from_str(&text).unwrap();
            assert_eq!(back.verify_self().is_ok(), go, "{from} -> {to}");
        }
    }

    /// A membership with no expiry, signed by the network key as Go signs it, with its
    /// times changed on the wire. Go column: `json.Unmarshal`, then Go's check of the
    /// membership a year later.
    #[test]
    fn membership_times_as_in_go() {
        let net = key(21);
        let device = key(23).verifying_key();
        let mut m = Membership {
            network: public_key_to_base64(net.verifying_key().as_bytes()),
            device_id: "clan".into(),
            device_key: public_key_to_base64(device.as_bytes()),
            issued_by: "root".into(),
            issued_at: 1_760_000_000,
            issued_at_nanos: 0,
            expires_at: Expiry::NEVER,
            signature: String::new(),
            admitter: None,
        };
        m.signature = STANDARD.encode(net.sign(&m.signed_bytes()).to_bytes());
        let text = serde_json::to_string(&m).unwrap();
        assert_eq!(
            text,
            r#"{"network":"1UIH2hlJd9z0atv+wrwudbUtWopCGE/t/cAAJPDj6No=","deviceId":"clan","deviceKey":"Md6+VdN8cidosTcTHKpghwgLLgtguUvXhdFFdc+kmLw=","issuedBy":"root","issuedAt":"2025-10-09T08:53:20Z","expiresAt":"0001-01-01T00:00:00Z","signature":"1B7mOatf9g20VmX1KzJzqj7L9Fp4w21D4WFzRtb0PZPYYZcBKptvwalsbshudEgDz13d48R6ZtnDJxf3n0s9BQ=="}"#,
            "the text Go writes"
        );
        let now = 1_770_000_000;
        let zero = r#""expiresAt":"0001-01-01T00:00:00Z""#;
        for (from, to, go) in [
            ("", "", "prima"),
            // Missing or null, the expiry is Go's zero time: no expiry, as signed.
            (&format!(",{zero}")[..], "", "prima"),
            (zero, r#""expiresAt":null"#, "prima"),
            (zero, r#""expiresAt":"0001-01-01T00:00:00.0Z""#, "prima"),
            // Go: expired in year 1. Rust: a bad record.
            (zero, r#""expiresAt":"0001-01-01T00:00:00.5Z""#, "istekao"),
            (zero, r#""expiresAt":-62135596800"#, "GRESKA"),
            (
                r#""issuedAt":"2025-10-09T08:53:20Z""#,
                r#""issuedAt":1760000000"#,
                "GRESKA",
            ),
            ("\"signature\"", "\"SIGNATURE\"", "prima"),
        ] {
            let text = if from.is_empty() {
                text.clone()
            } else {
                text.replacen(from, to, 1)
            };
            let got = match serde_json::from_str::<Membership>(&text) {
                Err(_) => "GRESKA",
                Ok(m) => match m.verify(&net.verifying_key(), &device, now) {
                    Ok(()) => "prima",
                    Err(TrustError::Expired) => "istekao",
                    Err(e) => panic!("{e:?}"),
                },
            };
            let rust = if go == "istekao" { "GRESKA" } else { go };
            assert_eq!(got, rust, "{from} -> {to}");
        }
    }

    /// Times with a part of a second, in an ovlast and a membership signed for real (keys
    /// from seeds 1, 2 and 3, as in the Go probe), written, read back and checked. The
    /// part of a second is not signed, but Go keeps it and compares the records' times in
    /// full; the clock (`now`) is a whole second on both sides. Go column: Go's
    /// `json.Marshal`, `json.Unmarshal` and check, go1.27.1. Before, Rust read whole
    /// seconds and took rows Go turns away (`dulje`, `ne vrijedi`, `buducnost`).
    #[test]
    fn fractions_of_a_second_as_in_go() {
        const I: i64 = 1_760_000_000;
        type T = (i64, u32);
        const ZERO: T = (GO_ZERO_TIME_UNIX, 0);
        let (net, adm, mem) = (key(1), key(2), key(3));
        let net_pub = net.verifying_key();
        let ovlast = |iss: T, exp: T| {
            let mut o = Ovlast {
                network: public_key_to_base64(net_pub.as_bytes()),
                device_id: "prim".into(),
                device_key: public_key_to_base64(adm.verifying_key().as_bytes()),
                issued_by: "root".into(),
                issued_at: iss.0,
                issued_at_nanos: iss.1,
                expires_at: Expiry::from_go_time(GoTime {
                    unix: exp.0,
                    nanos: exp.1,
                }),
                signature: String::new(),
            };
            o.signature = STANDARD.encode(net.sign(&o.signed_bytes()).to_bytes());
            o
        };
        let outcome = |r: Result<(), TrustError>| match r {
            Ok(()) => "ok",
            Err(TrustError::ExceedsAdmitterAuthority) => "dulje",
            Err(TrustError::AdmitterOvlast(_)) => "ne vrijedi",
            Err(TrustError::IssuedInFuture) => "buducnost",
            Err(TrustError::Expired) => "istekao",
            Err(e) => panic!("{e:?}"),
        };

        // (ovlast issuedAt, expiresAt, membership issuedAt, expiresAt, now, Go)
        let rows: &[(T, T, T, T, i64, &str)] = &[
            (
                (I, 0),
                (I + 86400, 0),
                (I + 100, 0),
                (I + 3600, 0),
                I + 200,
                "ok",
            ),
            (
                (I, 0),
                (I + 86400, 200_000_000),
                (I + 100, 0),
                (I + 86400, 700_000_000),
                I + 200,
                "dulje",
            ),
            (
                (I, 0),
                (I + 86400, 500_000_000),
                (I + 100, 0),
                (I + 86400, 500_000_000),
                I + 200,
                "ok",
            ),
            (
                (I, 0),
                (I + 86400, 700_000_000),
                (I + 100, 0),
                (I + 86400, 200_000_000),
                I + 200,
                "ok",
            ),
            (
                (I, 0),
                (I + 86401, 0),
                (I + 100, 0),
                (I + 86400, 999_999_999),
                I + 200,
                "ok",
            ),
            (
                (I, 0),
                (I + 86400, 1),
                (I + 100, 0),
                (I + 86400, 0),
                I + 200,
                "ok",
            ),
            (
                (I + 100, 700_000_000),
                (I + 86400, 0),
                (I + 100, 200_000_000),
                (I + 3600, 0),
                I + 200,
                "ne vrijedi",
            ),
            (
                (I + 100, 700_000_000),
                (I + 86400, 0),
                (I + 100, 700_000_000),
                (I + 3600, 0),
                I + 200,
                "ok",
            ),
            (
                (I + 100, 200_000_000),
                (I + 86400, 0),
                (I + 100, 700_000_000),
                (I + 3600, 0),
                I + 200,
                "ok",
            ),
            (
                (I, 0),
                (I + 100, 200_000_000),
                (I + 100, 700_000_000),
                (I + 100, 0),
                I + 200,
                "ne vrijedi",
            ),
            (
                (I, 0),
                (I + 100, 300_000_000),
                (I + 100, 300_000_000),
                (I + 100, 0),
                I + 200,
                "istekao",
            ),
            (
                (I, 0),
                (I + 86400, 0),
                (I + 100, 500_000_000),
                (I + 3600, 0),
                I + 100 - 3600,
                "buducnost",
            ),
            (
                (I, 0),
                (I + 86400, 0),
                (I + 100, 0),
                (I + 3600, 0),
                I + 100 - 3600,
                "ok",
            ),
            (
                (I, 0),
                (I + 86400, 0),
                (I + 100, 0),
                (I + 3600, 500_000_000),
                I + 3600,
                "ok",
            ),
            (
                (I, 0),
                (I + 86400, 0),
                (I + 100, 0),
                (I + 3600, 500_000_000),
                I + 3601,
                "istekao",
            ),
            (
                (I, 0),
                ZERO,
                (I + 100, 0),
                (I + 3600, 500_000_000),
                I + 200,
                "ok",
            ),
            (
                (I, 0),
                (I + 86400, 500_000_000),
                (I + 100, 0),
                ZERO,
                I + 200,
                "dulje",
            ),
            (
                (I, 100_000_000),
                (I + 86400, 900_000_000),
                (I + 100, 400_000_000),
                (I + 86400, 800_000_000),
                I + 200,
                "ok",
            ),
            (
                (I + 100, 0),
                (I + 86400, 0),
                (I + 100, 1),
                (I + 3600, 0),
                I + 200,
                "ok",
            ),
        ];
        for (n, &(o_iss, o_exp, m_iss, m_exp, now, go)) in rows.iter().enumerate() {
            let mut m = Membership {
                network: public_key_to_base64(net_pub.as_bytes()),
                device_id: "clan".into(),
                device_key: public_key_to_base64(mem.verifying_key().as_bytes()),
                issued_by: "prim".into(),
                issued_at: m_iss.0,
                issued_at_nanos: m_iss.1,
                expires_at: Expiry::from_go_time(GoTime {
                    unix: m_exp.0,
                    nanos: m_exp.1,
                }),
                signature: String::new(),
                admitter: Some(ovlast(o_iss, o_exp)),
            };
            m.signature = STANDARD.encode(adm.sign(&m.signed_bytes()).to_bytes());
            let text = serde_json::to_string(&m).unwrap();
            let back: Membership = serde_json::from_str(&text).unwrap();
            assert_eq!(back, m, "row {n}");
            let got = outcome(back.verify(&net_pub, &mem.verifying_key(), now));
            assert_eq!(got, go, "row {n}: {text}");
            if n == 17 {
                assert_eq!(
                    text,
                    r#"{"network":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","deviceId":"clan","deviceKey":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=","issuedBy":"prim","issuedAt":"2025-10-09T08:55:00.4Z","expiresAt":"2025-10-10T08:53:20.8Z","signature":"v1cRfRV7OT7mjemaAYYYQDmtTYzO/ZSLHFRug1RIUnfKwdKEOV7d/o/sbODSvMOo51MybRuA3o+0JFvwv49QBQ==","primatelj":{"network":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","deviceId":"prim","deviceKey":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=","issuedBy":"root","issuedAt":"2025-10-09T08:53:20.1Z","expiresAt":"2025-10-10T08:53:20.9Z","signature":"P6Rzbs0Mfc1x+o0PfCwIrllhEXqIPYHLir63RVNixuNlqZAr9HA57S8M1HQLy7ieelS20juKpHiLF7UigpE/Bg=="}}"#,
                    "the text Go writes"
                );
            }
        }

        // The ovlast alone, checked at a whole second (Go column the same way).
        for (iss, exp, at, go) in [
            ((I, 500_000_000), (I + 86400, 0), I, "ne vrijedi"),
            ((I, 0), (I + 86400, 0), I, "ok"),
            ((I, 0), (I + 86400, 500_000_000), I + 86400, "ok"),
            ((I, 0), (I + 86400, 500_000_000), I + 86401, "ne vrijedi"),
        ] {
            let o: Ovlast =
                serde_json::from_str(&serde_json::to_string(&ovlast(iss, exp)).unwrap()).unwrap();
            let got = match o.verify(&net_pub, at) {
                Ok(()) => "ok",
                Err(TrustError::NotYetValid | TrustError::Expired) => "ne vrijedi",
                Err(e) => panic!("{e:?}"),
            };
            assert_eq!(got, go, "{iss:?} {exp:?} {at}");
        }
    }
}
