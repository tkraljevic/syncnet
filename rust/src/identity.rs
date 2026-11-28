use crate::wire::go_base64::decode_std;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{
    SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::rngs::OsRng;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, PKCS_ED25519, SanType,
};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::*;

pub const CERT_CN_SUFFIX: &str = "-sync";
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

pub fn credential_uri_prefix(protocol: &str) -> String {
    format!("{protocol}:vjerodajnice:")
}

pub fn credential_urn_prefix(protocol: &str) -> String {
    format!("urn:{protocol}:vjerodajnice:")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    InvalidPublicKey(String),
    KeyFileAlreadyExists(String),
    KeyIo(String),
    KeyParse(String),
    CertGen(String),
    InvalidPeerCert(String),
    WrongProtocol { peer: String, expected: String },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey(m) => write!(f, "invalid Ed25519 public key: {m}"),
            Self::KeyFileAlreadyExists(p) => {
                write!(f, "key file already exists: {p}")
            }
            Self::KeyIo(m) => write!(f, "key I/O error: {m}"),
            Self::KeyParse(m) => write!(f, "private key parse error: {m}"),
            Self::CertGen(m) => write!(f, "certificate generation error: {m}"),
            Self::InvalidPeerCert(m) => write!(f, "invalid peer certificate: {m}"),
            Self::WrongProtocol { peer, expected } => {
                write!(f, "protocol mismatch: peer={peer}, expected={expected}")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

pub fn public_key_to_base64(pub_bytes: &[u8; 32]) -> String {
    STANDARD.encode(pub_bytes)
}

pub fn verifying_key_to_base64(vk: &VerifyingKey) -> String {
    public_key_to_base64(vk.as_bytes())
}

/// Reads a public key from the wire as the Go implementation reads one: base64 as Go reads it
/// (`wire::go_base64`, so no trimming, `\r` and `\n` skipped, leftover bits ignored) and
/// exactly 32 bytes.
///
/// Whether the bytes are a point of the curve is not checked here. Go checks that only when
/// it verifies a signature under the key, and then a key that is not a point is a bad
/// signature, not a bad key. A reader that must tell the two apart, as Go does, reads with
/// this and then `VerifyingKey::from_bytes`.
pub fn parse_public_key_bytes(s: &str) -> Result<[u8; 32], IdentityError> {
    let bytes = decode_std(s).map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        IdentityError::InvalidPublicKey(format!("ocekivano 32 B, dobiveno {} B", v.len()))
    })
}

/// [`parse_public_key_bytes`] and then the point of the curve: both a key that does not
/// read and one that is not a point are `InvalidPublicKey`.
pub fn parse_public_key(s: &str) -> Result<VerifyingKey, IdentityError> {
    VerifyingKey::from_bytes(&parse_public_key_bytes(s)?)
        .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))
}

pub fn principal_id_from_key(pub_bytes: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pub_bytes);
    hex::encode(&digest[..16])
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn signing_key_to_pkcs8_pem(sk: &SigningKey) -> Result<String, IdentityError> {
    sk.to_pkcs8_pem(Default::default())
        .map(|z| z.to_string())
        .map_err(|e| IdentityError::KeyParse(e.to_string()))
}

pub fn signing_key_from_pkcs8_pem(pem: &str) -> Result<SigningKey, IdentityError> {
    SigningKey::from_pkcs8_pem(pem).map_err(|e| IdentityError::KeyParse(e.to_string()))
}

pub fn load_key(path: &Path) -> Result<Option<SigningKey>, IdentityError> {
    match fs::read_to_string(path) {
        Ok(pem) => signing_key_from_pkcs8_pem(&pem).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(IdentityError::KeyIo(e.to_string())),
    }
}

pub fn save_key_exclusive(path: &Path, sk: &SigningKey) -> Result<(), IdentityError> {
    if path.exists() {
        return Err(IdentityError::KeyFileAlreadyExists(
            path.display().to_string(),
        ));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| IdentityError::KeyIo(e.to_string()))?;
    }
    let pem = signing_key_to_pkcs8_pem(sk)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| IdentityError::KeyIo(e.to_string()))?;
    file.write_all(pem.as_bytes())
        .map_err(|e| IdentityError::KeyIo(e.to_string()))?;
    file.sync_all()
        .map_err(|e| IdentityError::KeyIo(e.to_string()))?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| IdentityError::KeyIo(e.to_string()))?;
    }
    Ok(())
}

pub fn load_or_create_key(path: &Path) -> Result<SigningKey, IdentityError> {
    if let Some(existing) = load_key(path)? {
        return Ok(existing);
    }
    let sk = generate_signing_key();
    save_key_exclusive(path, &sk)?;
    Ok(sk)
}

pub fn cert_cn_for_protocol(protocol: &str) -> String {
    format!("{protocol}{CERT_CN_SUFFIX}")
}

pub fn build_self_signed_cert_der(
    sk: &SigningKey,
    protocol: &str,
    credentials: Option<&[u8]>,
) -> Result<Vec<u8>, IdentityError> {
    let pem = signing_key_to_pkcs8_pem(sk)?;
    let kp = KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_ED25519)
        .map_err(|e| IdentityError::CertGen(e.to_string()))?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cert_cn_for_protocol(protocol));
    params.distinguished_name = dn;

    if let Some(cred) = credentials
        && !cred.is_empty()
    {
        if cred.len() > MAX_CREDENTIAL_BYTES {
            return Err(IdentityError::CertGen(
                "credentials exceed max size".to_owned(),
            ));
        }
        let uri_str = format!(
            "{}{}",
            credential_urn_prefix(protocol),
            URL_SAFE_NO_PAD.encode(cred)
        );
        let ia5 =
            Ia5String::try_from(uri_str).map_err(|e| IdentityError::CertGen(e.to_string()))?;
        params.subject_alt_names = vec![SanType::URI(ia5)];
    }

    let cert = params
        .self_signed(&kp)
        .map_err(|e| IdentityError::CertGen(e.to_string()))?;
    Ok(cert.der().to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeerCert {
    pub public_key: [u8; 32],
    pub credentials: Option<Vec<u8>>,
}

pub fn verify_peer_cert_der(
    cert_der: &[u8],
    expected_protocol: &str,
) -> Result<VerifiedPeerCert, IdentityError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| IdentityError::InvalidPeerCert(e.to_string()))?;

    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 {
        return Err(IdentityError::InvalidPeerCert(
            "peer certificate does not carry an Ed25519 key".to_owned(),
        ));
    }
    let pk_bytes: [u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| IdentityError::InvalidPeerCert("invalid Ed25519 key length".to_owned()))?;
    VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| IdentityError::InvalidPeerCert(e.to_string()))?;

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("");
    let expected_cn = cert_cn_for_protocol(expected_protocol);
    if cn != expected_cn {
        let trimmed = cn.strip_suffix(CERT_CN_SUFFIX).unwrap_or(cn);
        return Err(IdentityError::WrongProtocol {
            peer: sanitize_name_for_msg(trimmed),
            expected: expected_protocol.to_owned(),
        });
    }

    let mut credentials = None;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let full_prefix = credential_urn_prefix(expected_protocol);
        for name in &san.value.general_names {
            if let GeneralName::URI(uri) = name
                && let Some(encoded) = uri.strip_prefix(&full_prefix)
                && encoded.len() <= MAX_CREDENTIAL_BYTES * 4 / 3 + 4
                && let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded)
                && decoded.len() <= MAX_CREDENTIAL_BYTES
            {
                credentials = Some(decoded);
                break;
            }
        }
    }

    Ok(VerifiedPeerCert {
        public_key: pk_bytes,
        credentials,
    })
}

fn sanitize_name_for_msg(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(64)
        .collect();
    if name.chars().count() > 64 {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

/// The edges of a public key on the wire, shared by the tests of every reader of one.
///
/// Each reader has its own table of what Go makes of these texts at the same place on the
/// wire. The names are the ones the Go probe prints.
#[cfg(test)]
pub(crate) mod key_edges {
    use super::*;
    use ed25519_dalek::Signer;

    /// Who signs the record that carries the key.
    pub(crate) enum EdgeSigner {
        Key(SigningKey),
        /// `R || 0`: holds under a small-order key whenever `[k]A` comes out as `R`.
        Forged([u8; 32]),
    }

    impl EdgeSigner {
        pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
            match self {
                Self::Key(sk) => sk.sign(msg).to_bytes(),
                Self::Forged(r) => {
                    let mut sig = [0u8; 64];
                    sig[..32].copy_from_slice(r);
                    sig
                }
            }
        }
    }

    pub(crate) struct KeyEdge {
        pub(crate) name: &'static str,
        pub(crate) key: String,
        pub(crate) signer: EdgeSigner,
    }

    /// The signer of every edge that is not about a key of its own.
    pub(crate) fn edge_signer() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    /// Flips the lowest bit of the last character before the padding: the bytes stay the
    /// same, the text is no longer the canonical one.
    pub(crate) fn with_trailing_bit(text: &str) -> String {
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

    pub(crate) fn key_edges() -> Vec<KeyEdge> {
        let k = public_key_to_base64(edge_signer().verifying_key().as_bytes());
        assert_eq!(k, "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=");
        let raw = STANDARD.decode(&k).unwrap();
        // A key with + and / in it, for the URL-safe alphabet.
        let other = SigningKey::from_bytes(&[2; 32]);
        let k2 = public_key_to_base64(other.verifying_key().as_bytes());
        assert_eq!(k2, "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=");

        // The identity point (order 1) in three encodings, and (0, -1) of order 2.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut identity_y_plus_p = [0xffu8; 32];
        identity_y_plus_p[0] = 0xee;
        identity_y_plus_p[31] = 0x7f;
        let mut identity_signed = identity;
        identity_signed[31] = 0x80;
        let mut order_two = [0xffu8; 32];
        order_two[0] = 0xec;
        order_two[31] = 0x7f;
        // y = 2 is not a point of the curve.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;

        let by = |name, key: String| KeyEdge {
            name,
            key,
            signer: EdgeSigner::Key(edge_signer()),
        };
        let forged = |name, key: [u8; 32], r: [u8; 32]| KeyEdge {
            name,
            key: STANDARD.encode(key),
            signer: EdgeSigner::Forged(r),
        };
        vec![
            by("ispravno", k.clone()),
            by("prazno", String::new()),
            by("samo_razmak", " ".into()),
            by("nije_base64", "nije kljuc".into()),
            by("31B", STANDARD.encode(&raw[..31])),
            by("33B", STANDARD.encode([&raw[..], &[0]].concat())),
            by("bez_paddinga", k.trim_end_matches('=').into()),
            by("visak_paddinga", format!("{k}=")),
            by("razmak_ispred", format!(" {k}")),
            by("razmak_iza", format!("{k} ")),
            by("tab_iza", format!("{k}\t")),
            by("novi_red_ispred", format!("\n{k}")),
            by("novi_red_iza", format!("{k}\n")),
            by("crlf_iza", format!("{k}\r\n")),
            by("novi_red_u_sredini", format!("{}\n{}", &k[..20], &k[20..])),
            by("visak_bitova", with_trailing_bit(&k)),
            KeyEdge {
                name: "url_safe",
                key: k2.replace('+', "-").replace('/', "_"),
                signer: EdgeSigner::Key(other.clone()),
            },
            KeyEdge {
                name: "url_safe_kanonski",
                key: k2,
                signer: EdgeSigner::Key(other),
            },
            by("nije_tocka", STANDARD.encode(not_a_point)),
            forged("identitet", identity, identity),
            forged("identitet_nekanonski_y", identity_y_plus_p, identity),
            forged("identitet_s_predznakom", identity_signed, identity),
            forged("red2_R_identitet", order_two, identity),
            forged("red2_R_tocka", order_two, order_two),
        ]
    }

    /// Runs `outcome` over every edge and fails with each edge where it is not what Go
    /// gives. `table` is `(edge, Go, Rust before)`; the last column is a record only, it
    /// shows where Rust used to differ. A Go column of `-` is a case Go cannot answer (the
    /// signed bytes are not the same); `outcome` still runs, but nothing is compared.
    pub(crate) fn assert_edges_as_in_go(
        table: &[(&str, &str, &str)],
        mut outcome: impl FnMut(&KeyEdge) -> String,
    ) {
        let edges = key_edges();
        let mut wrong = Vec::new();
        for edge in &edges {
            let Some((_, go, _before)) = table.iter().find(|row| row.0 == edge.name) else {
                wrong.push(format!("{}: no row in the table", edge.name));
                continue;
            };
            let got = outcome(edge);
            if *go != "-" && got != *go {
                wrong.push(format!("{}: Go {go}, Rust {got}", edge.name));
            }
        }
        for (name, _, _) in table {
            if !edges.iter().any(|e| e.name == *name) {
                wrong.push(format!("{name}: no such edge"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader reads as the Go implementation reads a public key. The Rust column is the
    /// old `parse_public_key`, which trimmed and then read strictly, and checked the point.
    #[test]
    fn public_key_reads_as_in_go() {
        use key_edges::{assert_edges_as_in_go, key_edges};

        #[rustfmt::skip]
        let table = [
            ("ispravno", "procitan", "procitan"),
            ("prazno", "greska", "greska"),
            ("samo_razmak", "greska", "greska"),
            ("nije_base64", "greska", "greska"),
            ("31B", "greska", "greska"),
            ("33B", "greska", "greska"),
            ("bez_paddinga", "greska", "greska"),
            ("visak_paddinga", "greska", "greska"),
            ("razmak_ispred", "greska", "procitan"),
            ("razmak_iza", "greska", "procitan"),
            ("tab_iza", "greska", "procitan"),
            ("novi_red_ispred", "procitan", "procitan"),
            ("novi_red_iza", "procitan", "procitan"),
            ("crlf_iza", "procitan", "procitan"),
            ("novi_red_u_sredini", "procitan", "greska"),
            ("visak_bitova", "procitan", "greska"),
            ("url_safe", "greska", "greska"),
            ("url_safe_kanonski", "procitan", "procitan"),
            ("nije_tocka", "procitan", "greska"),
            ("identitet", "procitan", "procitan"),
            ("identitet_nekanonski_y", "procitan", "procitan"),
            ("identitet_s_predznakom", "procitan", "procitan"),
            ("red2_R_identitet", "procitan", "procitan"),
            ("red2_R_tocka", "procitan", "procitan"),
        ];
        assert_edges_as_in_go(&table, |edge| {
            match parse_public_key_bytes(&edge.key) {
                Ok(_) => "procitan",
                Err(_) => "greska",
            }
            .into()
        });

        // With the point on top, only the key that is not a point changes; small-order
        // points are points, and Go does not refuse them either.
        for edge in key_edges() {
            let bytes = parse_public_key_bytes(&edge.key);
            let key = parse_public_key(&edge.key);
            if edge.name == "nije_tocka" {
                assert!(bytes.is_ok() && key.is_err());
            } else {
                assert_eq!(bytes.ok(), key.ok().map(|k| k.to_bytes()), "{}", edge.name);
            }
        }
    }

    #[test]
    fn key_persistence_never_overwrites_existing_or_corrupt_file() {
        let dir = std::env::temp_dir().join(format!("l2c-key-test-{}", uuid::Uuid::new_v4()));
        let key_path = dir.join("device.key");

        let sk1 = load_or_create_key(&key_path).expect("create key");
        let sk2 = load_or_create_key(&key_path).expect("reload key");
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert!(save_key_exclusive(&key_path, &generate_signing_key()).is_err());

        fs::write(&key_path, b"corrupt pem").expect("corrupt file");
        assert!(load_or_create_key(&key_path).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn self_signed_cert_carries_ed25519_protocol_cn_and_credentials() {
        let sk = generate_signing_key();
        let cred = br#"{"member":"ok"}"#;
        let der = build_self_signed_cert_der(&sk, "list2cart", Some(cred)).expect("cert");

        let verified = verify_peer_cert_der(&der, "list2cart").expect("verify");
        assert_eq!(verified.public_key, sk.verifying_key().to_bytes());
        assert_eq!(verified.credentials.as_deref(), Some(cred.as_slice()));

        let wrong_proto = verify_peer_cert_der(&der, "list2cart-sim");
        assert!(matches!(
            wrong_proto,
            Err(IdentityError::WrongProtocol { .. })
        ));
    }

    #[test]
    fn key_loading_rejects_non_ed25519_and_preserves_unreadable_or_unwritable_files() {
        let dir = std::env::temp_dir().join(format!("l2c-key-edge-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("mkdir");

        assert_eq!(load_key(&dir.join("missing.key")).expect("missing"), None);

        let ecdsa_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ecdsa");
        let ecdsa_pem = ecdsa_kp.serialize_pem();
        for (label, content) in [
            ("not_pem", "nije kljuc".to_owned()),
            (
                "public_pem",
                "-----BEGIN PUBLIC KEY-----\nYWJj\n-----END PUBLIC KEY-----\n".to_owned(),
            ),
            (
                "corrupt_der",
                "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n".to_owned(),
            ),
            ("ecdsa_key", ecdsa_pem),
        ] {
            let p = dir.join(format!("{label}.key"));
            fs::write(&p, content.as_bytes()).expect("write bad key");
            assert!(
                load_key(&p).is_err(),
                "{label} must be rejected as an Ed25519 private key"
            );
            assert!(
                load_or_create_key(&p).is_err(),
                "{label} must not be overwritten by load_or_create_key"
            );
        }

        // Non-Ed25519 X.509 certificate is rejected before CN inspection
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "list2cart-sync");
        params.distinguished_name = dn;
        let ecdsa_cert = params.self_signed(&ecdsa_kp).expect("ecdsa cert");
        assert!(matches!(
            verify_peer_cert_der(ecdsa_cert.der(), "list2cart"),
            Err(IdentityError::InvalidPeerCert(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = dir.join("unreadable.key");
            let sk = generate_signing_key();
            save_key_exclusive(&unreadable, &sk).expect("save unreadable");
            let original_bytes = fs::read(&unreadable).expect("read original");
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o200)).expect("chmod 200");
            assert!(load_or_create_key(&unreadable).is_err());
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).expect("chmod 600");
            let after_bytes = fs::read(&unreadable).expect("read after");
            assert_eq!(
                original_bytes, after_bytes,
                "unreadable key file must never be overwritten"
            );

            let ro_dir = dir.join("readonly");
            fs::create_dir_all(&ro_dir).expect("mkdir ro");
            fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o500)).expect("chmod 500");
            assert!(load_or_create_key(&ro_dir.join("device.key")).is_err());
            fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o700)).expect("chmod 700");
        }

        let _ = fs::remove_dir_all(dir);
    }
}
