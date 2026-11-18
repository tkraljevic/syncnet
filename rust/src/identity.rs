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
pub const CREDENTIAL_URI_PREFIX: &str = "list2cart:vjerodajnice:";
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

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
            Self::InvalidPublicKey(m) => write!(f, "neispravan Ed25519 javni kljuc: {m}"),
            Self::KeyFileAlreadyExists(p) => {
                write!(f, "datoteka kljuca {p} vec postoji — odbijeno prepisivanje")
            }
            Self::KeyIo(m) => write!(f, "I/O greska kljuca: {m}"),
            Self::KeyParse(m) => write!(f, "greska citanja privatnog kljuca: {m}"),
            Self::CertGen(m) => write!(f, "greska izrade certifikata: {m}"),
            Self::InvalidPeerCert(m) => write!(f, "neispravan certifikat partnera: {m}"),
            Self::WrongProtocol { peer, expected } => write!(
                f,
                "razmjena odbijena: partner koristi protokol `{peer}`, a ovaj uredjaj `{expected}`"
            ),
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

pub fn parse_public_key(s: &str) -> Result<VerifyingKey, IdentityError> {
    let bytes = STANDARD
        .decode(s.trim())
        .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        IdentityError::InvalidPublicKey(format!("ocekivano 32 B, dobiveno {} B", v.len()))
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))
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
                "vjerodajnice su prevelike".to_owned(),
            ));
        }
        let uri_str = format!(
            "urn:{}{}",
            CREDENTIAL_URI_PREFIX,
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
            "certifikat partnera ne nosi Ed25519 kljuc".to_owned(),
        ));
    }
    let pk_bytes: [u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| {
            IdentityError::InvalidPeerCert("neispravna duljina Ed25519 kljuca".to_owned())
        })?;
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
        let full_prefix = format!("urn:{CREDENTIAL_URI_PREFIX}");
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

#[cfg(test)]
mod tests {
    use super::*;

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
