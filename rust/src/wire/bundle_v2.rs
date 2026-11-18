use crate::identity::{parse_public_key, public_key_to_base64};
use crate::wire::signal::base64_bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const BUNDLE_V2_FORMAT: u32 = 2;
pub const MAX_BUNDLE_PLAINTEXT: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleV2Error {
    UnsupportedFormat(u32),
    WrongProtocol(String),
    WrongRecipient,
    BadSignature,
    DecryptionFailed,
    InvalidHeader(String),
}

impl fmt::Display for BundleV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat(v) => write!(f, "nepodrzana inacica paketa: v{v}"),
            Self::WrongProtocol(p) => write!(f, "paket pripada drugom protokolu: {p}"),
            Self::WrongRecipient => write!(f, "paket nije namijenjen ovom uredjaju"),
            Self::BadSignature => write!(f, "potpis paketa nije valjan"),
            Self::DecryptionFailed => write!(f, "desifriranje paketa nije uspjelo"),
            Self::InvalidHeader(m) => write!(f, "neispravno zaglavlje paketa: {m}"),
        }
    }
}

impl std::error::Error for BundleV2Error {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedBundleV2 {
    pub format_version: u32,
    pub protocol: String,
    pub sender_pub_key: String,
    pub recipient_pub_key: String,
    #[serde(with = "base64_bytes")]
    pub ephemeral_x25519_pub: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl ProtectedBundleV2 {
    pub fn seal(
        protocol: &str,
        sender_sk: &SigningKey,
        recipient_pub_bytes: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Self, BundleV2Error> {
        if plaintext.len() > MAX_BUNDLE_PLAINTEXT {
            return Err(BundleV2Error::InvalidHeader("payload too large".into()));
        }
        let sender_pub_b64 = public_key_to_base64(sender_sk.verifying_key().as_bytes());
        let recipient_pub_b64 = public_key_to_base64(recipient_pub_bytes);

        let recipient_vk = ed25519_dalek::VerifyingKey::from_bytes(recipient_pub_bytes)
            .map_err(|e| BundleV2Error::InvalidHeader(e.to_string()))?;
        let recipient_x25519 = X25519PublicKey::from(recipient_vk.to_montgomery().to_bytes());

        let mut eph_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut eph_bytes);
        let eph_secret = StaticSecret::from(eph_bytes);
        let eph_pub = X25519PublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&recipient_x25519);
        if recipient_vk.is_weak() || !shared.was_contributory() {
            return Err(BundleV2Error::InvalidHeader("weak recipient key".into()));
        }

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let key_bytes = derive_bundle_key(
            protocol,
            shared.as_bytes(),
            &salt,
            &sender_pub_b64,
            &recipient_pub_b64,
        );
        let aad = canonical_aad(protocol, &sender_pub_b64, &recipient_pub_b64);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| BundleV2Error::DecryptionFailed)?;

        let mut bundle = Self {
            format_version: BUNDLE_V2_FORMAT,
            protocol: protocol.to_owned(),
            sender_pub_key: sender_pub_b64,
            recipient_pub_key: recipient_pub_b64,
            ephemeral_x25519_pub: eph_pub.as_bytes().to_vec(),
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            signature: Vec::new(),
        };
        let sig = sender_sk.sign(&bundle.signing_bytes());
        bundle.signature = sig.to_bytes().to_vec();
        Ok(bundle)
    }

    pub fn open(
        &self,
        expected_protocol: &str,
        recipient_sk: &SigningKey,
    ) -> Result<(Vec<u8>, [u8; 32]), BundleV2Error> {
        if self.format_version != BUNDLE_V2_FORMAT {
            return Err(BundleV2Error::UnsupportedFormat(self.format_version));
        }
        if self.protocol != expected_protocol {
            return Err(BundleV2Error::WrongProtocol(self.protocol.clone()));
        }
        if self.ephemeral_x25519_pub.len() != 32
            || self.salt.len() != 16
            || self.nonce.len() != 12
            || self.signature.len() != 64
            || self.ciphertext.len() < 16
            || self.ciphertext.len() > MAX_BUNDLE_PLAINTEXT + 16
        {
            return Err(BundleV2Error::InvalidHeader(
                "invalid header or payload length".into(),
            ));
        }
        let expected_recipient = public_key_to_base64(recipient_sk.verifying_key().as_bytes());
        if self.recipient_pub_key != expected_recipient {
            return Err(BundleV2Error::WrongRecipient);
        }

        let sender_vk = parse_public_key(&self.sender_pub_key)
            .map_err(|e| BundleV2Error::InvalidHeader(e.to_string()))?;
        let sig_arr: [u8; 64] = self
            .signature
            .clone()
            .try_into()
            .map_err(|_| BundleV2Error::BadSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        sender_vk
            .verify(&self.signing_bytes(), &sig)
            .map_err(|_| BundleV2Error::BadSignature)?;

        let eph_arr: [u8; 32] = self
            .ephemeral_x25519_pub
            .clone()
            .try_into()
            .map_err(|_| BundleV2Error::InvalidHeader("ephemeral key".into()))?;
        let eph_pub = X25519PublicKey::from(eph_arr);
        let nonce_arr: [u8; 12] = self
            .nonce
            .clone()
            .try_into()
            .map_err(|_| BundleV2Error::InvalidHeader("nonce".into()))?;

        let recipient_secret = StaticSecret::from(recipient_sk.to_scalar_bytes());
        let shared = recipient_secret.diffie_hellman(&eph_pub);
        if !shared.was_contributory() {
            return Err(BundleV2Error::InvalidHeader("weak ephemeral key".into()));
        }
        let key_bytes = derive_bundle_key(
            &self.protocol,
            shared.as_bytes(),
            &self.salt,
            &self.sender_pub_key,
            &self.recipient_pub_key,
        );
        let aad = canonical_aad(
            &self.protocol,
            &self.sender_pub_key,
            &self.recipient_pub_key,
        );

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_arr),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BundleV2Error::DecryptionFailed)?;

        Ok((plaintext, sender_vk.to_bytes()))
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.ciphertext.len());
        out.extend_from_slice(b"list2cart-bundle-sig-v2|");
        out.extend_from_slice(self.format_version.to_string().as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.protocol.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.sender_pub_key.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.recipient_pub_key.as_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.ephemeral_x25519_pub);
        out.push(b'|');
        out.extend_from_slice(&self.salt);
        out.push(b'|');
        out.extend_from_slice(&self.nonce);
        out.push(b'|');
        out.extend_from_slice(&self.ciphertext);
        out
    }
}

fn canonical_aad(protocol: &str, sender: &str, recipient: &str) -> Vec<u8> {
    format!("{protocol}-bundle-aad-v2|{sender}|{recipient}").into_bytes()
}

fn derive_bundle_key(
    protocol: &str,
    shared_secret: &[u8],
    salt: &[u8],
    sender: &str,
    recipient: &str,
) -> [u8; 32] {
    let info = canonical_aad(protocol, sender, recipient);
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("32 bytes is valid HKDF-SHA256 output");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_signing_key;

    #[test]
    fn sealed_bundle_opens_only_for_intended_recipient_and_detects_tampering() {
        let sender = generate_signing_key();
        let recipient = generate_signing_key();
        let wrong_recipient = generate_signing_key();

        let payload = br#"{"versions":[{"id":"v1"}]}"#;
        let bundle = ProtectedBundleV2::seal(
            "list2cart",
            &sender,
            recipient.verifying_key().as_bytes(),
            payload,
        )
        .expect("seal");

        let (opened, sender_pub) = bundle.open("list2cart", &recipient).expect("open");
        assert_eq!(opened, payload);
        assert_eq!(sender_pub, sender.verifying_key().to_bytes());

        assert_eq!(
            bundle.open("list2cart", &wrong_recipient),
            Err(BundleV2Error::WrongRecipient)
        );
        assert_eq!(
            bundle.open("list2cart-sim", &recipient),
            Err(BundleV2Error::WrongProtocol("list2cart".to_owned()))
        );

        let mut tampered = bundle.clone();
        tampered.ciphertext[0] ^= 0xFF;
        assert_eq!(
            tampered.open("list2cart", &recipient),
            Err(BundleV2Error::BadSignature)
        );
    }

    #[test]
    fn rejects_malformed_headers_and_noncontributory_exchange_even_if_signed() {
        let sender = generate_signing_key();
        let recipient = generate_signing_key();
        let original = ProtectedBundleV2::seal(
            "list2cart",
            &sender,
            recipient.verifying_key().as_bytes(),
            b"test",
        )
        .unwrap();
        let mut malformed = original.clone();
        malformed.salt.clear();
        malformed.signature = sender.sign(&malformed.signing_bytes()).to_bytes().to_vec();
        assert!(matches!(
            malformed.open("list2cart", &recipient),
            Err(BundleV2Error::InvalidHeader(_))
        ));
        let mut weak = original;
        weak.ephemeral_x25519_pub.fill(0);
        weak.signature = sender.sign(&weak.signing_bytes()).to_bytes().to_vec();
        assert!(matches!(
            weak.open("list2cart", &recipient),
            Err(BundleV2Error::InvalidHeader(_))
        ));
        assert!(
            ProtectedBundleV2::seal(
                "list2cart",
                &sender,
                recipient.verifying_key().as_bytes(),
                &vec![0; MAX_BUNDLE_PLAINTEXT + 1]
            )
            .is_err()
        );
    }
}
