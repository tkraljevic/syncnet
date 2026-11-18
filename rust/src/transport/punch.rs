use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

pub const PUNCH_PACKET_LEN: usize = 60;
pub const PUNCH_AUTH_OFFSET: usize = 28;
pub const KIND_PUNCH: u8 = 0x10;
pub const KIND_REPLY: u8 = 0x11;
pub const PUNCH_VERSION: u8 = 1;
pub const DIR_AB: u8 = 0;
pub const DIR_BA: u8 = 1;
pub const MIN_SECRET_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchError {
    InvalidDerivationInputs,
    WrongShapeOrSession,
    OwnDirectionReflected,
    InvalidMac,
}

impl fmt::Display for PunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDerivationInputs => write!(f, "kljucevi udarca se ne daju izvesti"),
            Self::WrongShapeOrSession => write!(f, "paket nije udarac ove sesije"),
            Self::OwnDirectionReflected => write!(f, "udarac vlastitog smjera"),
            Self::InvalidMac => write!(f, "potpis udarca ne vrijedi"),
        }
    }
}

impl std::error::Error for PunchError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchKeys {
    pub session: [u8; 16],
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub dir: u8,
}

impl PunchKeys {
    pub fn derive(
        protocol: &str,
        session_hex: &str,
        call_secret: &[u8],
        response_secret: &[u8],
        my_pub: &[u8; 32],
        peer_pub: &[u8; 32],
    ) -> Result<Self, PunchError> {
        let session_bytes =
            hex::decode(session_hex).map_err(|_| PunchError::InvalidDerivationInputs)?;
        if session_bytes.len() != 16
            || call_secret.len().min(response_secret.len()) < MIN_SECRET_LEN
            || my_pub == peer_pub
        {
            return Err(PunchError::InvalidDerivationInputs);
        }
        let mut session = [0u8; 16];
        session.copy_from_slice(&session_bytes);

        let dir = if my_pub < peer_pub { DIR_AB } else { DIR_BA };
        let mut ikm = Vec::with_capacity(call_secret.len() + response_secret.len());
        ikm.extend_from_slice(call_secret);
        ikm.extend_from_slice(response_secret);

        let send_key = derive_dir_key(protocol, &session, &ikm, dir);
        let recv_key = derive_dir_key(protocol, &session, &ikm, dir ^ 1);

        Ok(Self {
            session,
            send_key,
            recv_key,
            dir,
        })
    }

    pub fn is_a(&self) -> bool {
        self.dir == DIR_AB
    }

    pub fn build_packet(&self, kind: u8, counter: u64) -> [u8; PUNCH_PACKET_LEN] {
        let mut out = [0u8; PUNCH_PACKET_LEN];
        out[0] = kind;
        out[1] = self.dir;
        out[2] = PUNCH_VERSION;
        out[3] = 0;
        out[4..20].copy_from_slice(&self.session);
        out[20..28].copy_from_slice(&counter.to_be_bytes());

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.send_key)
            .expect("HMAC-SHA256 accepts 32-byte key");
        mac.update(&out[..PUNCH_AUTH_OFFSET]);
        let tag = mac.finalize().into_bytes();
        out[PUNCH_AUTH_OFFSET..PUNCH_PACKET_LEN].copy_from_slice(&tag);
        out
    }

    pub fn verify_packet(&self, packet: &[u8]) -> Result<(u8, u64), PunchError> {
        if !is_punch_packet(packet) || packet[2] != PUNCH_VERSION || packet[4..20] != self.session {
            return Err(PunchError::WrongShapeOrSession);
        }
        if packet[1] == self.dir {
            return Err(PunchError::OwnDirectionReflected);
        }
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.recv_key)
            .expect("HMAC-SHA256 accepts 32-byte key");
        mac.update(&packet[..PUNCH_AUTH_OFFSET]);
        mac.verify_slice(&packet[PUNCH_AUTH_OFFSET..])
            .map_err(|_| PunchError::InvalidMac)?;

        let counter = u64::from_be_bytes([
            packet[20], packet[21], packet[22], packet[23], packet[24], packet[25], packet[26],
            packet[27],
        ]);
        Ok((packet[0], counter))
    }
}

fn derive_dir_key(protocol: &str, session: &[u8; 16], ikm: &[u8], dir: u8) -> [u8; 32] {
    let mut info = Vec::with_capacity(protocol.len() + 10 + 16 + 1);
    info.extend_from_slice(protocol.as_bytes());
    info.extend_from_slice(b"-udarac-v1");
    info.extend_from_slice(session);
    info.push(dir);

    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("32 bytes is valid HKDF-SHA256 length");
    out
}

pub fn is_punch_packet(packet: &[u8]) -> bool {
    packet.len() == PUNCH_PACKET_LEN && (packet[0] == KIND_PUNCH || packet[0] == KIND_REPLY)
}

pub fn punch_session_id(packet: &[u8]) -> Option<[u8; 16]> {
    if !is_punch_packet(packet) {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&packet[4..20]);
    Some(id)
}

#[derive(Debug, Default, Clone)]
pub struct PunchWindow {
    highest: u64,
    seen: u64,
}

impl PunchWindow {
    pub fn accept(&mut self, n: u64) -> bool {
        if n == 0 {
            return false;
        }
        if n > self.highest {
            let diff = n - self.highest;
            if diff >= 64 {
                self.seen = 1;
            } else {
                self.seen = (self.seen << diff) | 1;
            }
            self.highest = n;
            return true;
        }
        let diff = self.highest - n;
        if diff >= 64 {
            return false;
        }
        let bit = 1u64 << diff;
        if (self.seen & bit) != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_keys_roundtrip_and_direction_rejection() {
        let pub_a = [0x01u8; 32];
        let pub_b = [0x02u8; 32];
        let sess = "00112233445566778899aabbccddeeff";
        let call_sec = [0xAAu8; 32];
        let resp_sec = [0xBBu8; 32];

        let ka = PunchKeys::derive("list2cart", sess, &call_sec, &resp_sec, &pub_a, &pub_b)
            .expect("keys a");
        let kb = PunchKeys::derive("list2cart", sess, &call_sec, &resp_sec, &pub_b, &pub_a)
            .expect("keys b");

        assert!(ka.is_a());
        assert!(!kb.is_a());
        assert_eq!(ka.send_key, kb.recv_key);
        assert_eq!(kb.send_key, ka.recv_key);

        let pkt = ka.build_packet(KIND_PUNCH, 1);
        assert!(is_punch_packet(&pkt));
        assert_eq!(
            ka.verify_packet(&pkt),
            Err(PunchError::OwnDirectionReflected)
        );
        assert_eq!(kb.verify_packet(&pkt), Ok((KIND_PUNCH, 1)));

        let mut tampered = pkt;
        tampered[59] ^= 0xFF;
        assert_eq!(kb.verify_packet(&tampered), Err(PunchError::InvalidMac));
    }

    #[test]
    fn punch_window_rejects_zero_replay_and_old_and_handles_large_jumps() {
        let mut w = PunchWindow::default();
        assert!(!w.accept(0));
        assert!(w.accept(1));
        assert!(!w.accept(1));
        assert!(w.accept(64));
        assert!(w.accept(2));
        assert!(!w.accept(2));
        assert!(w.accept(130)); // jump >= 64 without overflow panic
        assert!(!w.accept(64)); // now 130 - 64 = 66 >= 64
        assert!(w.accept(67)); // 130 - 67 = 63 < 64
    }
}
