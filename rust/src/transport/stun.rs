use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_SUCCESS: u16 = 0x0101;
pub const STUN_HEADER_LEN: usize = 20;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    NotStunResponse,
    NoValidAddress,
}

impl fmt::Display for StunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStunResponse => write!(f, "paket nije STUN Binding odgovor"),
            Self::NoValidAddress => write!(f, "STUN odgovor nema valjanu adresu"),
        }
    }
}

impl std::error::Error for StunError {}

pub fn build_binding_request(tx_id: &[u8; 12]) -> [u8; STUN_HEADER_LEN] {
    let mut b = [0u8; STUN_HEADER_LEN];
    b[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    b[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    b[8..20].copy_from_slice(tx_id);
    b
}

pub fn build_binding_response(tx_id: &[u8; 12], addr: SocketAddr, use_xor: bool) -> Vec<u8> {
    let mut attr_val = Vec::with_capacity(20);
    attr_val.push(0);
    let port = addr.port();
    match addr.ip() {
        IpAddr::V4(v4) => {
            attr_val.push(FAMILY_IPV4);
            let encoded_port = if use_xor {
                port ^ (STUN_MAGIC_COOKIE >> 16) as u16
            } else {
                port
            };
            attr_val.extend_from_slice(&encoded_port.to_be_bytes());
            let mut octets = v4.octets();
            if use_xor {
                let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    octets[i] ^= cookie_bytes[i];
                }
            }
            attr_val.extend_from_slice(&octets);
        }
        IpAddr::V6(v6) => {
            attr_val.push(FAMILY_IPV6);
            let encoded_port = if use_xor {
                port ^ (STUN_MAGIC_COOKIE >> 16) as u16
            } else {
                port
            };
            attr_val.extend_from_slice(&encoded_port.to_be_bytes());
            let mut octets = v6.octets();
            if use_xor {
                let mut mask = [0u8; 16];
                mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                mask[4..16].copy_from_slice(tx_id);
                for i in 0..16 {
                    octets[i] ^= mask[i];
                }
            }
            attr_val.extend_from_slice(&octets);
        }
    }

    let attr_type = if use_xor {
        ATTR_XOR_MAPPED_ADDRESS
    } else {
        ATTR_MAPPED_ADDRESS
    };
    let mut out = Vec::with_capacity(STUN_HEADER_LEN + 4 + attr_val.len());
    let payload_len = (4 + attr_val.len()) as u16;
    out.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(tx_id);
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(attr_val.len() as u16).to_be_bytes());
    out.extend_from_slice(&attr_val);
    out
}

pub fn is_stun(packet: &[u8]) -> bool {
    if packet.len() < STUN_HEADER_LEN
        || (packet[0] & 0xC0) != 0
        || u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != STUN_MAGIC_COOKIE
    {
        return false;
    }
    let attr_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    attr_len.is_multiple_of(4) && STUN_HEADER_LEN + attr_len == packet.len()
}

pub fn transaction_id(packet: &[u8]) -> Option<[u8; 12]> {
    if !is_stun(packet) {
        return None;
    }
    let mut id = [0u8; 12];
    id.copy_from_slice(&packet[8..20]);
    Some(id)
}

pub fn parse_binding_response(
    packet: &[u8],
    expected_tx: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    if !is_stun(packet) {
        return Err(StunError::NotStunResponse);
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    if msg_type != STUN_BINDING_SUCCESS || &packet[8..20] != expected_tx {
        return Err(StunError::NotStunResponse);
    }

    let mut rest = &packet[STUN_HEADER_LEN..];
    let mut xor_addr: Option<SocketAddr> = None;
    let mut mapped_addr: Option<SocketAddr> = None;

    while let Some((attr_type, val, next)) = next_attribute(rest) {
        rest = next;
        let is_xor = attr_type == ATTR_XOR_MAPPED_ADDRESS;
        if attr_type != ATTR_XOR_MAPPED_ADDRESS && attr_type != ATTR_MAPPED_ADDRESS {
            continue;
        }
        if let Some(addr) = decode_address_attr(val, is_xor, expected_tx) {
            if is_xor {
                if xor_addr.is_none() {
                    xor_addr = Some(addr);
                }
            } else {
                mapped_addr = Some(addr);
            }
        }
    }

    xor_addr.or(mapped_addr).ok_or(StunError::NoValidAddress)
}

fn next_attribute(attrs: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    if attrs.len() < 4 {
        return None;
    }
    let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
    let len = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
    if 4 + len > attrs.len() {
        return None;
    }
    let padded = 4 + len.div_ceil(4) * 4;
    let next = if padded >= attrs.len() {
        &[]
    } else {
        &attrs[padded..]
    };
    Some((attr_type, &attrs[4..4 + len], next))
}

fn decode_address_attr(val: &[u8], is_xor: bool, tx_id: &[u8; 12]) -> Option<SocketAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let ip_len = match family {
        FAMILY_IPV4 => 4usize,
        FAMILY_IPV6 => 16usize,
        _ => return None,
    };
    if val.len() != 4 + ip_len {
        return None;
    }

    let mut port = u16::from_be_bytes([val[2], val[3]]);
    let mut ip_bytes = [0u8; 16];
    ip_bytes[..ip_len].copy_from_slice(&val[4..4 + ip_len]);

    if is_xor {
        port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
        let mut mask = [0u8; 16];
        mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        mask[4..16].copy_from_slice(tx_id);
        for i in 0..ip_len {
            ip_bytes[i] ^= mask[i];
        }
    }

    let ip = match family {
        FAMILY_IPV4 => IpAddr::V4(Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        )),
        FAMILY_IPV6 => {
            let v6 = Ipv6Addr::from(ip_bytes);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };

    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_rfc5769_ipv4_xor_mapped_vector() {
        // RFC 5769 section 2.2 test vector (Binding Success Response for 192.0.2.1:32853)
        let tx_id: [u8; 12] = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let resp = build_binding_response(&tx_id, "192.0.2.1:32853".parse().unwrap(), true);
        assert!(is_stun(&resp));
        assert_eq!(transaction_id(&resp), Some(tx_id));
        let parsed = parse_binding_response(&resp, &tx_id).expect("valid stun response");
        assert_eq!(parsed, "192.0.2.1:32853".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rejects_mismatched_tx_id_and_malformed_stun() {
        let tx_id = [1u8; 12];
        let mut resp = build_binding_response(&tx_id, "203.0.113.10:45000".parse().unwrap(), true);
        assert!(parse_binding_response(&resp, &[2u8; 12]).is_err());
        resp[0] |= 0x40; // top two bits != 00
        assert!(!is_stun(&resp));
    }
}
