use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Default UDP discovery port.
pub const DEFAULT_DISCOVERY_PORT: u16 = 45_821;

/// Suffix appended to the protocol name in UDP discovery probe payloads.
pub const PROBE_SUFFIX: &str = "-discover-v1";

/// Grace period after writing the pairing flag before TCP liveness is enforced.
const PAIRING_FLAG_GRACE: Duration = Duration::from_secs(3);

/// Filename for the transient pairing port flag inside the data directory.
const PAIRING_FLAG_FILE: &str = "pairing-port";

/// Maximum total discovery replies per second for the announcer.
const MAX_REPLIES_PER_SEC_TOTAL: u32 = 20;

/// Maximum discovery replies per second per source IP address.
const MAX_REPLIES_PER_SEC_PER_IP: u32 = 2;

/// Returns the expected UDP probe payload string for a given protocol identifier.
#[must_use]
pub fn probe_text(protocol: &str) -> String {
    format!("{protocol}{PROBE_SUFFIX}")
}

/// JSON beacon broadcast/replied over UDP LAN discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Beacon {
    pub protocol: String,
    pub device_id: String,
    pub name: String,
    pub exchange_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_port: Option<u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

/// Discovered peer returned by LAN discovery, pairing the UDP source IP with the beacon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundPeer {
    #[serde(flatten)]
    pub beacon: Beacon,
    pub addr: IpAddr,
}

impl FoundPeer {
    /// Returns the `SocketAddr` for the peer's exchange listener using the verified UDP source IP.
    #[must_use]
    pub fn exchange_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.beacon.exchange_port)
    }

    /// Returns the `SocketAddr` for the peer's pairing listener, if advertised.
    #[must_use]
    pub fn pair_addr(&self) -> Option<SocketAddr> {
        self.beacon
            .pair_port
            .filter(|&port| port > 0)
            .map(|port| SocketAddr::new(self.addr, port))
    }
}

/// Returns true if an IP address is on a local, private, link-local, or loopback network.
#[must_use]
pub fn is_local_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_local_lan_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_local_lan_ipv4(mapped);
            }
            is_local_lan_ipv6(v6)
        }
    }
}

fn is_local_lan_ipv4(v4: Ipv4Addr) -> bool {
    v4.is_loopback() || v4.is_private() || v4.is_link_local()
}

fn is_local_lan_ipv6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
}

#[derive(Debug)]
struct PerIpWindow {
    window_start: Instant,
    count: u32,
}

/// Rate limiter for UDP discovery responses preventing amplification or flood abuse.
#[derive(Debug)]
pub struct AnnouncerRateLimiter {
    total_window_start: Instant,
    total_count: u32,
    per_ip: HashMap<IpAddr, PerIpWindow>,
    max_total_per_sec: u32,
    max_per_ip_per_sec: u32,
}

impl Default for AnnouncerRateLimiter {
    fn default() -> Self {
        Self::new(MAX_REPLIES_PER_SEC_TOTAL, MAX_REPLIES_PER_SEC_PER_IP)
    }
}

impl AnnouncerRateLimiter {
    /// Creates a new rate limiter with explicit total and per-IP per-second caps.
    #[must_use]
    pub fn new(max_total_per_sec: u32, max_per_ip_per_sec: u32) -> Self {
        Self {
            total_window_start: Instant::now(),
            total_count: 0,
            per_ip: HashMap::new(),
            max_total_per_sec,
            max_per_ip_per_sec,
        }
    }

    /// Checks whether a probe from `src_ip` is allowed to receive a reply right now.
    pub fn allow(&mut self, src_ip: IpAddr, now: Instant) -> bool {
        if !is_local_lan_ip(src_ip) {
            return false;
        }

        if now.duration_since(self.total_window_start) >= Duration::from_secs(1) {
            self.total_window_start = now;
            self.total_count = 0;
            // Prune stale per-IP entries periodically when the global window resets.
            self.per_ip
                .retain(|_, w| now.duration_since(w.window_start) < Duration::from_secs(5));
        }

        if self.total_count >= self.max_total_per_sec {
            return false;
        }

        let entry = self.per_ip.entry(src_ip).or_insert(PerIpWindow {
            window_start: now,
            count: 0,
        });
        if now.duration_since(entry.window_start) >= Duration::from_secs(1) {
            entry.window_start = now;
            entry.count = 0;
        }
        if entry.count >= self.max_per_ip_per_sec {
            return false;
        }

        self.total_count += 1;
        entry.count += 1;
        true
    }
}

/// Runs the LAN discovery announcer on an already bound UDP socket until `cancel` is triggered.
pub async fn announce_on(
    socket: Arc<UdpSocket>,
    cancel: CancellationToken,
    protocol: String,
    info: Arc<dyn Fn() -> Beacon + Send + Sync>,
) -> io::Result<()> {
    let expected_probe = probe_text(&protocol);
    let rate_limiter = Arc::new(Mutex::new(AnnouncerRateLimiter::default()));
    let mut buf = [0u8; 512];

    loop {
        let recv = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = socket.recv_from(&mut buf) => res,
        };

        let (len, peer_addr) = match recv {
            Ok(v) => v,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };

        let Ok(text) = std::str::from_utf8(&buf[..len]) else {
            continue;
        };
        if text.trim() != expected_probe {
            continue;
        }

        {
            let mut limiter = rate_limiter.lock().await;
            if !limiter.allow(peer_addr.ip(), Instant::now()) {
                continue;
            }
        }

        let mut beacon = info();
        if beacon.protocol.is_empty() {
            beacon.protocol = protocol.clone();
        }
        let Ok(payload) = serde_json::to_vec(&beacon) else {
            continue;
        };
        let _ = socket.send_to(&payload, peer_addr).await;
    }
}

/// Binds a UDP socket to `bind_addr` (never silently falling back to another port) and runs
/// `announce_on` until `cancel` is triggered.
pub async fn announce_on_port(
    bind_addr: SocketAddr,
    cancel: CancellationToken,
    protocol: String,
    info: Arc<dyn Fn() -> Beacon + Send + Sync>,
) -> io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let _ = socket.set_broadcast(true);
    announce_on(socket, cancel, protocol, info).await
}

/// Sends discovery probes on `socket` to `targets` at 0ms, 150ms, and 400ms, collecting unique
/// valid `Beacon` responses up to `timeout_dur`. Stops early if all `wanted_device_ids` respond.
pub async fn discover_on(
    socket: &UdpSocket,
    targets: &[SocketAddr],
    protocol: &str,
    timeout_dur: Duration,
    wanted_device_ids: &[String],
) -> io::Result<Vec<FoundPeer>> {
    let _ = socket.set_broadcast(true);
    let probe = probe_text(protocol).into_bytes();
    let wanted: HashSet<&str> = wanted_device_ids
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();

    let start = Instant::now();
    let deadline = start + timeout_dur;
    let probe_offsets = [
        Duration::from_millis(0),
        Duration::from_millis(150),
        Duration::from_millis(400),
    ];
    let mut next_probe_idx = 0usize;

    let mut found: Vec<FoundPeer> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut buf = [0u8; 4096];

    loop {
        let now = Instant::now();
        while next_probe_idx < probe_offsets.len()
            && now.duration_since(start) >= probe_offsets[next_probe_idx]
        {
            for &target in targets {
                let _ = socket.send_to(&probe, target).await;
            }
            next_probe_idx += 1;
        }

        if !wanted.is_empty() && wanted.iter().all(|id| seen_ids.contains(*id)) {
            break;
        }

        let now = Instant::now();
        if now >= deadline {
            break;
        }

        let mut wait_until = deadline;
        if next_probe_idx < probe_offsets.len() {
            let next_probe_at = start + probe_offsets[next_probe_idx];
            if next_probe_at < wait_until {
                wait_until = next_probe_at;
            }
        }

        let wait_dur = wait_until.saturating_duration_since(now);
        let recv = tokio::time::timeout(wait_dur, socket.recv_from(&mut buf)).await;
        match recv {
            Err(_) => {
                // Timeout reached either for the next probe or final deadline.
                continue;
            }
            Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(err)) => return Err(err),
            Ok(Ok((len, src_addr))) => {
                let Ok(beacon) = serde_json::from_slice::<Beacon>(&buf[..len]) else {
                    continue;
                };
                if beacon.protocol != protocol || beacon.device_id.trim().is_empty() {
                    continue;
                }
                if seen_ids.insert(beacon.device_id.clone()) {
                    found.push(FoundPeer {
                        beacon,
                        addr: src_addr.ip(),
                    });
                }
            }
        }
    }

    Ok(found)
}

/// Discovers peers on the local subnet via UDP broadcast (255.255.255.255) on `discovery_port`.
pub async fn discover_lan(
    discovery_port: u16,
    protocol: &str,
    timeout_dur: Duration,
    wanted_device_ids: &[String],
) -> io::Result<Vec<FoundPeer>> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    let targets = [SocketAddr::from((Ipv4Addr::BROADCAST, discovery_port))];
    discover_on(&socket, &targets, protocol, timeout_dur, wanted_device_ids).await
}

/// Discovers a single peer by `device_id` on the local LAN.
pub async fn find_device(
    discovery_port: u16,
    protocol: &str,
    device_id: &str,
    timeout_dur: Duration,
) -> io::Result<Option<FoundPeer>> {
    let wanted = vec![device_id.to_string()];
    let peers = discover_lan(discovery_port, protocol, timeout_dur, &wanted).await?;
    Ok(peers
        .into_iter()
        .find(|peer| peer.beacon.device_id == device_id))
}

fn pairing_flag_path(dir: &Path) -> PathBuf {
    dir.join(PAIRING_FLAG_FILE)
}

/// Writes the active pairing port flag file so a standing LAN announcer can advertise `pairPort`.
pub fn write_pairing_flag(dir: &Path, port: u16) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(pairing_flag_path(dir), port.to_string())
}

/// Removes the active pairing port flag file.
pub fn clear_pairing_flag(dir: &Path) {
    let _ = std::fs::remove_file(pairing_flag_path(dir));
}

/// Reads the pairing port flag if present and still alive (within grace period or accepting TCP).
/// Automatically removes stale flag files whose listener is no longer reachable.
pub fn read_pairing_flag(dir: &Path) -> Option<u16> {
    let path = pairing_flag_path(dir);
    let content = std::fs::read_to_string(&path).ok()?;
    let port: u16 = content.trim().parse().ok()?;
    if port == 0 {
        clear_pairing_flag(dir);
        return None;
    }

    if let Ok(meta) = std::fs::metadata(&path)
        && let Ok(modified) = meta.modified()
        && let Ok(age) = SystemTime::now().duration_since(modified)
        && age < PAIRING_FLAG_GRACE
    {
        return Some(port);
    }

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    if TcpStream::connect_timeout(&addr, Duration::from_millis(120)).is_ok() {
        Some(port)
    } else {
        clear_pairing_flag(dir);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn discovery_filters_protocol_and_returns_valid_beacons() {
        let sock_good = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let good_addr = sock_good.local_addr().unwrap();

        let sock_other = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let other_addr = sock_other.local_addr().unwrap();

        let cancel = CancellationToken::new();
        let cancel_good = cancel.clone();
        let h_good = tokio::spawn(announce_on(
            sock_good,
            cancel_good,
            "list2cart".to_string(),
            Arc::new(|| Beacon {
                protocol: "list2cart".to_string(),
                device_id: "dev-good".to_string(),
                name: "Mobitel".to_string(),
                exchange_port: 4411,
                pair_port: Some(4412),
                meta: BTreeMap::new(),
            }),
        ));

        let cancel_other = cancel.clone();
        let h_other = tokio::spawn(announce_on(
            sock_other,
            cancel_other,
            "otherapp".to_string(),
            Arc::new(|| Beacon {
                protocol: "otherapp".to_string(),
                device_id: "dev-other".to_string(),
                name: "Other".to_string(),
                exchange_port: 5511,
                pair_port: None,
                meta: BTreeMap::new(),
            }),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let found = discover_on(
            &client,
            &[good_addr, other_addr],
            "list2cart",
            Duration::from_millis(600),
            &["dev-good".to_string()],
        )
        .await
        .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].beacon.device_id, "dev-good");
        assert_eq!(found[0].addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(found[0].beacon.pair_port, Some(4412));

        cancel.cancel();
        h_good.await.unwrap().unwrap();
        h_other.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn announce_on_port_fails_when_port_is_occupied() {
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let cancel = CancellationToken::new();

        let res = announce_on_port(
            addr,
            cancel,
            "list2cart".to_string(),
            Arc::new(|| Beacon {
                protocol: "list2cart".to_string(),
                device_id: "dev-1".to_string(),
                name: "Node".to_string(),
                exchange_port: 4000,
                pair_port: None,
                meta: BTreeMap::new(),
            }),
        )
        .await;

        assert!(res.is_err());
    }

    #[test]
    fn rate_limiter_blocks_external_and_excess_per_ip() {
        let mut limiter = AnnouncerRateLimiter::new(20, 2);
        let now = Instant::now();

        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!limiter.allow(public_ip, now));

        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        assert!(limiter.allow(lan_ip, now));
        assert!(limiter.allow(lan_ip, now));
        assert!(!limiter.allow(lan_ip, now));

        let later = now + Duration::from_secs(1) + Duration::from_millis(5);
        assert!(limiter.allow(lan_ip, later));
    }

    #[tokio::test]
    async fn pairing_flag_returns_live_port_and_cleans_up_dead_port() {
        let dir = std::env::temp_dir().join(format!("l2c-pair-flag-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        write_pairing_flag(&dir, port).unwrap();
        assert_eq!(read_pairing_flag(&dir), Some(port));

        clear_pairing_flag(&dir);
        assert_eq!(read_pairing_flag(&dir), None);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
