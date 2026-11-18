use crate::transport::punch::{is_punch_packet, punch_session_id};
use crate::transport::stun::{is_stun, transaction_id};
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker, ready},
    time::Instant,
};
use tokio::{io::Interest, sync::mpsc};

const MAX_REGISTRATIONS: usize = 64;
const MAX_QUEUE_CAPACITY: usize = 256;
const MAX_PACKETS_PER_POLL: usize = 64;

#[derive(Debug, Clone)]
pub struct StunDatagram {
    pub packet: Vec<u8>,
    pub from: SocketAddr,
    pub received_at: Instant,
}

#[derive(Debug, Clone)]
pub struct PunchDatagram {
    pub packet: Vec<u8>,
    pub from: SocketAddr,
    pub received_at: Instant,
}

#[derive(Default)]
struct UdpMuxState {
    stun_waiters: Mutex<HashMap<[u8; 12], mpsc::Sender<StunDatagram>>>,
    punch_sessions: Mutex<HashMap<[u8; 16], mpsc::Sender<PunchDatagram>>>,
    recv_waker: Mutex<Option<Waker>>,
    discarded: AtomicU64,
    closed: AtomicBool,
}

impl fmt::Debug for UdpMuxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpMuxState")
            .field("discarded", &self.discarded.load(Ordering::Relaxed))
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

impl UdpMuxState {
    fn dispatch_stun(&self, pkt: &[u8], from: SocketAddr) {
        let Some(tx_id) = transaction_id(pkt) else {
            self.discarded.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let sender = {
            let guard = self.stun_waiters.lock().expect("stun_waiters lock");
            guard.get(&tx_id).cloned()
        };
        if let Some(tx) = sender {
            let msg = StunDatagram {
                packet: pkt.to_vec(),
                from,
                received_at: Instant::now(),
            };
            if tx.try_send(msg).is_err() {
                self.discarded.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.discarded.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dispatch_punch(&self, pkt: &[u8], from: SocketAddr) {
        let Some(session_id) = punch_session_id(pkt) else {
            self.discarded.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let sender = {
            let guard = self.punch_sessions.lock().expect("punch_sessions lock");
            guard.get(&session_id).cloned()
        };
        if let Some(tx) = sender {
            let msg = PunchDatagram {
                packet: pkt.to_vec(),
                from,
                received_at: Instant::now(),
            };
            if tx.try_send(msg).is_err() {
                self.discarded.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.discarded.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
pub struct MuxUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    state: Arc<UdpMuxState>,
}

struct MuxUdpPoller {
    io: Arc<tokio::net::UdpSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for MuxUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MuxUdpPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for MuxUdpPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.fut.is_none() {
            let io = self.io.clone();
            self.fut = Some(Box::pin(async move { io.writable().await }));
        }
        let res = self.fut.as_mut().expect("fut set").as_mut().poll(cx);
        if res.is_ready() {
            self.fut = None;
        }
        res
    }
}

impl AsyncUdpSocket for MuxUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(MuxUdpPoller {
            io: self.io.clone(),
            fut: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Endpoint::close still needs I/O to flush QUIC close packets and drain
        // connection events. The last Endpoint/handle drop releases the socket.
        self.io.try_io(Interest::WRITABLE, || {
            self.io
                .try_send_to(transmit.contents, transmit.destination)
                .map(|_| ())
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        {
            let mut waker_slot = self.state.recv_waker.lock().expect("recv_waker lock");
            *waker_slot = Some(cx.waker().clone());
        }

        for _ in 0..MAX_PACKETS_PER_POLL {
            ready!(self.io.poll_recv_ready(cx))?;

            if bufs.is_empty() || meta.is_empty() {
                return Poll::Ready(Ok(0));
            }

            let recv_res = self
                .io
                .try_io(Interest::READABLE, || self.io.try_recv_from(&mut bufs[0]));

            match recv_res {
                Ok((len, addr)) => {
                    let pkt = &bufs[0][..len];
                    if is_punch_packet(pkt) {
                        self.state.dispatch_punch(pkt, addr);
                        continue;
                    }
                    if is_stun(pkt) {
                        self.state.dispatch_stun(pkt, addr);
                        continue;
                    }
                    if len > 0 && (pkt[0] & 0xC0) != 0 {
                        meta[0] = RecvMeta {
                            addr,
                            len,
                            stride: len,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    self.state.discarded.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        // A flood of non-QUIC packets must not starve timers and other endpoints.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug)]
pub struct UdpMuxHandle {
    io: Arc<tokio::net::UdpSocket>,
    state: Arc<UdpMuxState>,
    endpoint: Endpoint,
}

impl UdpMuxHandle {
    pub fn bind(bind_addr: SocketAddr, server_config: Option<ServerConfig>) -> io::Result<Self> {
        // Callers must see a failed bind; silently changing the port invalidates
        // advertised candidates and can make a shutdown/rebind test lie.
        let std_sock = std::net::UdpSocket::bind(bind_addr)?;
        std_sock.set_nonblocking(true)?;
        let tokio_sock = Arc::new(tokio::net::UdpSocket::from_std(std_sock)?);
        let state = Arc::new(UdpMuxState::default());
        let mux_socket = Arc::new(MuxUdpSocket {
            io: tokio_sock.clone(),
            state: state.clone(),
        });

        // Demultiplexing reserves packets with both high bits clear for STUN
        // and punches. Do not advertise RFC 9287: a peer could then clear the
        // QUIC fixed bit and its short-header packets would be discarded here.
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.grease_quic_bit(false);
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            server_config,
            mux_socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self {
            io: tokio_sock,
            state,
            endpoint,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn port(&self) -> u16 {
        self.io.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    pub fn discarded_count(&self) -> u64 {
        self.state.discarded.load(Ordering::Relaxed)
    }

    pub fn is_open(&self) -> bool {
        !self.state.closed.load(Ordering::Acquire)
    }

    pub async fn send_non_quic(&self, target: SocketAddr, payload: &[u8]) -> io::Result<usize> {
        if self.state.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP mux uticnica zatvorena",
            ));
        }
        self.io.send_to(payload, target).await
    }

    pub fn register_stun_waiter(
        &self,
        tx_ids: &[[u8; 12]],
        capacity: usize,
    ) -> io::Result<(mpsc::Receiver<StunDatagram>, StunWaiterGuard)> {
        let (tx, rx) = mpsc::channel(capacity.clamp(1, MAX_QUEUE_CAPACITY));
        {
            let mut guard = self.state.stun_waiters.lock().expect("stun_waiters lock");
            if !self.is_open() || guard.len() + tx_ids.len() > MAX_REGISTRATIONS {
                return Err(io::Error::other("STUN registry closed or full"));
            }
            if tx_ids.iter().any(|id| guard.contains_key(id)) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "STUN ID already registered",
                ));
            }
            for id in tx_ids {
                guard.insert(*id, tx.clone());
            }
        }
        Ok((
            rx,
            StunWaiterGuard {
                state: self.state.clone(),
                ids: tx_ids.to_vec(),
            },
        ))
    }

    pub fn register_punch_session(
        &self,
        session_id: [u8; 16],
        capacity: usize,
    ) -> io::Result<(mpsc::Receiver<PunchDatagram>, PunchSessionGuard)> {
        let (tx, rx) = mpsc::channel(capacity.clamp(1, MAX_QUEUE_CAPACITY));
        {
            let mut guard = self
                .state
                .punch_sessions
                .lock()
                .expect("punch_sessions lock");
            if !self.is_open() || guard.len() >= MAX_REGISTRATIONS {
                return Err(io::Error::other("punch registry closed or full"));
            }
            if guard.contains_key(&session_id) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "punch session already registered",
                ));
            }
            guard.insert(session_id, tx);
        }
        Ok((
            rx,
            PunchSessionGuard {
                state: self.state.clone(),
                session_id,
            },
        ))
    }

    pub fn close(&self) {
        if !self.state.closed.swap(true, Ordering::AcqRel) {
            self.endpoint.close(0u32.into(), b"zatvoreno");
            self.state
                .stun_waiters
                .lock()
                .expect("stun_waiters lock")
                .clear();
            self.state
                .punch_sessions
                .lock()
                .expect("punch_sessions lock")
                .clear();
            if let Some(waker) = self
                .state
                .recv_waker
                .lock()
                .expect("recv_waker lock")
                .take()
            {
                waker.wake();
            }
        }
    }
}

pub struct StunWaiterGuard {
    state: Arc<UdpMuxState>,
    ids: Vec<[u8; 12]>,
}

impl Drop for StunWaiterGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.stun_waiters.lock() {
            for id in &self.ids {
                guard.remove(id);
            }
        }
    }
}

pub struct PunchSessionGuard {
    state: Arc<UdpMuxState>,
    session_id: [u8; 16],
}

impl Drop for PunchSessionGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.punch_sessions.lock() {
            guard.remove(&self.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::punch::{KIND_PUNCH, KIND_REPLY, PunchKeys, PunchWindow};
    use crate::transport::stun::{
        build_binding_request, build_binding_response, parse_binding_response,
    };
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use std::time::Duration;

    #[derive(Debug)]
    struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn make_quic_configs() -> (ServerConfig, quinn::ClientConfig) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certified = rcgen::generate_simple_self_signed(vec!["list2cart-sync".to_owned()])
            .expect("self signed cert");
        let cert_der = CertificateDer::from(certified.cert);
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server cert");
        server_crypto.alpn_protocols = vec![b"list2cart-web/1".to_vec()];

        let server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic server"),
        ));

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"list2cart-web/1".to_vec()];

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("quic client"),
        ));

        (server_config, client_config)
    }

    #[tokio::test]
    async fn single_udp_port_demuxes_stun_punch_quic_and_discards_unknown() {
        tokio::time::timeout(Duration::from_secs(10), exercise_shared_socket())
            .await
            .expect("whole UDP/QUIC scenario exceeded deadline");
    }

    async fn exercise_shared_socket() {
        let (server_cfg, client_cfg) = make_quic_configs();
        let bind_loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let node_a = UdpMuxHandle::bind(bind_loopback, Some(server_cfg.clone())).expect("bind A");
        let node_b = UdpMuxHandle::bind(bind_loopback, Some(server_cfg)).expect("bind B");

        let addr_a = node_a.local_addr().expect("addr A");
        let addr_b = node_b.local_addr().expect("addr B");
        assert_ne!(addr_a.port(), addr_b.port());

        // 1. STUN request / response over the shared UDP sockets
        let tx_id = [0x42u8; 12];
        let (mut stun_rx_a, _stun_guard_a) = node_a.register_stun_waiter(&[tx_id], 4).unwrap();
        assert!(node_a.register_stun_waiter(&[tx_id], 4).is_err());
        assert!(
            UdpMuxHandle::bind(addr_a, None).is_err(),
            "an occupied port must not silently fall back"
        );
        let req = build_binding_request(&tx_id);
        node_a
            .send_non_quic(addr_b, &req)
            .await
            .expect("send stun req");

        let mapped_for_a: SocketAddr = format!("203.0.113.7:{}", addr_a.port()).parse().unwrap();
        let stun_resp = build_binding_response(&tx_id, mapped_for_a, true);
        node_b
            .send_non_quic(addr_a, &stun_resp)
            .await
            .expect("send stun resp");

        let received_stun = tokio::time::timeout(Duration::from_secs(2), stun_rx_a.recv())
            .await
            .expect("stun timeout")
            .expect("stun datagram");
        assert_eq!(received_stun.from, addr_b);
        let decoded_addr =
            parse_binding_response(&received_stun.packet, &tx_id).expect("parse stun");
        assert_eq!(decoded_addr, mapped_for_a);

        // 2. 60-byte authenticated punch exchange on the exact same ports
        let sess_hex = "0102030405060708090a0b0c0d0e0f10";
        let pub_a = [0x11u8; 32];
        let pub_b = [0x22u8; 32];
        let call_secret = [0xA5u8; 32];
        let resp_secret = [0x5Au8; 32];

        let keys_a = PunchKeys::derive(
            "list2cart",
            sess_hex,
            &call_secret,
            &resp_secret,
            &pub_a,
            &pub_b,
        )
        .expect("keys A");
        let keys_b = PunchKeys::derive(
            "list2cart",
            sess_hex,
            &call_secret,
            &resp_secret,
            &pub_b,
            &pub_a,
        )
        .expect("keys B");

        let (mut punch_rx_a, _punch_guard_a) =
            node_a.register_punch_session(keys_a.session, 8).unwrap();
        let (mut punch_rx_b, _punch_guard_b) =
            node_b.register_punch_session(keys_b.session, 8).unwrap();
        assert!(node_a.register_punch_session(keys_a.session, 8).is_err());

        let punch_pkt = keys_a.build_packet(KIND_PUNCH, 1);
        node_a
            .send_non_quic(addr_b, &punch_pkt)
            .await
            .expect("send punch");

        let recv_on_b = tokio::time::timeout(Duration::from_secs(2), punch_rx_b.recv())
            .await
            .expect("punch B timeout")
            .expect("punch B msg");
        assert_eq!(recv_on_b.from, addr_a);
        let (kind, counter) = keys_b.verify_packet(&recv_on_b.packet).expect("verify B");
        assert_eq!(kind, KIND_PUNCH);
        assert_eq!(counter, 1);
        let mut win_b = PunchWindow::default();
        assert!(win_b.accept(counter));

        let reply_pkt = keys_b.build_packet(KIND_REPLY, 1);
        node_b
            .send_non_quic(addr_a, &reply_pkt)
            .await
            .expect("send reply");

        let recv_on_a = tokio::time::timeout(Duration::from_secs(2), punch_rx_a.recv())
            .await
            .expect("punch A timeout")
            .expect("punch A msg");
        assert_eq!(recv_on_a.from, addr_b);
        let (r_kind, r_counter) = keys_a.verify_packet(&recv_on_a.packet).expect("verify A");
        assert_eq!(r_kind, KIND_REPLY);
        assert_eq!(r_counter, 1);

        // 3. Unknown non-QUIC datagrams are counted as discarded without breaking QUIC
        node_b
            .send_non_quic(addr_a, &[0x00, 0x99, 0x88, 0x77])
            .await
            .expect("send unknown");

        // 4. Bidirectional QUIC connection and stream over the exact same ports (addr_a <-> addr_b)
        let accept_task = {
            let ep_b = node_b.endpoint().clone();
            tokio::spawn(async move {
                let incoming = ep_b.accept().await.expect("incoming conn");
                let conn = incoming.await.expect("quic server handshake");
                let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
                let data = recv.read_to_end(1024).await.expect("read stream");
                assert_eq!(data, b"ping-list2cart");
                send.write_all(b"pong-list2cart")
                    .await
                    .expect("write stream");
                send.finish().expect("finish stream");
                conn.closed().await;
            })
        };

        let connecting = node_a
            .endpoint()
            .connect_with(client_cfg, addr_b, "list2cart-sync")
            .expect("connect_with");
        let conn_a = tokio::time::timeout(Duration::from_secs(3), connecting)
            .await
            .expect("connect timeout")
            .expect("quic client handshake");
        assert_eq!(conn_a.remote_address(), addr_b);

        let (mut send_a, mut recv_a) = conn_a.open_bi().await.expect("open_bi");
        send_a
            .write_all(b"ping-list2cart")
            .await
            .expect("write ping");
        send_a.finish().expect("finish ping");
        let reply = recv_a.read_to_end(1024).await.expect("read pong");
        assert_eq!(reply, b"pong-list2cart");

        assert!(node_a.discarded_count() >= 1);

        conn_a.close(0u32.into(), b"done");
        tokio::time::timeout(Duration::from_secs(2), accept_task)
            .await
            .expect("server task did not stop")
            .expect("server task failed");

        // 5. Clean shutdown and re-opening on the same port
        let port_a = node_a.port();
        node_a.close();
        node_b.close();
        assert!(!node_a.is_open());
        assert!(node_a.register_stun_waiter(&[[9; 12]], 1).is_err());
        drop(send_a);
        drop(recv_a);
        drop(conn_a);
        tokio::time::timeout(Duration::from_secs(2), node_a.endpoint().wait_idle())
            .await
            .expect("A endpoint did not drain");
        tokio::time::timeout(Duration::from_secs(2), node_b.endpoint().wait_idle())
            .await
            .expect("B endpoint did not drain");
        drop(node_a);
        drop(node_b);
        // EndpointDriver owns the final socket reference until its next poll.
        tokio::task::yield_now().await;

        let reopened =
            UdpMuxHandle::bind(SocketAddr::new("127.0.0.1".parse().unwrap(), port_a), None)
                .expect("rebind after close");
        assert_eq!(
            reopened.port(),
            port_a,
            "must rebind the exact original port"
        );
        assert!(reopened.is_open());
        reopened.close();
    }
}
