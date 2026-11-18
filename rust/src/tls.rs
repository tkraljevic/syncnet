use crate::identity::{
    IdentityError, VerifiedPeerCert, build_self_signed_cert_der, cert_cn_for_protocol,
    public_key_to_base64, verify_peer_cert_der,
};
use ed25519_dalek::SigningKey;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError, ServerConfig,
    SignatureScheme,
    client::{
        ResolvesClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, ring::default_provider, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::{
        ClientHello, ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
    version::TLS13,
};
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};

pub const ALPN_PAIR: &[u8] = b"list2cart-pair/1";
pub const ALPN_LAN: &[u8] = b"list2cart-lan/1";
pub const ALPN_WEB: &[u8] = b"list2cart-web/1";
pub const ALPN_SIG: &[u8] = b"list2cart-sig/1";
pub const ALPN_TUN: &[u8] = b"list2cart-tun/1";

pub type CredentialsProvider = Arc<dyn Fn() -> Option<Vec<u8>> + Send + Sync>;
pub type KeyTrustChecker = Arc<dyn Fn(&[u8; 32], Option<&[u8]>) -> bool + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateRejectionReason {
    Handshake,
    NotANode,
    WrongProtocol,
    UntrustedMember,
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsAuthError {
    NotAPeer(String),
    WrongProtocol {
        peer: String,
        expected: String,
    },
    DifferentPeerKey {
        addr: String,
        expected_b64: String,
        actual_b64: String,
    },
    UntrustedPeer {
        public_key: [u8; 32],
    },
    Identity(IdentityError),
    Tls(String),
    Io(String),
}

impl TlsAuthError {
    pub fn gate_reason(&self) -> GateRejectionReason {
        match self {
            Self::NotAPeer(_) | Self::Io(_) => GateRejectionReason::Handshake,
            Self::WrongProtocol { .. } => GateRejectionReason::WrongProtocol,
            Self::UntrustedPeer { .. } => GateRejectionReason::UntrustedMember,
            Self::Identity(_) | Self::DifferentPeerKey { .. } | Self::Tls(_) => {
                GateRejectionReason::NotANode
            }
        }
    }
}

impl fmt::Display for TlsAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAPeer(m) => write!(f, "veza nije dovrsila TLS 1.3 rukovanje: {m}"),
            Self::WrongProtocol { peer, expected } => write!(
                f,
                "Razmjena odbijena: drugo racunalo radi pod imenom protokola \"{peer}\", a ovo pod \"{expected}\"."
            ),
            Self::DifferentPeerKey {
                addr,
                expected_b64,
                actual_b64,
            } => {
                let exp_short: String = expected_b64.chars().take(8).collect();
                let act_short: String = actual_b64.chars().take(8).collect();
                write!(
                    f,
                    "cvor na {addr} dokazao je drugi kljuc od uparenog — razmjena odbijena (pokazao {act_short}…, ocekivano {exp_short}…)"
                )
            }
            Self::UntrustedPeer { public_key } => {
                let b64 = public_key_to_base64(public_key);
                let short: String = b64.chars().take(8).collect();
                write!(f, "cvor ({short}…) nije aktivni clan mreze ili je opozvan")
            }
            Self::Identity(e) => write!(f, "{e}"),
            Self::Tls(m) => write!(f, "TLS greska: {m}"),
            Self::Io(m) => write!(f, "I/O greska: {m}"),
        }
    }
}

impl std::error::Error for TlsAuthError {}

impl From<IdentityError> for TlsAuthError {
    fn from(value: IdentityError) -> Self {
        match value {
            IdentityError::WrongProtocol { peer, expected } => {
                Self::WrongProtocol { peer, expected }
            }
            other => Self::Identity(other),
        }
    }
}

struct CachedCert {
    credentials: Option<Vec<u8>>,
    certified: Arc<CertifiedKey>,
}

/// Dynamically resolves our Ed25519 self-signed X.509 certificate, caching the
/// generated certificate until the node's credentials (`urn:list2cart:vjerodajnice:...`) change.
pub struct DynamicCertResolver {
    signing_key: SigningKey,
    protocol: String,
    provider: Arc<CryptoProvider>,
    credentials_fn: Option<CredentialsProvider>,
    cache: Mutex<Option<CachedCert>>,
}

impl fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl DynamicCertResolver {
    pub fn new(
        signing_key: SigningKey,
        protocol: impl Into<String>,
        credentials_fn: Option<CredentialsProvider>,
    ) -> Result<Arc<Self>, TlsAuthError> {
        let provider = Arc::new(default_provider());
        let resolver = Arc::new(Self {
            signing_key,
            protocol: protocol.into(),
            provider,
            credentials_fn,
            cache: Mutex::new(None),
        });
        let _ = resolver.current_certified_key()?;
        Ok(resolver)
    }

    pub fn current_certified_key(&self) -> Result<Arc<CertifiedKey>, TlsAuthError> {
        let creds = self.credentials_fn.as_ref().and_then(|f| f());
        let mut guard = self.cache.lock().expect("cert cache lock");
        if let Some(cached) = guard.as_ref()
            && cached.credentials == creds
        {
            return Ok(cached.certified.clone());
        }
        let cert_der =
            build_self_signed_cert_der(&self.signing_key, &self.protocol, creds.as_deref())?;
        let pkcs8_der = ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_der(&self.signing_key)
            .map_err(|e| TlsAuthError::Identity(IdentityError::KeyParse(e.to_string())))?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes().to_vec()));
        let signing_key = self
            .provider
            .key_provider
            .load_private_key(key_der)
            .map_err(|e| TlsAuthError::Tls(e.to_string()))?;
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert_der)],
            signing_key,
        ));
        *guard = Some(CachedCert {
            credentials: creds,
            certified: certified.clone(),
        });
        Ok(certified)
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current_certified_key().ok()
    }
}

impl ResolvesClientCert for DynamicCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.current_certified_key().ok()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct NoClientCertResolver;

impl ResolvesClientCert for NoClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

#[derive(Default)]
pub struct PeerVerifyState {
    outcome: Mutex<Option<Result<VerifiedPeerCert, TlsAuthError>>>,
    tls13_sig_verified: AtomicBool,
}

impl fmt::Debug for PeerVerifyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerVerifyState")
            .field(
                "tls13_sig_verified",
                &self.tls13_sig_verified.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl PeerVerifyState {
    fn record_cert(&self, res: Result<VerifiedPeerCert, TlsAuthError>) {
        let mut guard = self.outcome.lock().expect("verify outcome lock");
        *guard = Some(res);
    }

    fn peek_verified_cert(&self) -> Option<VerifiedPeerCert> {
        let guard = self.outcome.lock().expect("verify outcome lock");
        match guard.as_ref() {
            Some(Ok(v)) => Some(v.clone()),
            _ => None,
        }
    }

    fn mark_tls13_signature_verified(&self) {
        self.tls13_sig_verified.store(true, Ordering::Release);
    }

    fn take_verified(
        &self,
        handshake_err: Option<String>,
    ) -> Result<VerifiedPeerCert, TlsAuthError> {
        let recorded = self.outcome.lock().expect("verify outcome lock").take();
        if let Some(Err(auth_err)) = recorded {
            return Err(auth_err);
        }
        if let Some(err_msg) = handshake_err {
            return Err(TlsAuthError::NotAPeer(err_msg));
        }
        if !self.tls13_sig_verified.load(Ordering::Acquire) {
            return Err(TlsAuthError::NotAPeer(
                "partner nije dokazao posjedovanje kljuca TLS 1.3 potpisom".to_owned(),
            ));
        }
        match recorded {
            Some(Ok(verified)) => Ok(verified),
            Some(Err(e)) => Err(e),
            None => Err(TlsAuthError::NotAPeer(
                "partner nije poslao certifikat".to_owned(),
            )),
        }
    }
}

struct Ed25519PeerVerifier {
    provider: Arc<CryptoProvider>,
    protocol: String,
    expected_peer_key: Option<([u8; 32], String)>,
    trusted_fn: Option<KeyTrustChecker>,
    state: Arc<PeerVerifyState>,
    empty_subjects: Vec<DistinguishedName>,
}

impl fmt::Debug for Ed25519PeerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PeerVerifier")
            .field("protocol", &self.protocol)
            .field("expected_peer_key", &self.expected_peer_key)
            .finish_non_exhaustive()
    }
}

impl Ed25519PeerVerifier {
    fn new(
        protocol: impl Into<String>,
        expected_peer_key: Option<([u8; 32], String)>,
        trusted_fn: Option<KeyTrustChecker>,
        state: Arc<PeerVerifyState>,
    ) -> Self {
        Self {
            provider: Arc::new(default_provider()),
            protocol: protocol.into(),
            expected_peer_key,
            trusted_fn,
            state,
            empty_subjects: Vec::new(),
        }
    }

    fn verify_cert_der(&self, end_entity: &CertificateDer<'_>) -> Result<(), RustlsError> {
        match verify_peer_cert_der(end_entity.as_ref(), &self.protocol) {
            Ok(verified) => {
                if let Some((expected_key, ref addr)) = self.expected_peer_key
                    && verified.public_key != expected_key
                {
                    let err = TlsAuthError::DifferentPeerKey {
                        addr: addr.clone(),
                        expected_b64: public_key_to_base64(&expected_key),
                        actual_b64: public_key_to_base64(&verified.public_key),
                    };
                    let msg = err.to_string();
                    self.state.record_cert(Err(err));
                    return Err(RustlsError::General(msg));
                }
                self.state.record_cert(Ok(verified));
                Ok(())
            }
            Err(id_err) => {
                let auth_err = TlsAuthError::from(id_err);
                let msg = auth_err.to_string();
                self.state.record_cert(Err(auth_err));
                Err(RustlsError::General(msg))
            }
        }
    }
}

impl ServerCertVerifier for Ed25519PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.verify_cert_der(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "TLS 1.2 nije dopusten za List2Cart sinkronizaciju".to_owned(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let valid = verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )?;
        self.state.mark_tls13_signature_verified();
        Ok(valid)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for Ed25519PeerVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.empty_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.verify_cert_der(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "TLS 1.2 nije dopusten za List2Cart sinkronizaciju".to_owned(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let valid = verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )?;
        self.state.mark_tls13_signature_verified();
        if let Some(ref checker) = self.trusted_fn
            && let Some(verified) = self.state.peek_verified_cert()
            && !checker(&verified.public_key, verified.credentials.as_deref())
        {
            let err = TlsAuthError::UntrustedPeer {
                public_key: verified.public_key,
            };
            let msg = err.to_string();
            self.state.record_cert(Err(err));
            return Err(RustlsError::General(msg));
        }
        Ok(valid)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
pub struct AuthenticatedStream<S> {
    pub stream: S,
    pub peer_key: [u8; 32],
    pub peer_credentials: Option<Vec<u8>>,
    pub rtt: Duration,
}

pub fn build_server_config_with_resolver(
    resolver: Arc<DynamicCertResolver>,
    protocol: &str,
    alpn: &[u8],
    trusted_fn: Option<KeyTrustChecker>,
) -> Result<(Arc<ServerConfig>, Arc<PeerVerifyState>), TlsAuthError> {
    let provider = Arc::new(default_provider());
    let state = Arc::new(PeerVerifyState::default());
    let verifier = Arc::new(Ed25519PeerVerifier::new(
        protocol,
        None,
        trusted_fn,
        state.clone(),
    ));

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| TlsAuthError::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok((Arc::new(cfg), state))
}

pub fn build_client_config_with_resolver(
    resolver: Arc<DynamicCertResolver>,
    protocol: &str,
    alpn: &[u8],
    expected_peer_key: Option<([u8; 32], String)>,
) -> Result<(Arc<ClientConfig>, Arc<PeerVerifyState>), TlsAuthError> {
    let provider = Arc::new(default_provider());
    let state = Arc::new(PeerVerifyState::default());
    let verifier = Arc::new(Ed25519PeerVerifier::new(
        protocol,
        expected_peer_key,
        None,
        state.clone(),
    ));

    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| TlsAuthError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(resolver);
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok((Arc::new(cfg), state))
}

fn sni_for_protocol(protocol: &str) -> Result<ServerName<'static>, TlsAuthError> {
    let cn = cert_cn_for_protocol(protocol);
    ServerName::try_from(cn)
        .map_err(|_| TlsAuthError::Tls("neispravno ime protokola za TLS ServerName".to_owned()))
}

pub async fn handshake_pairing_client<S>(
    stream: S,
    sk: &SigningKey,
    protocol: &str,
) -> Result<(ClientTlsStream<S>, VerifiedPeerCert), TlsAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let resolver = DynamicCertResolver::new(sk.clone(), protocol, None)?;
    let (cfg, state) = build_client_config_with_resolver(resolver, protocol, ALPN_PAIR, None)?;
    let connector = TlsConnector::from(cfg);
    let server_name = sni_for_protocol(protocol)?;
    match connector.connect(server_name, stream).await {
        Ok(tls_stream) => {
            let verified = state.take_verified(None)?;
            Ok((tls_stream, verified))
        }
        Err(e) => Err(state.take_verified(Some(e.to_string())).unwrap_err()),
    }
}

pub async fn handshake_pairing_server<S>(
    stream: S,
    sk: &SigningKey,
    protocol: &str,
) -> Result<(ServerTlsStream<S>, VerifiedPeerCert), TlsAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let resolver = DynamicCertResolver::new(sk.clone(), protocol, None)?;
    let (cfg, state) = build_server_config_with_resolver(resolver, protocol, ALPN_PAIR, None)?;
    let acceptor = TlsAcceptor::from(cfg);
    match acceptor.accept(stream).await {
        Ok(tls_stream) => {
            let verified = state.take_verified(None)?;
            Ok((tls_stream, verified))
        }
        Err(e) => Err(state.take_verified(Some(e.to_string())).unwrap_err()),
    }
}

pub async fn dial_exchange_on<S>(
    stream: S,
    sk: &SigningKey,
    protocol: &str,
    credentials_fn: Option<CredentialsProvider>,
    addr_label: &str,
    expected_peer_key: &[u8; 32],
) -> Result<AuthenticatedStream<ClientTlsStream<S>>, TlsAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let resolver = DynamicCertResolver::new(sk.clone(), protocol, credentials_fn)?;
    let (cfg, state) = build_client_config_with_resolver(
        resolver,
        protocol,
        ALPN_LAN,
        Some((*expected_peer_key, addr_label.to_owned())),
    )?;
    let connector = TlsConnector::from(cfg);
    let server_name = sni_for_protocol(protocol)?;
    let start = Instant::now();
    match connector.connect(server_name, stream).await {
        Ok(tls_stream) => {
            let rtt = start.elapsed();
            let verified = state.take_verified(None)?;
            Ok(AuthenticatedStream {
                stream: tls_stream,
                peer_key: verified.public_key,
                peer_credentials: verified.credentials,
                rtt,
            })
        }
        Err(e) => Err(state.take_verified(Some(e.to_string())).unwrap_err()),
    }
}

pub async fn accept_exchange_on<S, F>(
    stream: S,
    sk: &SigningKey,
    protocol: &str,
    credentials_fn: Option<CredentialsProvider>,
    trusted: F,
) -> Result<AuthenticatedStream<ServerTlsStream<S>>, TlsAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(&[u8; 32], Option<&[u8]>) -> bool + Send + Sync + 'static,
{
    let resolver = DynamicCertResolver::new(sk.clone(), protocol, credentials_fn)?;
    let (cfg, state) =
        build_server_config_with_resolver(resolver, protocol, ALPN_LAN, Some(Arc::new(trusted)))?;
    let acceptor = TlsAcceptor::from(cfg);
    match acceptor.accept(stream).await {
        Ok(tls_stream) => {
            let verified = state.take_verified(None)?;
            Ok(AuthenticatedStream {
                stream: tls_stream,
                peer_key: verified.public_key,
                peer_credentials: verified.credentials,
                rtt: Duration::ZERO,
            })
        }
        Err(e) => Err(state.take_verified(Some(e.to_string())).unwrap_err()),
    }
}

/// Verifies the peer's Ed25519 key possession and protocol over TLS 1.3 and
/// closes the stream immediately without sending a client certificate or
/// opening an exchange session on the server (`provjera_kljuca.go`).
pub async fn probe_peer_key_on<S>(
    stream: S,
    _sk: &SigningKey,
    protocol: &str,
    addr_label: &str,
    expected_peer_key: &[u8; 32],
) -> Result<Duration, TlsAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let provider = Arc::new(default_provider());
    let state = Arc::new(PeerVerifyState::default());
    let verifier = Arc::new(Ed25519PeerVerifier::new(
        protocol,
        Some((*expected_peer_key, addr_label.to_owned())),
        None,
        state.clone(),
    ));

    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| TlsAuthError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(NoClientCertResolver));
    cfg.alpn_protocols = vec![ALPN_LAN.to_vec()];

    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = sni_for_protocol(protocol)?;
    let start = Instant::now();
    match connector.connect(server_name, stream).await {
        Ok(mut tls_stream) => {
            let rtt = start.elapsed();
            let _verified = state.take_verified(None)?;
            let _ = tls_stream.shutdown().await;
            Ok(rtt.max(Duration::from_nanos(1)))
        }
        Err(e) => {
            // Check once: if the server already proved its certificate AND TLS 1.3
            // signature before closing on our empty client cert, the probe succeeded;
            // otherwise return the recorded auth/handshake error.
            let sig_ok = state.tls13_sig_verified.load(Ordering::Acquire);
            match state.take_verified(Some(e.to_string())) {
                Ok(_) if sig_ok => Ok(start.elapsed().max(Duration::from_nanos(1))),
                Ok(_) => Err(TlsAuthError::NotAPeer(e.to_string())),
                Err(auth_err) => Err(auth_err),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_signing_key;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct FixedCertResolver(Arc<CertifiedKey>);

    impl ResolvesServerCert for FixedCertResolver {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    #[test]
    fn dynamic_cert_resolver_caches_until_credentials_change() {
        let sk = generate_signing_key();
        let current = Arc::new(Mutex::new(Some(
            br#"{"clanstvo":{"deviceId":"a"}}"#.to_vec(),
        )));
        let c_clone = current.clone();
        let resolver = DynamicCertResolver::new(
            sk,
            "list2cart",
            Some(Arc::new(move || c_clone.lock().unwrap().clone())),
        )
        .expect("resolver");

        let first = resolver.current_certified_key().expect("first");
        let second = resolver.current_certified_key().expect("second");
        assert!(
            Arc::ptr_eq(&first, &second),
            "identical credentials must reuse cached CertifiedKey"
        );
        let parsed1 = verify_peer_cert_der(first.cert[0].as_ref(), "list2cart").expect("parse1");
        assert_eq!(
            parsed1.credentials.as_deref(),
            Some(br#"{"clanstvo":{"deviceId":"a"}}"#.as_slice())
        );

        *current.lock().unwrap() = Some(br#"{"clanstvo":{"deviceId":"b"}}"#.to_vec());
        let third = resolver.current_certified_key().expect("third");
        assert!(
            !Arc::ptr_eq(&first, &third),
            "updated credentials must mint a fresh certificate"
        );
        let parsed3 = verify_peer_cert_der(third.cert[0].as_ref(), "list2cart").expect("parse3");
        assert_eq!(
            parsed3.credentials.as_deref(),
            Some(br#"{"clanstvo":{"deviceId":"b"}}"#.as_slice())
        );
    }

    #[tokio::test]
    async fn tls13_proof_of_possession_rejects_stolen_public_cert_and_wrong_key() {
        let real_server = generate_signing_key();
        let imposter_key = generate_signing_key();
        let client_key = generate_signing_key();
        let real_server_pub = real_server.verifying_key().to_bytes();

        // Imposter presents `real_server`'s X.509 certificate but signs TLS 1.3 handshake with `imposter_key`.
        let stolen_cert_der =
            build_self_signed_cert_der(&real_server, "list2cart", None).expect("cert");
        let imposter_pkcs8 =
            ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_der(&imposter_key).expect("pkcs8");
        let provider = Arc::new(default_provider());
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                imposter_pkcs8.as_bytes().to_vec(),
            )))
            .expect("load imposter key");
        let mismatched_certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(stolen_cert_der)],
            signing_key,
        ));

        let state = Arc::new(PeerVerifyState::default());
        let verifier = Arc::new(Ed25519PeerVerifier::new("list2cart", None, None, state));
        let mut fake_server_cfg = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(FixedCertResolver(mismatched_certified)));
        fake_server_cfg.alpn_protocols = vec![ALPN_LAN.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(fake_server_cfg));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let _ = acceptor.accept(server_io).await;
        });

        let probe_err = probe_peer_key_on(
            client_io,
            &client_key,
            "list2cart",
            "127.0.0.1:4610",
            &real_server_pub,
        )
        .await;
        assert!(
            probe_err.is_err(),
            "stolen certificate without private key possession must fail TLS 1.3 handshake"
        );
    }

    #[tokio::test]
    async fn probe_peer_key_verifies_server_without_opening_exchange_or_calling_trusted() {
        let server_key = generate_signing_key();
        let client_key = generate_signing_key();
        let other_key = generate_signing_key();
        let server_pub = server_key.verifying_key().to_bytes();

        let trusted_calls = Arc::new(AtomicUsize::new(0));
        let exchange_opened = Arc::new(AtomicUsize::new(0));

        // 1. Valid key probe succeeds and does not trigger `trusted` or open exchange on server
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let sk_srv = server_key.clone();
        let tc = trusted_calls.clone();
        let eo = exchange_opened.clone();
        let srv_task = tokio::spawn(async move {
            let res = accept_exchange_on(server_io, &sk_srv, "list2cart", None, move |_, _| {
                tc.fetch_add(1, Ordering::SeqCst);
                true
            })
            .await;
            if res.is_ok() {
                eo.fetch_add(1, Ordering::SeqCst);
            }
            res
        });

        let rtt = probe_peer_key_on(
            client_io,
            &client_key,
            "list2cart",
            "127.0.0.1:4610",
            &server_pub,
        )
        .await
        .expect("probe should succeed");
        assert!(rtt > Duration::ZERO);
        let srv_res = srv_task.await.expect("join srv");
        assert!(matches!(srv_res, Err(TlsAuthError::NotAPeer(_))));
        assert_eq!(trusted_calls.load(Ordering::SeqCst), 0);
        assert_eq!(exchange_opened.load(Ordering::SeqCst), 0);

        // 2. Probing when expecting a different key returns DifferentPeerKey
        let (client_io2, server_io2) = tokio::io::duplex(16 * 1024);
        let sk_srv2 = server_key.clone();
        tokio::spawn(async move {
            let _ = accept_exchange_on(server_io2, &sk_srv2, "list2cart", None, |_, _| true).await;
        });
        let wrong_res = probe_peer_key_on(
            client_io2,
            &client_key,
            "list2cart",
            "127.0.0.1:4610",
            &other_key.verifying_key().to_bytes(),
        )
        .await;
        assert!(matches!(
            wrong_res,
            Err(TlsAuthError::DifferentPeerKey { .. })
        ));
    }

    #[tokio::test]
    async fn exchange_pins_expected_key_and_separates_pairing_alpn() {
        let server_key = generate_signing_key();
        let paired_key = generate_signing_key();
        let stranger_key = generate_signing_key();
        let server_pub = server_key.verifying_key().to_bytes();
        let paired_pub = paired_key.verifying_key().to_bytes();

        // 1. Paired client succeeds
        let (c_io, s_io) = tokio::io::duplex(16 * 1024);
        let sk_s = server_key.clone();
        let srv = tokio::spawn(async move {
            accept_exchange_on(s_io, &sk_s, "list2cart", None, move |pk, _| {
                pk == &paired_pub
            })
            .await
        });
        let cli = dial_exchange_on(
            c_io,
            &paired_key,
            "list2cart",
            None,
            "127.0.0.1:4610",
            &server_pub,
        )
        .await
        .expect("paired dial");
        let srv_conn = srv.await.unwrap().expect("paired accept");
        assert_eq!(cli.peer_key, server_pub);
        assert_eq!(srv_conn.peer_key, paired_pub);

        // 2. Stranger is rejected at server gate (`UntrustedPeer`) inside TLS handshake
        let (c_io2, s_io2) = tokio::io::duplex(16 * 1024);
        let sk_s2 = server_key.clone();
        let srv2 = tokio::spawn(async move {
            accept_exchange_on(s_io2, &sk_s2, "list2cart", None, move |pk, _| {
                pk == &paired_pub
            })
            .await
        });
        let cli2 = tokio::spawn(async move {
            dial_exchange_on(
                c_io2,
                &stranger_key,
                "list2cart",
                None,
                "127.0.0.1:4610",
                &server_pub,
            )
            .await
        });
        assert!(matches!(
            srv2.await.unwrap(),
            Err(TlsAuthError::UntrustedPeer { .. })
        ));
        let _ = cli2.await;

        // 3. Pairing client cannot connect to Exchange server (ALPN mismatch)
        let (c_io3, s_io3) = tokio::io::duplex(16 * 1024);
        let sk_s3 = server_key.clone();
        let srv3 = tokio::spawn(async move {
            accept_exchange_on(s_io3, &sk_s3, "list2cart", None, |_, _| true).await
        });
        let pair_on_exchange = handshake_pairing_client(c_io3, &paired_key, "list2cart").await;
        assert!(pair_on_exchange.is_err());
        assert!(srv3.await.unwrap().is_err());
    }
}
