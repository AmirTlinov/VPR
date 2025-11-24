use assert_cmd::cargo::cargo_bin;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use quinn::{ClientConfig, Endpoint};
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

fn next_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn build_dns_query() -> Vec<u8> {
    let mut q = Vec::new();
    let id: u16 = 0x1234;
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NS
    q.extend_from_slice(&0u16.to_be_bytes()); // AR
    q.extend_from_slice(&[7, 101, 120, 97, 109, 112, 108, 101]);
    q.extend_from_slice(&[3, 99, 111, 109, 0]);
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // A
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    q
}

fn build_dns_response(id: u16) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&id.to_be_bytes());
    r.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD, RA, no error
    r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    r.extend_from_slice(&0u16.to_be_bytes()); // NS
    r.extend_from_slice(&0u16.to_be_bytes()); // AR
                                              // question (same as query)
    r.extend_from_slice(&[7, 101, 120, 97, 109, 112, 108, 101]);
    r.extend_from_slice(&[3, 99, 111, 109, 0]);
    r.extend_from_slice(&0x0001u16.to_be_bytes());
    r.extend_from_slice(&0x0001u16.to_be_bytes());
    // answer
    r.extend_from_slice(&[0xC0, 0x0C]); // pointer to name
    r.extend_from_slice(&0x0001u16.to_be_bytes()); // type A
    r.extend_from_slice(&0x0001u16.to_be_bytes()); // class IN
    r.extend_from_slice(&60u32.to_be_bytes()); // TTL
    r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    r.extend_from_slice(&[1, 2, 3, 4]); // 1.2.3.4
    r
}

fn spawn_upstream_udp(addr: &str) {
    let response_template = build_dns_response(0x1234);
    let addr: SocketAddr = addr.parse().unwrap();
    std::thread::spawn(move || {
        let socket = UdpSocket::bind(addr).unwrap();
        let mut buf = [0u8; 512];
        loop {
            if let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let mut resp = response_template.clone();
                if n >= 2 {
                    resp[0] = buf[0];
                    resp[1] = buf[1];
                }
                let _ = socket.send_to(&resp, peer);
            }
        }
    });
}

async fn wait_http(port: u16) {
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/healthz");
    for _ in 0..40 {
        if client.get(&url).send().await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("doh-gateway not responding on {port}");
}

fn spawn_gateway(bind: u16, doq: u16, upstream: &str) -> Child {
    std::process::Command::new(cargo_bin!("doh-gateway"))
        .args([
            "--bind",
            &format!("127.0.0.1:{bind}"),
            "--doq-bind",
            &format!("127.0.0.1:{doq}"),
            "--upstream",
            upstream,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start doh-gateway")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_roundtrip_basic() {
    let _tmp = TempDir::new().unwrap();
    let upstream_port = next_port();
    let upstream_addr = format!("127.0.0.1:{upstream_port}");
    spawn_upstream_udp(&upstream_addr);

    let bind_port = next_port();
    let doq_port = next_port();
    let mut gateway = spawn_gateway(bind_port, doq_port, &upstream_addr);

    wait_http(bind_port).await;

    let query = build_dns_query();
    let encoded = URL_SAFE_NO_PAD.encode(&query);
    let url = format!("http://127.0.0.1:{bind_port}/dns-query?dns={encoded}");
    let client = Client::new();
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..2], &query[..2]);
    assert!(body.windows(4).any(|w| w == [1, 2, 3, 4]));

    let _ = gateway.kill();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doq_roundtrip_basic() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let _tmp = TempDir::new().unwrap();
    let upstream_port = next_port();
    let upstream_addr = format!("127.0.0.1:{upstream_port}");
    spawn_upstream_udp(&upstream_addr);

    let bind_port = next_port();
    let doq_port = next_port();
    let mut gateway = spawn_gateway(bind_port, doq_port, &upstream_addr);

    sleep(Duration::from_millis(300)).await;
    if let Some(status) = gateway.try_wait().unwrap() {
        panic!("doh-gateway exited early with status {status}");
    }

    // Build QUIC client that skips cert verification (test-only)
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let server_addr = format!("127.0.0.1:{doq_port}").parse().unwrap();
    let connection = {
        let mut attempt = None;
        for _ in 0..12 {
            match endpoint.connect(server_addr, "localhost") {
                Ok(conn) => {
                    if let Ok(Ok(c)) = timeout(Duration::from_millis(500), conn).await {
                        attempt = Some(c);
                        break;
                    }
                }
                Err(_) => {}
            }
            sleep(Duration::from_millis(100)).await;
        }
        attempt.expect("DoQ server did not accept connection")
    };

    let (mut send, mut recv) = connection.open_bi().await.unwrap();

    let query = build_dns_query();
    let len = (query.len() as u16).to_be_bytes();
    send.write_all(&len).await.unwrap();
    send.write_all(&query).await.unwrap();
    send.finish().unwrap();

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(5), recv.read_exact(&mut len_buf))
        .await
        .unwrap()
        .unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    timeout(Duration::from_secs(5), recv.read_exact(&mut resp))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&resp[..2], &query[..2]);
    assert!(resp.windows(4).any(|w| w == [1, 2, 3, 4]));

    let _ = gateway.kill();
}

/// Insecure verifier for test purposes (DoQ self-signed)
#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
