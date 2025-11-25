#![allow(deprecated)]
use assert_cmd::cargo::cargo_bin;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use quinn::rustls::pki_types::CertificateDer;
use quinn::{ClientConfig, Endpoint};
use rcgen::generate_simple_self_signed;
use reqwest::ClientBuilder;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
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
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let url = format!("https://127.0.0.1:{port}/dns-query");
    for _ in 0..40 {
        if client.get(&url).send().await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("doh-gateway not responding on {port}");
}

fn spawn_gateway(bind: u16, doq: u16, upstream: &str, config: Option<&std::path::Path>) -> Child {
    let mut cmd = std::process::Command::new(cargo_bin!("doh-gateway"));
    cmd.args([
        "--bind",
        &format!("127.0.0.1:{bind}"),
        "--doq-bind",
        &format!("127.0.0.1:{doq}"),
        "--upstream",
        upstream,
    ]);

    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }

    cmd.stdout(Stdio::null())
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
    let mut gateway = spawn_gateway(bind_port, doq_port, &upstream_addr, None);

    wait_http(bind_port).await;

    let query = build_dns_query();
    let encoded = URL_SAFE_NO_PAD.encode(&query);
    let url = format!("https://127.0.0.1:{bind_port}/dns-query?dns={encoded}");
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..2], &query[..2]);
    assert!(body.windows(4).any(|w| w == [1, 2, 3, 4]));

    let _ = gateway.kill();
    let _ = gateway.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doq_roundtrip_basic() {
    let _ = quinn::rustls::crypto::ring::default_provider().install_default();

    let tmp = TempDir::new().unwrap();
    let upstream_port = next_port();
    let upstream_addr = format!("127.0.0.1:{upstream_port}");
    spawn_upstream_udp(&upstream_addr);

    // Generate self-signed cert for localhost and write to temp files
    let cert = generate_simple_self_signed(["localhost".into()]).unwrap();
    let cert_path = tmp.path().join("doq_cert.pem");
    let key_path = tmp.path().join("doq_key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    // Build config file for gateway
    let bind_port = next_port();
    let doq_port = next_port();
    let cfg_path = tmp.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "bind = \"127.0.0.1:{bind}\"\ndoq_bind = \"127.0.0.1:{doq}\"\ndoq_cert = \"{}\"\ndoq_key = \"{}\"\nupstream = \"{upstream}\"\n",
            cert_path.display(),
            key_path.display(),
            upstream = upstream_addr,
            bind = bind_port,
            doq = doq_port,
        ),
    )
    .unwrap();

    let mut gateway = spawn_gateway(bind_port, doq_port, &upstream_addr, Some(&cfg_path));

    sleep(Duration::from_millis(300)).await;
    if let Some(status) = gateway.try_wait().unwrap() {
        panic!("doh-gateway exited early with status {status}");
    }

    // Build QUIC client trusting the generated self-signed cert
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add_parsable_certificates(vec![CertificateDer::from(cert.cert.der().to_vec())]);

    let client_crypto = quinn::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_crypto)).unwrap(),
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let server_addr = format!("127.0.0.1:{doq_port}").parse().unwrap();
    let connection = {
        let mut attempt = None;
        for _ in 0..12 {
            if let Ok(conn) = endpoint.connect(server_addr, "localhost") {
                if let Ok(Ok(c)) = timeout(Duration::from_millis(500), conn).await {
                    attempt = Some(c);
                    break;
                }
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
    let _ = gateway.wait();
}
