use assert_cmd::cargo::CommandCargoExt;
use predicates::prelude::*;
use rcgen::generate_simple_self_signed;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::time::sleep;
use vpr_crypto::keys::NoiseKeypair;

fn next_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_cert_pair(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let certified_key = generate_simple_self_signed(["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    // rcgen 0.13: CertifiedKey has .cert and .key_pair - use PEM format for rustls_pemfile
    std::fs::write(&cert_path, certified_key.cert.pem()).unwrap();
    std::fs::write(&key_path, certified_key.key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

fn spawn_echo_tcp() -> SocketAddr {
    let port = next_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    std::thread::spawn(move || {
        let listener = TcpListener::bind(addr).unwrap();
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        let _ = stream.write_all(&buf[..n]);
                    }
                }
            }
        }
    });
    addr
}

fn spawn_echo_udp() -> SocketAddr {
    let port = next_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    std::thread::spawn(move || {
        let socket = UdpSocket::bind(addr).unwrap();
        let mut buf = [0u8; 65535];
        loop {
            if let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..n], peer);
            }
        }
    });
    addr
}

async fn wait_port(addr: SocketAddr) {
    for _ in 0..30 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not open port {}", addr);
}

fn spawn_server(
    bind_addr: &str,
    noise_dir: &TempDir,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Child {
    std::process::Command::cargo_bin("masque-core")
        .unwrap()
        .args([
            "--bind",
            bind_addr,
            "--noise-dir",
            noise_dir.path().to_str().unwrap(),
            "--noise-name",
            "server",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start server")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_tcp_end_to_end() {
    let tmp = TempDir::new().unwrap();

    // Noise keys
    let server_kp = NoiseKeypair::generate();
    let client_kp = NoiseKeypair::generate();
    server_kp.save(tmp.path(), "server").unwrap();
    client_kp.save(tmp.path(), "client").unwrap();
    let server_pub_path = tmp.path().join("server.noise.pub");

    // Cert
    let (cert_path, key_path) = write_cert_pair(&tmp);

    // Backend echo services
    let echo_tcp = spawn_echo_tcp();
    let _echo_udp = spawn_echo_udp(); // reserved for future UDP test

    let bind_port = next_port();
    let bind_addr = format!("127.0.0.1:{bind_port}");

    let mut server = spawn_server(&bind_addr, &tmp, &cert_path, &key_path);
    wait_port(bind_addr.parse().unwrap()).await;

    // Client: send payload and expect echo
    let mut client = std::process::Command::cargo_bin("client")
        .unwrap()
        .args([
            "--addr",
            &bind_addr,
            "--server-name",
            "localhost",
            "--target",
            &echo_tcp.to_string(),
            "--proto",
            "tcp",
            "--noise-dir",
            tmp.path().to_str().unwrap(),
            "--noise-name",
            "client",
            "--server-pub",
            server_pub_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start client");

    let mut stdin = client.stdin.take().unwrap();
    stdin.write_all(b"hello world").unwrap();
    drop(stdin);

    let output = client.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(predicates::str::contains("hello world").eval(&stdout));

    let _ = server.kill();
}
