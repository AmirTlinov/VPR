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
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        }
    });
    addr
}

fn spawn_echo_udp() -> SocketAddr {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
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
    // Increased retries for CI environments
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not open port {}", addr);
}

fn spawn_server(
    bind_addr: &str,
    quic_addr: Option<&str>,
    noise_dir: &TempDir,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Child {
    let mut args = vec![
        "--bind".to_string(),
        bind_addr.to_string(),
        "--noise-dir".into(),
        noise_dir.path().to_str().unwrap().into(),
        "--noise-name".into(),
        "server".into(),
        "--cert".into(),
        cert.to_str().unwrap().into(),
        "--key".into(),
        key.to_str().unwrap().into(),
    ];
    if let Some(q) = quic_addr {
        args.push("--quic-bind".into());
        args.push(q.into());
    }

    std::process::Command::new(assert_cmd::cargo::cargo_bin!("masque-core"))
        .args(args)
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

    let mut server = spawn_server(&bind_addr, None, &tmp, &cert_path, &key_path);
    wait_port(bind_addr.parse().unwrap()).await;

    // Client: send payload and expect echo
    let mut client = std::process::Command::new(assert_cmd::cargo::cargo_bin!("client"))
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
    let _ = server.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_tcp_end_to_end() {
    let tmp = TempDir::new().unwrap();

    let server_kp = NoiseKeypair::generate();
    let client_kp = NoiseKeypair::generate();
    server_kp.save(tmp.path(), "server").unwrap();
    client_kp.save(tmp.path(), "client").unwrap();
    let server_pub_path = tmp.path().join("server.noise.pub");

    let (cert_path, key_path) = write_cert_pair(&tmp);

    let echo_tcp = spawn_echo_tcp();

    let quic_port = next_port();
    let quic_addr = format!("127.0.0.1:{quic_port}");

    let mut server = spawn_server("127.0.0.1:0", Some(&quic_addr), &tmp, &cert_path, &key_path);
    // give QUIC listener time to bind
    sleep(Duration::from_millis(200)).await;

    let mut client = std::process::Command::new(assert_cmd::cargo::cargo_bin!("client"))
        .args([
            "--addr",
            &quic_addr,
            "--server-name",
            "localhost",
            "--target",
            &echo_tcp.to_string(),
            "--proto",
            "tcp",
            "--transport",
            "quic",
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
    stdin.write_all(b"quic echo").unwrap();
    drop(stdin);

    let output = client.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(predicates::str::contains("quic echo").eval(&stdout));

    let _ = server.kill();
    let _ = server.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_udp_end_to_end() {
    let tmp = TempDir::new().unwrap();

    let server_kp = NoiseKeypair::generate();
    let client_kp = NoiseKeypair::generate();
    server_kp.save(tmp.path(), "server").unwrap();
    client_kp.save(tmp.path(), "client").unwrap();
    let server_pub_path = tmp.path().join("server.noise.pub");

    let (cert_path, key_path) = write_cert_pair(&tmp);

    let target_udp = spawn_echo_udp();

    let quic_port = next_port();
    let quic_addr = format!("127.0.0.1:{quic_port}");
    let mut server = spawn_server("127.0.0.1:0", Some(&quic_addr), &tmp, &cert_path, &key_path);
    sleep(Duration::from_millis(200)).await;

    let udp_listen_port = next_port();
    let udp_listen = format!("127.0.0.1:{udp_listen_port}");

    let mut client = std::process::Command::new(assert_cmd::cargo::cargo_bin!("client"))
        .args([
            "--addr",
            &quic_addr,
            "--server-name",
            "localhost",
            "--target",
            &target_udp.to_string(),
            "--proto",
            "udp",
            "--transport",
            "quic",
            "--udp-listen",
            &udp_listen,
            "--noise-dir",
            tmp.path().to_str().unwrap(),
            "--noise-name",
            "client",
            "--server-pub",
            server_pub_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start client");

    // Send UDP packet to client listener and expect echo
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let payload = b"udp-roundtrip";
    let mut buf = [0u8; 64];
    let mut received = false;
    for _ in 0..5 {
        let _ = sock.send_to(payload, &udp_listen);
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            if &buf[..n] == payload {
                received = true;
                break;
            }
        }
    }
    assert!(received, "no UDP echo received through tunnel");

    let _ = client.kill();
    let _ = server.kill();
    let _ = server.wait();
}
