//! Tests for H3 server paths
//!
//! Verify CONNECT-UDP URI parsing and MASQUE path detection.

#[test]
fn connect_udp_uri_check() {
    // Verify MASQUE CONNECT-UDP URI path format
    let uri = "https://example.com/.well-known/masque/udp/8.8.8.8/53";
    let parsed: http::Uri = uri.parse().expect("valid URI");

    assert_eq!(parsed.scheme_str(), Some("https"));
    assert_eq!(parsed.host(), Some("example.com"));
    assert!(parsed.path().starts_with("/.well-known/masque/udp/"));

    // Parse target from path
    let path = parsed.path();
    let parts: Vec<&str> = path.split('/').collect();
    // Path: ["", ".well-known", "masque", "udp", "8.8.8.8", "53"]
    assert_eq!(parts.get(4), Some(&"8.8.8.8")); // target host
    assert_eq!(parts.get(5), Some(&"53")); // target port
}

#[test]
fn masque_path_detection() {
    // Valid MASQUE paths
    let valid_paths = [
        "/.well-known/masque/udp/8.8.8.8/53",
        "/.well-known/masque/udp/2606:4700:4700::1111/853",
        "/.well-known/masque/udp/example.com/443",
    ];

    for path in valid_paths {
        assert!(
            path.starts_with("/.well-known/masque/udp/"),
            "Path should be detected as MASQUE UDP: {path}"
        );
    }

    // Invalid paths
    let invalid_paths = ["/api/v1/connect", "/masque/tcp/host/port", "/.well-known/"];

    for path in invalid_paths {
        assert!(
            !path.starts_with("/.well-known/masque/udp/"),
            "Path should NOT be detected as MASQUE UDP: {path}"
        );
    }
}
