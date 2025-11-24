//! Unit tests for quic_stream module

use masque_core::quic_stream::QuicBiStream;

#[test]
fn bistream_is_send_sync() {
    // QuicBiStream wraps quinn streams and must be Send + Sync for async usage
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<QuicBiStream>();
}

#[test]
fn bistream_size_is_reasonable() {
    // QuicBiStream should not be excessively large
    // Quinn's SendStream and RecvStream together are ~100-200 bytes typically
    // We allow up to 512 bytes to be conservative
    let size = std::mem::size_of::<QuicBiStream>();
    assert!(
        size <= 512,
        "QuicBiStream size ({size} bytes) exceeds 512 bytes"
    );
}
