//! QUIC bidirectional stream adapter
//!
//! Wraps quinn's separate SendStream and RecvStream into a single
//! AsyncRead + AsyncWrite type for use with Noise handshakes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bidirectional QUIC stream adapter
///
/// Combines quinn's SendStream and RecvStream into a single type
/// that implements AsyncRead and AsyncWrite for use with protocols
/// that expect a single bidirectional stream (like Noise).
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    /// Create a new bidirectional stream from send/recv halves
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    /// Split back into send and receive halves
    pub fn into_parts(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }

    /// Get reference to send stream
    pub fn send(&self) -> &quinn::SendStream {
        &self.send
    }

    /// Get reference to receive stream
    pub fn recv(&self) -> &quinn::RecvStream {
        &self.recv
    }

    /// Get mutable reference to send stream
    pub fn send_mut(&mut self) -> &mut quinn::SendStream {
        &mut self.send
    }

    /// Get mutable reference to receive stream
    pub fn recv_mut(&mut self) -> &mut quinn::RecvStream {
        &mut self.recv
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            #[allow(clippy::incompatible_msrv)]
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            #[allow(clippy::incompatible_msrv)]
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            #[allow(clippy::incompatible_msrv)]
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    // QuicBiStream requires actual QUIC connection, tested via integration tests
}
