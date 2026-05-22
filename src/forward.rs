use anyhow::Result;
use noq::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::FORWARD_BUF_SIZE;

/// Forward data between TCP stream and QUIC streams, shutting down gracefully
pub async fn forward_bidi(tcp_stream: TcpStream, mut recv: RecvStream, mut send: SendStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // QUIC → TCP
    let quic_to_tcp = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    tcp_write.write_all(&buf[..n]).await?;
                }
                Ok(None) => {
                    // Stream closed, shutdown TCP write half to signal EOF
                    tcp_write.shutdown().await?;
                    break;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    // TCP → QUIC
    let tcp_to_quic = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        loop {
            match tokio::io::AsyncReadExt::read(&mut tcp_read, &mut buf).await {
                Ok(0) => {
                    // TCP EOF, finish QUIC send stream
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    send.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    let (r1, r2) = tokio::join!(quic_to_tcp, tcp_to_quic);
    r1?;
    r2?;
    Ok(())
}

/// Forward data between stdio and QUIC streams, shutting down gracefully
pub async fn forward_bidi_stdio<R, W>(
    mut stdin: R,
    mut stdout: W,
    mut recv: RecvStream,
    mut send: SendStream,
) -> Result<()>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    // QUIC → stdout
    let quic_to_stdout = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    stdout.write_all(&buf[..n]).await?;
                }
                Ok(None) => break,
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    // stdin → QUIC
    let stdin_to_quic = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await {
                Ok(0) => {
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    send.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    let (r1, r2) = tokio::join!(quic_to_stdout, stdin_to_quic);
    r1?;
    r2?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forward_bidi_stdio_signature() {
        // Ensure the function compiles with concrete types
        let _f: fn(tokio::io::Stdin, tokio::io::Stdout, RecvStream, SendStream) -> _ = forward_bidi_stdio;
    }
}
