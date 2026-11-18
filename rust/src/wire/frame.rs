use std::fmt;
use std::io::{Read, Write};

pub const DEFAULT_MAX_FRAME_LEN: usize = 64 * 1024;
pub const MAX_DATA_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooLarge { len: usize, max: usize },
    Io(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => {
                write!(f, "okvir je prevelik ({len} B > max {max} B)")
            }
            Self::Io(e) => write!(f, "I/O greska okvira: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    max_len: usize,
) -> Result<(), FrameError> {
    if payload.len() > max_len {
        return Err(FrameError::TooLarge {
            len: payload.len(),
            max: max_len,
        });
    }
    let len_be = (payload.len() as u32).to_be_bytes();
    writer
        .write_all(&len_be)
        .map_err(|e| FrameError::Io(e.to_string()))?;
    writer
        .write_all(payload)
        .map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R, max_len: usize) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|e| FrameError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(FrameError::TooLarge { len, max: max_len });
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(buf)
}

pub async fn write_frame_async<W>(
    writer: &mut W,
    payload: &[u8],
    max_len: usize,
) -> Result<(), FrameError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    if payload.len() > max_len {
        return Err(FrameError::TooLarge {
            len: payload.len(),
            max: max_len,
        });
    }
    let len_be = (payload.len() as u32).to_be_bytes();
    writer
        .write_all(&len_be)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    writer
        .write_all(payload)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(())
}

pub async fn read_frame_async<R>(reader: &mut R, max_len: usize) -> Result<Vec<u8>, FrameError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(FrameError::TooLarge { len, max: max_len });
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip_and_pre_allocation_limit() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"ok\":true}", DEFAULT_MAX_FRAME_LEN).expect("write");
        let mut cur = Cursor::new(buf);
        let decoded = read_frame(&mut cur, DEFAULT_MAX_FRAME_LEN).expect("read");
        assert_eq!(decoded, b"{\"ok\":true}");

        // Header claims 64 KiB + 1 bytes without body: rejected before allocating body
        let mut oversized = ((DEFAULT_MAX_FRAME_LEN as u32) + 1).to_be_bytes().to_vec();
        oversized.extend_from_slice(b"abc");
        let mut cur2 = Cursor::new(oversized);
        assert!(matches!(
            read_frame(&mut cur2, DEFAULT_MAX_FRAME_LEN),
            Err(FrameError::TooLarge { .. })
        ));
    }
}
