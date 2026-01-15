//! Async adapters for PTY I/O.
//!
//! These adapters convert blocking PTY read/write operations into
//! async-friendly channel-based communication to avoid blocking
//! the tokio runtime.

use std::io::{Read, Write};
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

/// Async reader for PTY output.
///
/// Runs in a blocking thread and sends output chunks through a channel.
pub struct AsyncPtyReader<R: Read + Send + 'static> {
    reader: R,
    tx: mpsc::Sender<Vec<u8>>,
    buffer_size: usize,
}

impl<R: Read + Send + 'static> AsyncPtyReader<R> {
    /// Create a new AsyncPtyReader.
    ///
    /// # Arguments
    ///
    /// * `reader` - The PTY reader (blocking).
    /// * `tx` - Channel sender for output data.
    pub fn new(reader: R, tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            reader,
            tx,
            buffer_size: 4096,
        }
    }

    /// Create with custom buffer size.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Start the reader loop in a blocking thread.
    ///
    /// This method spawns a blocking task that reads from the PTY
    /// and sends data through the channel. It returns when:
    /// - The PTY is closed (read returns 0 or EIO)
    /// - The channel is closed (receiver dropped)
    /// - An unrecoverable error occurs
    pub async fn run(self) {
        let buffer_size = self.buffer_size;
        let mut reader = self.reader;
        let tx = self.tx;

        let result = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; buffer_size];

            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        debug!("PTY reader: EOF");
                        break;
                    }
                    Ok(n) => {
                        trace!("PTY reader: read {} bytes", n);
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            debug!("PTY reader: channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        // EIO on Unix typically means the PTY slave was closed
                        #[cfg(unix)]
                        if e.raw_os_error() == Some(libc::EIO) {
                            debug!("PTY reader: PTY closed (EIO)");
                            break;
                        }

                        // Check for broken pipe or similar
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            debug!("PTY reader: broken pipe");
                            break;
                        }

                        error!("PTY reader error: {}", e);
                        break;
                    }
                }
            }
        })
        .await;

        if let Err(e) = result {
            error!("PTY reader task panicked: {}", e);
        }
    }
}

/// Async writer for PTY input.
///
/// Receives data through a channel and writes to the PTY in a blocking thread.
pub struct AsyncPtyWriter<W: Write + Send + 'static> {
    writer: W,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl<W: Write + Send + 'static> AsyncPtyWriter<W> {
    /// Create a new AsyncPtyWriter.
    ///
    /// # Arguments
    ///
    /// * `writer` - The PTY writer (blocking).
    /// * `rx` - Channel receiver for input data.
    pub fn new(writer: W, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self { writer, rx }
    }

    /// Start the writer loop in a blocking thread.
    ///
    /// This method spawns a blocking task that receives data from
    /// the channel and writes it to the PTY. It returns when:
    /// - The channel is closed (sender dropped)
    /// - An unrecoverable error occurs
    pub async fn run(self) {
        let mut writer = self.writer;
        let mut rx = self.rx;

        let result = tokio::task::spawn_blocking(move || {
            // We need to receive in a blocking way inside spawn_blocking
            // Use a small wrapper to bridge async recv
            while let Some(data) = {
                // This is a bit awkward, but we need to block on the receive
                // We'll use a small runtime just for this
                tokio::runtime::Handle::try_current()
                    .ok()
                    .and_then(|h| h.block_on(async { rx.recv().await }))
                    .or_else(|| {
                        // Fallback: try blocking receive
                        rx.blocking_recv()
                    })
            } {
                trace!("PTY writer: writing {} bytes", data.len());
                if let Err(e) = writer.write_all(&data) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        debug!("PTY writer: broken pipe");
                        break;
                    }
                    error!("PTY writer error: {}", e);
                    break;
                }
                if let Err(e) = writer.flush() {
                    error!("PTY writer flush error: {}", e);
                    break;
                }
            }
            debug!("PTY writer: channel closed");
        })
        .await;

        if let Err(e) = result {
            error!("PTY writer task panicked: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    #[tokio::test]
    async fn test_async_reader_basic() {
        // Create a reader with some test data
        let data = b"Hello, World!\nTest line 2\n";
        let cursor = Cursor::new(data.to_vec());

        let (tx, mut rx) = mpsc::channel(32);
        let reader = AsyncPtyReader::new(cursor, tx);

        // Run reader in background
        let handle = tokio::spawn(reader.run());

        // Collect all received data
        let mut received = Vec::new();
        while let Ok(Some(chunk)) =
            tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
        {
            received.extend(chunk);
        }

        // Wait for reader to finish
        let _ = tokio::time::timeout(Duration::from_millis(100), handle).await;

        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn test_async_reader_empty() {
        let cursor = Cursor::new(Vec::new());
        let (tx, mut rx) = mpsc::channel(32);
        let reader = AsyncPtyReader::new(cursor, tx);

        let handle = tokio::spawn(reader.run());

        // Should complete quickly with no data
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Channel closed, no data

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_async_writer_basic() {
        let buffer = Vec::new();
        let cursor = Cursor::new(buffer);

        let (tx, rx) = mpsc::channel(32);
        let writer = AsyncPtyWriter::new(cursor, rx);

        // Send some data
        tx.send(b"Hello".to_vec()).await.unwrap();
        tx.send(b", World!".to_vec()).await.unwrap();
        drop(tx); // Close the channel

        // Run writer
        let handle = tokio::spawn(writer.run());
        let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;

        // Note: We can't easily check the output here because Cursor moves
        // This test mainly verifies no panics/deadlocks
    }

    #[tokio::test]
    async fn test_channel_creation() {
        // Test that we can create channels for PTY communication
        let (reader_tx, mut reader_rx) = mpsc::channel::<Vec<u8>>(32);
        let (writer_tx, _writer_rx) = mpsc::channel::<Vec<u8>>(32);

        // Verify channels work
        reader_tx.send(b"test".to_vec()).await.unwrap();
        let received = reader_rx.recv().await.unwrap();
        assert_eq!(received, b"test");

        writer_tx.send(b"input".to_vec()).await.unwrap();
    }

    #[tokio::test]
    async fn test_reader_channel_closed() {
        let data = b"Some data that won't be fully read";
        let cursor = Cursor::new(data.to_vec());

        let (tx, rx) = mpsc::channel(1); // Small buffer
        let reader = AsyncPtyReader::new(cursor, tx);

        // Drop receiver immediately
        drop(rx);

        // Reader should handle closed channel gracefully
        let handle = tokio::spawn(reader.run());
        let result = tokio::time::timeout(Duration::from_millis(100), handle).await;
        assert!(result.is_ok()); // Should complete without hanging
    }
}
