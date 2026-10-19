//! Draining a child's output pipe without a thread that can be left blocked.
//!
//! Execution used to pump each pipe with a dedicated thread doing blocking
//! `read()`. That thread has exactly one way out — EOF — and EOF arrives only
//! when *every* holder of the write end has closed it. A shell child routinely
//! leaves a grandchild behind (a daemon, a watcher, anything started in the
//! background), the grandchild inherits both pipe handles, and it does not close
//! them because it is still running. The reader thread then blocks forever: the
//! `JoinHandle` was dropped rather than joined, so nothing ever noticed.
//!
//! Measured before the change, on Windows: one leaked thread and one leaked
//! handle for every command that left a quiet background process, never
//! reclaimed, growing without bound for as long as the server ran. Two threads
//! when the grandchild was quiet on *both* pipes — which is the common case,
//! since a daemon usually redirects its own output. The reclaim path was to kill
//! the grandchild, which the server has no business doing on the success path.
//!
//! So the fix removes the thread rather than adding an escape hatch for it. The
//! control loop in `executor.rs` already polls at a fixed interval to enforce
//! the timeout and reap the child; draining both pipes from that same loop needs
//! no thread at all, and the loop can simply stop and close its read ends when
//! the child is gone. A pipe nobody is blocked on cannot be leaked.
//!
//! What it costs is a platform call per pipe per poll. Neither is a blocking
//! call, and both are the standard way to read a pipe without committing to it:
//! `PeekNamedPipe` on Windows (anonymous pipes are named pipes underneath, so it
//! applies), `O_NONBLOCK` on Unix.

use std::io::{self, Read, Write};

/// Largest single `read` issued against a pipe.
const READ_CHUNK: usize = 4096;

/// A source this module can drain: a pipe, plus whatever the platform needs to
/// interrogate it without blocking. `ChildStdout` and `ChildStderr` satisfy both.
#[cfg(windows)]
pub(crate) trait PipeSource: Read + std::os::windows::io::AsRawHandle {}
#[cfg(windows)]
impl<T: Read + std::os::windows::io::AsRawHandle> PipeSource for T {}

/// A source this module can drain: a pipe, plus whatever the platform needs to
/// interrogate it without blocking. `ChildStdout` and `ChildStderr` satisfy both.
#[cfg(unix)]
pub(crate) trait PipeSource: Read + std::os::unix::io::AsRawFd {}
#[cfg(unix)]
impl<T: Read + std::os::unix::io::AsRawFd> PipeSource for T {}

/// What one non-blocking read found.
enum Outcome {
    /// This many bytes were read.
    Data(usize),
    /// The pipe is open but has nothing right now.
    Empty,
    /// Every write end is closed; nothing further will arrive.
    Eof,
}

/// One of a child's output pipes, drained on demand rather than by a thread.
///
/// Holds the read end and closes it on [`PipeDrain::release`] or on drop, which
/// is the whole point: giving up on a pipe is a local decision here, where the
/// blocking-thread design made it impossible.
pub(crate) struct PipeDrain<R: PipeSource> {
    /// `None` once the pipe has ended or failed — the handle is closed then.
    reader: Option<R>,
    buf: [u8; READ_CHUNK],
}

impl<R: PipeSource> PipeDrain<R> {
    /// Take ownership of a pipe's read end.
    ///
    /// On Unix this switches the descriptor to non-blocking; a failure there is
    /// reported as an immediately-finished pipe rather than swallowed, because a
    /// descriptor that stayed blocking would reintroduce exactly the stall this
    /// module exists to remove.
    pub(crate) fn new(reader: R) -> Self {
        #[cfg(unix)]
        {
            if !set_nonblocking(&reader) {
                return Self {
                    reader: None,
                    buf: [0u8; READ_CHUNK],
                };
            }
        }
        Self {
            reader: Some(reader),
            buf: [0u8; READ_CHUNK],
        }
    }

    /// Whether this pipe has ended and can be ignored from here on.
    pub(crate) fn finished(&self) -> bool {
        self.reader.is_none()
    }

    /// Close the read end now, whatever state the pipe is in.
    ///
    /// Called when the caller stops caring — a deadline passed, the result is
    /// already being returned. Nothing is left waiting on the pipe afterwards.
    pub(crate) fn release(&mut self) {
        self.reader = None;
    }

    /// Move up to `budget` bytes into `sink`, returning how many moved.
    ///
    /// Never blocks, and never runs longer than `budget` allows. The budget is
    /// what keeps a pipe that always has data — a command streaming megabytes —
    /// from holding the control loop away from its deadline and `try_wait`
    /// checks; the loop gets to run either way, it just takes more passes.
    ///
    /// A read error ends the pipe rather than propagating. The blocking readers
    /// this replaced did the same (`Err(_) => break`): a broken pipe is how a
    /// pipe ends on some platforms, and the child's exit status is the thing
    /// callers act on.
    pub(crate) fn drain(&mut self, budget: usize, sink: &mut impl FnMut(&[u8])) -> usize {
        let mut moved = 0;
        while moved < budget {
            let Some(reader) = self.reader.as_mut() else {
                break;
            };
            let want = READ_CHUNK.min(budget - moved);
            match read_available(reader, &mut self.buf[..want]) {
                Outcome::Data(0) | Outcome::Eof => {
                    self.reader = None;
                    break;
                }
                Outcome::Data(n) => {
                    sink(&self.buf[..n]);
                    moved += n;
                }
                Outcome::Empty => break,
            }
        }
        moved
    }
}

/// Largest single `write` issued against a child's stdin.
///
/// On Windows this is not only a pass size. A pipe in `PIPE_NOWAIT` mode
/// accepts a write whole or not at all — measured: a 4 MiB write to a pipe
/// nobody was reading returned zero bytes every time, while the same bytes in
/// 4 KiB writes filled the 64 KiB buffer and then stopped. A write larger than
/// the free space never makes progress, so writes stay small enough to fit.
const WRITE_CHUNK: usize = 4096;

/// A sink this module can feed: a pipe's write end, plus whatever the platform
/// needs to switch it to non-blocking. `ChildStdin` satisfies both.
#[cfg(windows)]
pub(crate) trait PipeSink: Write + std::os::windows::io::AsRawHandle {}
#[cfg(windows)]
impl<T: Write + std::os::windows::io::AsRawHandle> PipeSink for T {}

/// A sink this module can feed: a pipe's write end, plus whatever the platform
/// needs to switch it to non-blocking. `ChildStdin` satisfies both.
#[cfg(unix)]
pub(crate) trait PipeSink: Write + std::os::unix::io::AsRawFd {}
#[cfg(unix)]
impl<T: Write + std::os::unix::io::AsRawFd> PipeSink for T {}

/// A child's stdin, fed from a polling loop rather than by a thread — the same
/// answer [`PipeDrain`] gives for output, for the same reason.
///
/// A thread doing a blocking `write_all` has one way out: the input is accepted.
/// A child that never reads its stdin, or a grandchild that inherited it and
/// sits on it, means the input is never accepted, and the thread blocks for the
/// life of the server. Here a full pipe is a pass that moves nothing, and the
/// loop decides when to stop trying.
///
/// Two shapes. [`new`](Self::new) carries a fixed input and closes the write
/// end as soon as the last byte is accepted — the end-of-file a one-shot
/// command reads after its input. [`open`](Self::open) starts empty and stays
/// open: input is [`push`](Self::push)ed as it arrives and the pipe closes only
/// once [`close_when_drained`](Self::close_when_drained) has been asked for and
/// everything queued is in. Either way the write end also closes when the child
/// stops reading for good (the pipe breaks) and on drop.
pub(crate) struct PipeFeed<W: PipeSink> {
    /// `None` once closed: delivered and asked to close, or the pipe is gone.
    writer: Option<W>,
    /// Queued input; `input[offset..]` is what the pipe has not accepted yet.
    input: Vec<u8>,
    offset: usize,
    /// Bytes the pipe has accepted, over the feed's life.
    accepted: u64,
    close_when_drained: bool,
}

impl<W: PipeSink> PipeFeed<W> {
    /// A feed carrying `input`, closed once it is delivered.
    ///
    /// Fails if the pipe cannot be made non-blocking. Unlike a read end, a
    /// write end that stayed blocking cannot be degraded into "finished": the
    /// child would be told its input ended when it never arrived.
    pub(crate) fn new(writer: W, input: Vec<u8>) -> io::Result<Self> {
        let mut feed = Self::open(writer)?;
        feed.input = input;
        feed.close_when_drained();
        Ok(feed)
    }

    /// A feed with nothing queued, left open until asked to close.
    pub(crate) fn open(writer: W) -> io::Result<Self> {
        set_write_nonblocking(&writer)?;
        Ok(Self {
            writer: Some(writer),
            input: Vec::new(),
            offset: 0,
            accepted: 0,
            close_when_drained: false,
        })
    }

    /// Queue more input behind what is already queued.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        if self.writer.is_some() {
            self.input.extend_from_slice(bytes);
        }
    }

    /// Close the write end once everything queued has been accepted — at once,
    /// if nothing is.
    pub(crate) fn close_when_drained(&mut self) {
        self.close_when_drained = true;
        self.close_if_done();
    }

    /// Whether the write end is still open.
    pub(crate) fn is_open(&self) -> bool {
        self.writer.is_some()
    }

    /// Bytes queued that the pipe has not accepted yet. Zero once closed: a
    /// closed feed can deliver nothing more, and what it held is dropped.
    pub(crate) fn pending(&self) -> usize {
        if self.writer.is_some() {
            self.input.len() - self.offset
        } else {
            0
        }
    }

    /// Bytes the pipe has accepted over the feed's life.
    ///
    /// Accepted is not the same as read: the last pipe buffer's worth may still
    /// be unread when the child exits.
    pub(crate) fn accepted(&self) -> u64 {
        self.accepted
    }

    /// Close the write end now, delivered or not.
    pub(crate) fn release(&mut self) {
        self.writer = None;
        self.input = Vec::new();
        self.offset = 0;
    }

    fn close_if_done(&mut self) {
        if self.close_when_drained && self.offset == self.input.len() {
            self.release();
        }
    }

    /// Write up to `budget` more bytes of the queue, returning how many moved.
    ///
    /// Never blocks. A full pipe ends the pass; a broken one — the child has
    /// exited or closed its stdin — ends the feed.
    pub(crate) fn feed(&mut self, budget: usize) -> usize {
        let mut moved = 0;
        while moved < budget && self.offset < self.input.len() {
            let Some(writer) = self.writer.as_mut() else {
                break;
            };
            let end = self
                .input
                .len()
                .min(self.offset + WRITE_CHUNK.min(budget - moved));
            match writer.write(&self.input[self.offset..end]) {
                // Windows `PIPE_NOWAIT`: no room for this write right now.
                Ok(0) => break,
                Ok(n) => {
                    self.offset += n;
                    self.accepted += n as u64;
                    moved += n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                // A broken pipe, or anything else: no further write can land.
                Err(_) => {
                    self.release();
                    return moved;
                }
            }
        }
        if self.offset == self.input.len() {
            // Everything queued is in: forget it, so a long-lived feed holds
            // only what is still pending.
            self.input.clear();
            self.offset = 0;
        }
        self.close_if_done();
        moved
    }
}

/// Switch a pipe's write end to non-blocking.
#[cfg(windows)]
fn set_write_nonblocking<W: PipeSink>(writer: &W) -> io::Result<()> {
    use std::ffi::c_void;

    // Anonymous pipes are named pipes underneath (the reason `PeekNamedPipe`
    // works on them, above), so the named-pipe mode switch applies too.
    #[link(name = "kernel32")]
    extern "system" {
        fn SetNamedPipeHandleState(
            handle: *mut c_void,
            mode: *mut u32,
            max_collection_count: *mut u32,
            collect_data_timeout: *mut u32,
        ) -> i32;
    }

    /// `PIPE_NOWAIT` — a write returns at once, with the bytes accepted.
    const PIPE_NOWAIT: u32 = 1;

    let mut mode = PIPE_NOWAIT;
    // SAFETY: `handle` is a live pipe handle owned by `writer` for this call; the
    // two collection parameters apply only to remote pipes and may be null.
    let ok = unsafe {
        SetNamedPipeHandleState(
            writer.as_raw_handle(),
            &mut mode,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Switch a pipe's write end to non-blocking.
#[cfg(unix)]
fn set_write_nonblocking<W: PipeSink>(writer: &W) -> io::Result<()> {
    if set_fd_nonblocking(writer.as_raw_fd()) {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Read whatever is there without waiting for more.
#[cfg(windows)]
fn read_available<R: PipeSource>(reader: &mut R, buf: &mut [u8]) -> Outcome {
    use std::ffi::c_void;

    // `PeekNamedPipe` reports how much is readable and, once every write end is
    // gone, fails with ERROR_BROKEN_PIPE. Those are the two facts a blocking
    // `read` conflates by simply waiting for whichever comes first. A pipe that
    // is open but idle — the grandchild case — is `Ok` with zero available, and
    // being able to see that state at all is what makes giving up possible.
    #[link(name = "kernel32")]
    extern "system" {
        fn PeekNamedPipe(
            handle: *mut c_void,
            buffer: *mut c_void,
            buffer_size: u32,
            bytes_read: *mut u32,
            total_available: *mut u32,
            bytes_left_this_message: *mut u32,
        ) -> i32;
    }

    /// `ERROR_BROKEN_PIPE` — every write end has been closed.
    const ERROR_BROKEN_PIPE: i32 = 109;

    let mut available: u32 = 0;
    // SAFETY: `handle` is a live pipe handle owned by `reader` for the duration
    // of this call, and the three out-parameters this does not want are passed
    // as null, which `PeekNamedPipe` documents as permitted.
    let ok = unsafe {
        PeekNamedPipe(
            reader.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };

    if ok == 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(ERROR_BROKEN_PIPE) => Outcome::Eof,
            // Any other failure is treated as the end of this pipe, matching the
            // blocking readers this replaced. Retrying an unknown handle error
            // every poll would spin without ever making progress.
            _ => Outcome::Eof,
        };
    }
    if available == 0 {
        return Outcome::Empty;
    }

    // Bounded by `available`, so this cannot block waiting for bytes that have
    // not been written yet.
    let want = buf.len().min(available as usize);
    match reader.read(&mut buf[..want]) {
        Ok(0) => Outcome::Eof,
        Ok(n) => Outcome::Data(n),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Outcome::Empty,
        Err(_) => Outcome::Eof,
    }
}

/// Read whatever is there without waiting for more.
#[cfg(unix)]
fn read_available<R: PipeSource>(reader: &mut R, buf: &mut [u8]) -> Outcome {
    // The descriptor was put in non-blocking mode when the pipe was taken over,
    // so the three states are the three answers `read` already gives: bytes,
    // `WouldBlock` for an open-but-idle pipe, and zero for a closed one.
    match reader.read(buf) {
        Ok(0) => Outcome::Eof,
        Ok(n) => Outcome::Data(n),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Outcome::Empty,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Outcome::Empty,
        Err(_) => Outcome::Eof,
    }
}

/// Switch a read end to non-blocking, reporting whether it took.
#[cfg(unix)]
fn set_nonblocking<R: PipeSource>(reader: &R) -> bool {
    // No `use` for `AsRawFd`: the method is in scope through `PipeSource`'s own
    // bound. Importing it as well is an unused import, and `clippy-all` runs
    // with `-D warnings` — which would have failed CI's Lint job on Unix only,
    // where this branch is the one that compiles.
    set_fd_nonblocking(reader.as_raw_fd())
}

/// Switch a descriptor to non-blocking, reporting whether it took.
#[cfg(unix)]
fn set_fd_nonblocking(fd: std::os::unix::io::RawFd) -> bool {
    // SAFETY: `fd` is owned by the caller's pipe and live for this call; both `fcntl`
    // uses here only read and rewrite that descriptor's own status flags.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return false;
        }
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    use crate::process::shell_command;

    fn collect(drain: &mut PipeDrain<impl PipeSource>, budget: usize) -> Vec<u8> {
        let mut out = Vec::new();
        drain.drain(budget, &mut |chunk: &[u8]| out.extend_from_slice(chunk));
        out
    }

    /// The ordinary case: a command writes, the pipe ends when it exits.
    #[test]
    fn a_finished_command_ends_its_pipe() {
        let mut child = shell_command("echo drained_ok")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let mut pipe = PipeDrain::new(child.stdout.take().expect("stdout is piped"));
        let _ = child.wait();

        let mut got = Vec::new();
        // Polling rather than one call: the child may exit before its bytes have
        // been through the pipe, and `finished()` is the only end condition —
        // exactly how the control loop uses this.
        for _ in 0..200 {
            got.extend_from_slice(&collect(&mut pipe, 64 * 1024));
            if pipe.finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert!(
            pipe.finished(),
            "the pipe of an exited command must reach its end"
        );
        assert!(
            String::from_utf8_lossy(&got).contains("drained_ok"),
            "everything written before the end must be drained: {got:?}"
        );
    }

    /// An idle pipe reports empty rather than ending — and, crucially, returns.
    ///
    /// This is the state a blocking `read` cannot observe: it simply waits, and
    /// waits for as long as whoever holds the write end stays alive. Here it is
    /// a live child that has written nothing yet, which is the same pipe state a
    /// surviving grandchild leaves behind.
    #[test]
    fn an_idle_pipe_reports_empty_without_blocking() {
        #[cfg(windows)]
        let line = "ping -n 4 127.0.0.1 >nul";
        #[cfg(unix)]
        let line = "sleep 3";

        let mut child = shell_command(line)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let mut pipe = PipeDrain::new(child.stdout.take().expect("stdout is piped"));

        let start = std::time::Instant::now();
        let moved = collect(&mut pipe, 64 * 1024);
        let elapsed = start.elapsed();

        assert!(
            moved.is_empty(),
            "a silent command wrote nothing: {moved:?}"
        );
        assert!(
            !pipe.finished(),
            "a pipe held open by a live process has not ended"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "draining an idle pipe must return at once, not wait on it: {elapsed:?}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    /// The budget bounds one pass, so the caller's loop always gets to run.
    ///
    /// The writer is the shell's own `echo` and the whole payload fits the pipe
    /// buffer, so waiting for the child settles the question of what is readable:
    /// a single write that fits cannot be observed half-done, and the child is
    /// gone before anything is read. That is what lets this assert the exact
    /// budget rather than "no more than" it — a pass that ignored the budget
    /// returns the whole payload, and there is no third answer to confuse it with.
    ///
    /// It used to start PowerShell and poll two seconds for a first byte. That
    /// measured an interpreter's startup: 319 ms on a warm workstation, over the
    /// two seconds on a cold CI runner, where it failed on its first run there.
    /// With `stderr` discarded, a slow interpreter and a broken command line were
    /// also the same observation — zero bytes.
    #[test]
    fn a_pass_stops_at_its_budget() {
        // Twice the budget, and well under the 4 KiB a Windows anonymous pipe
        // buffers, so the writer never blocks and `wait` cannot deadlock on it.
        const PAYLOAD: usize = 2048;
        const BUDGET: usize = 1024;

        let mut child = shell_command(&format!("echo {}", "x".repeat(PAYLOAD)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let mut pipe = PipeDrain::new(child.stdout.take().expect("stdout is piped"));
        let _ = child.wait();

        let first = collect(&mut pipe, BUDGET);
        assert_eq!(
            first.len(),
            BUDGET,
            "one pass must stop at its budget, with the payload already buffered"
        );

        // And the remainder is still there: a budget that dropped what it did not
        // return would pass the assertion above and lose output.
        let rest = collect(&mut pipe, 64 * 1024);
        assert_eq!(
            first.len() + rest.len(),
            PAYLOAD + line_ending_len(),
            "the bytes past the budget are kept for the next pass"
        );
    }

    /// What the shell's `echo` appends: `\r\n` under `cmd`, `\n` under `sh`.
    const fn line_ending_len() -> usize {
        if cfg!(windows) {
            2
        } else {
            1
        }
    }
}
