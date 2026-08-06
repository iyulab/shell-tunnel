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

use std::io::{self, Read};

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

/// Switch a descriptor to non-blocking, reporting whether it took.
#[cfg(unix)]
fn set_nonblocking<R: PipeSource>(reader: &R) -> bool {
    // No `use` for `AsRawFd`: the method is in scope through `PipeSource`'s own
    // bound. Importing it as well is an unused import, and `clippy-all` runs
    // with `-D warnings` — which would have failed CI's Lint job on Unix only,
    // where this branch is the one that compiles.
    let fd = reader.as_raw_fd();
    // SAFETY: `fd` is owned by `reader` and live for this call; both `fcntl`
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
    #[test]
    fn a_pass_stops_at_its_budget() {
        #[cfg(windows)]
        let line = "powershell -NoProfile -Command [Console]::Out.Write(('x'*20000))";
        #[cfg(unix)]
        let line = "head -c 20000 /dev/zero | tr '\\0' x";

        let mut child = shell_command(line)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let mut pipe = PipeDrain::new(child.stdout.take().expect("stdout is piped"));

        // Wait for bytes to actually be available, so the assertion is about the
        // budget rather than about a pipe that had not filled yet.
        let mut first = Vec::new();
        for _ in 0..400 {
            first = collect(&mut pipe, 1024);
            if !first.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert!(!first.is_empty(), "the command produced no output at all");
        assert!(
            first.len() <= 1024,
            "one pass must not exceed its budget: took {}",
            first.len()
        );

        let _ = child.kill();
        let _ = child.wait();
    }
}
