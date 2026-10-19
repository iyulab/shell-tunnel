//! Background processes: commands started now and read later.
//!
//! `execute` waits for its command and returns the output; a session's
//! WebSocket streams it but loses whatever arrives while no one is connected.
//! A handle here is the third shape — start a command, get an id, and read its
//! output by offset whenever convenient, from any connection, for as long as
//! the handle is kept.
//!
//! # Who drains the pipes
//!
//! One watcher thread, for every handle. The `execute` path drains a child from
//! the blocking-pool thread that runs it, and that thread exists only for the
//! command's lifetime; a background process can run for days, and holding a
//! pool slot for it would quietly shrink the slots `execute` and the file API
//! share. So the watcher owns the draining, with the same non-blocking
//! [`PipeDrain`] the control loop uses — no thread attends a pipe, and a
//! grandchild that inherited one cannot pin anything.
//!
//! The watcher parks on a condition variable while nothing runs, so an idle
//! server pays nothing for this module.
//!
//! # Offsets
//!
//! Each stream counts the bytes it has ever produced. An offset names a
//! position in that count, never in a buffer, so it stays valid however much
//! has been discarded since: a read from an offset the ring no longer holds
//! starts at the oldest byte still held and says so (`start > since`), rather
//! than skipping silently.

use std::collections::{BTreeMap, VecDeque};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use super::pipe::{PipeDrain, PipeFeed};
use crate::audit::{AuditEvent, AuditSink, Identity};
use crate::process::{shell_command, KillGroup};

/// How many handles may exist at once, running or kept after exit.
pub const MAX_PROCESSES: usize = 64;

/// Bytes each stream keeps. Older bytes are discarded as new ones arrive.
pub const RING_BYTES: usize = 1024 * 1024;

/// Most input a handle holds for its stdin that the process has not taken yet.
///
/// Twice the largest body the stdin route accepts, so one write can always be
/// queued behind another that is still going in.
pub const STDIN_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// How long a handle is kept after its process ends.
pub const RETAIN_AFTER_EXIT: Duration = Duration::from_secs(3600);

/// How often the watcher drains while anything runs.
const TICK: Duration = Duration::from_millis(20);

/// Bytes drained from one pipe per tick, so one process mid-flood cannot hold
/// the watcher away from the others.
const DRAIN_BUDGET: usize = 256 * 1024;

/// How long output keeps being collected after the process exits — the window
/// for bytes still in the pipe. A grandchild holding the pipe past it is cut
/// off, as on the `execute` path.
const COLLECT_GRACE: Duration = Duration::from_millis(500);

/// One stream's retained bytes and the count of every byte it ever produced.
#[derive(Debug, Default)]
struct Ring {
    bytes: VecDeque<u8>,
    /// Offset one past the newest byte.
    end: u64,
}

impl Ring {
    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend(chunk);
        self.end += chunk.len() as u64;
        let excess = self.bytes.len().saturating_sub(RING_BYTES);
        self.bytes.drain(..excess);
    }

    /// Offset of the oldest byte still held.
    fn start(&self) -> u64 {
        self.end - self.bytes.len() as u64
    }

    /// Up to `max` bytes from `since`, and the offset they begin at — later
    /// than `since` when the bytes in between were discarded.
    fn read(&self, since: u64, max: usize) -> (u64, Vec<u8>) {
        let from = since.clamp(self.start(), self.end);
        let skip = (from - self.start()) as usize;
        let data = self.bytes.iter().skip(skip).take(max).copied().collect();
        (from, data)
    }
}

/// Which output stream a read is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// A signal a caller may send to a handle's process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Ask it to stop: `SIGTERM` on Unix. Windows has no such request for a
    /// console-less process, so there it ends the group as `Kill` does.
    Terminate,
    /// End it now: `SIGKILL` to the group on Unix, the job terminated on Windows.
    Kill,
    /// `SIGINT`, as Ctrl-C would. Unix only.
    Interrupt,
}

/// Why a request about a handle was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessError {
    /// No handle with that id (never existed, deleted, or expired).
    NotFound,
    /// [`MAX_PROCESSES`] handles exist already.
    TooMany,
    /// The process has already exited.
    NotRunning,
    /// stdin was not opened at start, or has been closed — by a caller, or by
    /// the process itself.
    StdinUnavailable,
    /// More input is queued than [`STDIN_QUEUE_BYTES`] allows; what is queued
    /// has to be taken by the process first.
    StdinBacklogFull,
    /// This platform cannot deliver the signal.
    SignalUnsupported,
    /// The OS refused: spawn, write, or signal.
    Io(String),
}

/// What a caller sees of one handle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessInfo {
    pub id: u64,
    pub command: String,
    pub pid: u32,
    /// `running` or `exited`.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<u64>,
    /// Offset one past the newest byte of each stream.
    pub stdout_end: u64,
    pub stderr_end: u64,
    /// Offset of the oldest byte each stream still holds.
    pub stdout_start: u64,
    pub stderr_start: u64,
    /// Whether no more output can arrive.
    pub output_complete: bool,
    pub stdin_open: bool,
    /// Input written to stdin that the process has not taken yet.
    pub stdin_pending: u64,
}

/// How a stdin write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdinWrite {
    /// Bytes of this write — and of any queued before it — that the process
    /// had not taken when the wait ended. Zero means all of it is in the pipe.
    pub pending: u64,
}

/// One read of a stream.
#[derive(Debug, Clone)]
pub struct OutputRead {
    /// Offset of the first byte in `data` — later than the requested one when
    /// bytes in between were discarded.
    pub start: u64,
    pub data: Vec<u8>,
    /// Offset to ask for next.
    pub next: u64,
    /// Whether this stream will produce nothing more.
    pub complete: bool,
}

/// What a caller asks to start.
#[derive(Debug, Clone, Default)]
pub struct StartRequest {
    pub command: String,
    pub working_dir: Option<String>,
    pub env: Vec<(String, String)>,
    /// Keep a pipe to the process's stdin; otherwise stdin is empty.
    pub stdin: bool,
}

struct Proc {
    command: String,
    pid: u32,
    started: Instant,
    started_at_ms: u64,
    ended: Option<Instant>,
    ended_at_ms: Option<u64>,
    exit_code: Option<i32>,
    child: Option<Child>,
    group: KillGroup,
    stdout_pipe: Option<PipeDrain<ChildStdout>>,
    stderr_pipe: Option<PipeDrain<ChildStderr>>,
    /// `None` when stdin was not requested. Fed by the watcher.
    stdin: Option<PipeFeed<ChildStdin>>,
    stdout: Ring,
    stderr: Ring,
}

impl Proc {
    fn running(&self) -> bool {
        self.exit_code.is_none() && self.child.is_some()
    }

    fn pipes_done(&self) -> bool {
        self.stdout_pipe.as_ref().map_or(true, |p| p.finished())
            && self.stderr_pipe.as_ref().map_or(true, |p| p.finished())
    }

    fn info(&self, id: u64) -> ProcessInfo {
        ProcessInfo {
            id,
            command: self.command.clone(),
            pid: self.pid,
            state: if self.running() { "running" } else { "exited" },
            exit_code: self.exit_code,
            started_at_ms: self.started_at_ms,
            ended_at_ms: self.ended_at_ms,
            stdout_end: self.stdout.end,
            stderr_end: self.stderr.end,
            stdout_start: self.stdout.start(),
            stderr_start: self.stderr.start(),
            output_complete: !self.running() && self.pipes_done(),
            stdin_open: self.stdin.as_ref().is_some_and(|f| f.is_open()),
            stdin_pending: self.stdin.as_ref().map_or(0, |f| f.pending() as u64),
        }
    }

    fn ring(&self, stream: Stream) -> &Ring {
        match stream {
            Stream::Stdout => &self.stdout,
            Stream::Stderr => &self.stderr,
        }
    }
}

#[derive(Default)]
struct Table {
    procs: BTreeMap<u64, Proc>,
    next_id: u64,
}

struct Inner {
    table: Mutex<Table>,
    /// Wakes the watcher when a process starts.
    wake: Condvar,
    /// Wakes readers waiting for output or an exit.
    changed: tokio::sync::Notify,
    audit: RwLock<Arc<AuditSink>>,
    kill_orphans: AtomicBool,
    watcher_started: AtomicBool,
}

/// Every background process this server started, and the thread that drains
/// them.
#[derive(Clone)]
pub struct ProcessTable {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ProcessTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessTable")
            .field("running", &self.running_count())
            .finish()
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                table: Mutex::new(Table::default()),
                wake: Condvar::new(),
                changed: tokio::sync::Notify::new(),
                audit: RwLock::new(Arc::new(AuditSink::Disabled)),
                kill_orphans: AtomicBool::new(false),
                watcher_started: AtomicBool::new(false),
            }),
        }
    }

    /// Where `process.exit` is recorded — the watcher records it, not a request.
    pub fn set_audit(&self, sink: Arc<AuditSink>) {
        if let Ok(mut audit) = self.inner.audit.write() {
            *audit = sink;
        }
    }

    /// Whether what a process leaves running is ended when it exits — the same
    /// rule `--kill-orphans` sets for `execute`.
    pub fn set_kill_orphans(&self, kill: bool) {
        self.inner.kill_orphans.store(kill, Ordering::Relaxed);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many processes are running now. An updater counts these as work in
    /// flight: a restart would end them.
    pub fn running_count(&self) -> usize {
        self.lock().procs.values().filter(|p| p.running()).count()
    }

    /// Start `request.command` through the platform shell and return its id.
    pub fn start(
        &self,
        request: &StartRequest,
        identity: Option<Identity>,
    ) -> Result<ProcessInfo, ProcessError> {
        let mut table = self.lock();
        sweep_expired(&mut table);
        if table.procs.len() >= MAX_PROCESSES {
            return Err(ProcessError::TooMany);
        }

        let mut cmd = shell_command(&request.command);
        cmd.stdin(if request.stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        if let Some(dir) = &request.working_dir {
            cmd.current_dir(dir);
        }
        for (key, value) in &request.env {
            cmd.env(key, value);
        }
        let group = KillGroup::prepare(&mut cmd);
        // The group dies with its handle unless the process exits on its own
        // first (then `--kill-orphans` decides) — so a handle deleted, or a
        // table dropped at shutdown, never leaves a process nobody can reach.
        group.reap_on_drop();
        let mut child = cmd.spawn().map_err(|e| ProcessError::Io(e.to_string()))?;
        group.adopt(&child);
        let stdin = match child.stdin.take().map(PipeFeed::open).transpose() {
            Ok(feed) => feed,
            Err(e) => {
                // Not run on a blocking write end: that is the thread this
                // feed exists to avoid.
                group.kill();
                let _ = child.wait();
                return Err(ProcessError::Io(e.to_string()));
            }
        };

        let id = table.next_id;
        table.next_id += 1;
        let proc = Proc {
            command: request.command.clone(),
            pid: child.id(),
            started: Instant::now(),
            started_at_ms: now_ms(),
            ended: None,
            ended_at_ms: None,
            exit_code: None,
            stdout_pipe: child.stdout.take().map(PipeDrain::new),
            stderr_pipe: child.stderr.take().map(PipeDrain::new),
            stdin,
            child: Some(child),
            group,
            stdout: Ring::default(),
            stderr: Ring::default(),
        };
        let info = proc.info(id);
        table.procs.insert(id, proc);
        drop(table);

        self.record(
            AuditEvent::new("process.start")
                .with_identity(identity)
                .with_route("POST /api/v1/processes")
                .with_command(&request.command)
                .with_process(id),
        );
        self.ensure_watcher();
        self.inner.wake.notify_all();
        Ok(info)
    }

    pub fn list(&self) -> Vec<ProcessInfo> {
        let mut table = self.lock();
        sweep_expired(&mut table);
        table.procs.iter().map(|(id, p)| p.info(*id)).collect()
    }

    pub fn info(&self, id: u64) -> Result<ProcessInfo, ProcessError> {
        let table = self.lock();
        table
            .procs
            .get(&id)
            .map(|p| p.info(id))
            .ok_or(ProcessError::NotFound)
    }

    /// Read without waiting.
    pub fn read(
        &self,
        id: u64,
        stream: Stream,
        since: u64,
        max: usize,
    ) -> Result<OutputRead, ProcessError> {
        let table = self.lock();
        let proc = table.procs.get(&id).ok_or(ProcessError::NotFound)?;
        let ring = proc.ring(stream);
        let (start, data) = ring.read(since, max);
        let next = start + data.len() as u64;
        let pipe_done = match stream {
            Stream::Stdout => proc.stdout_pipe.as_ref().map_or(true, |p| p.finished()),
            Stream::Stderr => proc.stderr_pipe.as_ref().map_or(true, |p| p.finished()),
        };
        Ok(OutputRead {
            start,
            data,
            next,
            complete: pipe_done && !proc.running() && next == ring.end,
        })
    }

    /// Read, waiting up to `wait` for something to read when there is nothing
    /// yet — a long-poll. Returns at once when there is data, when the stream
    /// is complete, or when the handle goes away.
    pub async fn read_wait(
        &self,
        id: u64,
        stream: Stream,
        since: u64,
        max: usize,
        wait: Duration,
    ) -> Result<OutputRead, ProcessError> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            // Registered before the check, so a change between the check and
            // the wait still wakes this reader.
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let read = self.read(id, stream, since, max)?;
            if !read.data.is_empty() || read.complete {
                return Ok(read);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Ok(read);
            }
        }
    }

    /// Queue `bytes` for the process's stdin, close it after if `close`, and
    /// wait up to `wait` for the process to take them.
    ///
    /// The bytes are written by the watcher, without blocking, as the pipe
    /// takes them — never by a thread parked in `write`, which a process that
    /// does not read (or a grandchild holding its stdin) would hold forever.
    /// The wait is async and costs nothing while it lasts; when it ends with
    /// input still queued, the input stays queued and [`StdinWrite::pending`]
    /// says how much.
    pub async fn write_stdin(
        &self,
        id: u64,
        bytes: &[u8],
        close: bool,
        identity: Option<Identity>,
        wait: Duration,
    ) -> Result<StdinWrite, ProcessError> {
        // Taken through this offset, the process has everything up to and
        // including this write.
        let target = {
            let mut table = self.lock();
            let proc = table.procs.get_mut(&id).ok_or(ProcessError::NotFound)?;
            if !proc.running() {
                return Err(ProcessError::NotRunning);
            }
            let feed = proc
                .stdin
                .as_mut()
                .filter(|f| f.is_open())
                .ok_or(ProcessError::StdinUnavailable)?;
            if feed.pending() + bytes.len() > STDIN_QUEUE_BYTES {
                return Err(ProcessError::StdinBacklogFull);
            }
            feed.push(bytes);
            let target = feed.accepted() + feed.pending() as u64;
            if close {
                feed.close_when_drained();
            }
            target
        };
        self.record(
            AuditEvent::new("process.stdin")
                .with_identity(identity)
                .with_route("POST /api/v1/processes/{id}/stdin")
                .with_process(id)
                .with_bytes(bytes.len() as u64),
        );
        self.inner.wake.notify_all();

        let deadline = tokio::time::Instant::now() + wait;
        loop {
            // Registered before the check, as in `read_wait`.
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let table = self.lock();
                let proc = table.procs.get(&id).ok_or(ProcessError::NotFound)?;
                let feed = proc.stdin.as_ref().ok_or(ProcessError::StdinUnavailable)?;
                let accepted = feed.accepted();
                if accepted >= target {
                    return Ok(StdinWrite { pending: 0 });
                }
                if !feed.is_open() {
                    // Closed with this input still queued: it is gone.
                    return Err(if proc.running() {
                        ProcessError::StdinUnavailable
                    } else {
                        ProcessError::NotRunning
                    });
                }
                if tokio::time::Instant::now() >= deadline {
                    return Ok(StdinWrite {
                        pending: target - accepted,
                    });
                }
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
    }

    pub fn signal(
        &self,
        id: u64,
        signal: Signal,
        identity: Option<Identity>,
    ) -> Result<(), ProcessError> {
        {
            let table = self.lock();
            let proc = table.procs.get(&id).ok_or(ProcessError::NotFound)?;
            if !proc.running() {
                return Err(ProcessError::NotRunning);
            }
            match signal {
                Signal::Kill => proc.group.kill(),
                #[cfg(unix)]
                Signal::Terminate => proc.group.signal(libc::SIGTERM),
                #[cfg(unix)]
                Signal::Interrupt => proc.group.signal(libc::SIGINT),
                #[cfg(windows)]
                Signal::Terminate => proc.group.kill(),
                #[cfg(windows)]
                Signal::Interrupt => return Err(ProcessError::SignalUnsupported),
            }
        }
        let name = match signal {
            Signal::Terminate => "terminate",
            Signal::Kill => "kill",
            Signal::Interrupt => "interrupt",
        };
        self.record(
            AuditEvent::new("process.signal")
                .with_identity(identity)
                .with_route("POST /api/v1/processes/{id}/signal")
                .with_process(id)
                .with_reason(name),
        );
        self.inner.wake.notify_all();
        Ok(())
    }

    /// Forget a handle, ending its process group first if it still runs.
    ///
    /// Blocking: waits for an ended process to be reaped.
    pub fn delete(&self, id: u64, identity: Option<Identity>) -> Result<(), ProcessError> {
        let proc = self
            .lock()
            .procs
            .remove(&id)
            .ok_or(ProcessError::NotFound)?;
        let was_running = proc.running();
        finish(proc);
        self.record(
            AuditEvent::new("process.delete")
                .with_identity(identity)
                .with_route("DELETE /api/v1/processes/{id}")
                .with_process(id)
                .with_reason(if was_running { "ended" } else { "removed" }),
        );
        self.inner.changed.notify_waiters();
        Ok(())
    }

    /// End every process and forget every handle — for server shutdown. A
    /// handle does not outlive the server, and neither should what it started.
    pub fn shutdown(&self) {
        let procs = std::mem::take(&mut self.lock().procs);
        for (id, proc) in procs {
            // Only the ones this ends: a process that already exited was
            // recorded by the watcher as `process.exit`.
            if proc.running() {
                self.record(
                    AuditEvent::new("process.delete")
                        .with_process(id)
                        .with_reason("server-stopping"),
                );
            }
            finish(proc);
        }
        self.inner.changed.notify_waiters();
    }

    /// A guard that runs [`Self::shutdown`] when dropped — held by the server
    /// for as long as it serves, so every way out of serving ends what the
    /// handles started, a stop request that drops the serving future included.
    pub fn shutdown_on_drop(&self) -> ShutdownGuard {
        ShutdownGuard(self.clone())
    }

    fn record(&self, event: AuditEvent) {
        let sink = self
            .inner
            .audit
            .read()
            .map(|a| Arc::clone(&a))
            .unwrap_or_else(|_| Arc::new(AuditSink::Disabled));
        sink.record(event);
    }

    fn ensure_watcher(&self) {
        if self.inner.watcher_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        let spawned = std::thread::Builder::new()
            .name("process-watcher".into())
            .spawn(move || watch(weak));
        if spawned.is_err() {
            self.inner.watcher_started.store(false, Ordering::Release);
        }
    }
}

/// Ends every background process when dropped; see
/// [`ProcessTable::shutdown_on_drop`].
pub struct ShutdownGuard(ProcessTable);

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// End a handle's process group, if it still runs, and reap the leader.
fn finish(mut proc: Proc) {
    if let Some(mut child) = proc.child.take() {
        if proc.exit_code.is_none() {
            proc.group.kill();
        }
        let _ = child.wait();
    }
    // Dropping `proc` drops the group, which reaps whatever is left when the
    // flag is still set.
}

/// Remove handles whose process ended more than [`RETAIN_AFTER_EXIT`] ago.
fn sweep_expired(table: &mut Table) {
    let expired: Vec<u64> = table
        .procs
        .iter()
        .filter(|(_, p)| p.ended.is_some_and(|e| e.elapsed() >= RETAIN_AFTER_EXIT))
        .map(|(id, _)| *id)
        .collect();
    for id in expired {
        if let Some(proc) = table.procs.remove(&id) {
            finish(proc);
        }
    }
}

/// The watcher: drain every live pipe, reap exits, sleep while nothing runs.
fn watch(weak: Weak<Inner>) {
    loop {
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let mut changed = false;
        let mut exits: Vec<(u64, Option<i32>, u64, u64)> = Vec::new();
        let kill_orphans = inner.kill_orphans.load(Ordering::Relaxed);
        let mut table = inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut active = false;
        for (id, proc) in table.procs.iter_mut() {
            let Proc {
                stdout_pipe,
                stderr_pipe,
                stdout,
                stderr,
                stdin: stdin_feed,
                ..
            } = proc;
            if let Some(feed) = stdin_feed.as_mut() {
                let was_open = feed.is_open();
                // A write waiting on this input is woken by progress, and by
                // the pipe closing under it.
                changed |= feed.feed(DRAIN_BUDGET) > 0 || was_open != feed.is_open();
            }
            if let Some(pipe) = stdout_pipe.as_mut() {
                changed |= pipe.drain(DRAIN_BUDGET, &mut |chunk| stdout.push(chunk)) > 0;
            }
            if let Some(pipe) = stderr_pipe.as_mut() {
                changed |= pipe.drain(DRAIN_BUDGET, &mut |chunk| stderr.push(chunk)) > 0;
            }

            if proc.exit_code.is_none() {
                if let Some(child) = proc.child.as_mut() {
                    if let Ok(Some(status)) = child.try_wait() {
                        // A process ended by a signal has no code; -1 marks
                        // "ended, no exit code" so `running` stays false.
                        proc.exit_code = Some(status.code().unwrap_or(-1));
                        proc.ended = Some(Instant::now());
                        proc.ended_at_ms = Some(now_ms());
                        // What is still queued has nobody left to read it.
                        if let Some(feed) = proc.stdin.as_mut() {
                            feed.release();
                        }
                        if kill_orphans {
                            proc.group.kill();
                        } else {
                            proc.group.keep_on_drop();
                        }
                        changed = true;
                        exits.push((
                            *id,
                            status.code(),
                            proc.started.elapsed().as_millis() as u64,
                            proc.stdout.end + proc.stderr.end,
                        ));
                    }
                }
            }

            if proc.exit_code.is_some() && !proc.pipes_done() {
                // Bytes still in the pipe are collected for a short grace; a
                // grandchild holding it past that is cut off.
                if proc.ended.is_some_and(|e| e.elapsed() >= COLLECT_GRACE) {
                    if let Some(p) = proc.stdout_pipe.as_mut() {
                        p.release();
                    }
                    if let Some(p) = proc.stderr_pipe.as_mut() {
                        p.release();
                    }
                    changed = true;
                }
            }
            active |= proc.running() || !proc.pipes_done();
        }
        sweep_expired(&mut table);

        if !exits.is_empty() {
            drop(table);
            let sink = inner
                .audit
                .read()
                .map(|a| Arc::clone(&a))
                .unwrap_or_else(|_| Arc::new(AuditSink::Disabled));
            for (id, code, duration_ms, bytes) in exits {
                sink.record(
                    AuditEvent::new("process.exit")
                        .with_process(id)
                        .with_outcome(code, false, duration_ms)
                        .with_bytes(bytes),
                );
            }
            table = inner
                .table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if changed {
            inner.changed.notify_waiters();
        }

        if active {
            drop(table);
            drop(inner);
            std::thread::sleep(TICK);
        } else {
            // Nothing to drain: park until a start wakes us. The timeout lets
            // the thread notice the table being dropped and lets the retention
            // sweep run on an idle server.
            // The guard comes back and is dropped at the end of this block,
            // before `inner` is — the thread holds the table only while
            // deciding, never while parked.
            let _ = inner.wake.wait_timeout(table, Duration::from_secs(60));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ring_keeps_the_newest_bytes_and_counts_every_one() {
        let mut ring = Ring::default();
        ring.push(&vec![b'a'; RING_BYTES]);
        ring.push(b"xyz");
        assert_eq!(ring.end, RING_BYTES as u64 + 3);
        assert_eq!(ring.start(), 3);
        let (start, data) = ring.read(0, 2);
        assert_eq!(
            start, 3,
            "a discarded offset reads from the oldest byte held"
        );
        assert_eq!(data, b"aa");
        let (start, data) = ring.read(RING_BYTES as u64, 10);
        assert_eq!((start, data.as_slice()), (RING_BYTES as u64, &b"xyz"[..]));
        let (start, data) = ring.read(u64::MAX, 10);
        assert_eq!((start, data.len()), (ring.end, 0));
    }
}
