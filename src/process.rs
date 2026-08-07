//! Shared child-process primitives.
//!
//! Both command execution and tunnel supervision spawn children that may create
//! grandchildren, so the platform-specific tree-termination and shell-invocation
//! logic lives here rather than being duplicated per caller.

use std::process::{Child, Command as OsCommand};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// A child together with everything it spawns, held so the whole tree can be
/// killed with one call.
///
/// Both platforms express the same idea with a different kernel object, which is
/// why this is one type rather than the pair of free functions it replaced:
///
/// - **Unix** — the child gets its own session (`setsid`), making its pid a
///   process-group id that `kill(-pgid)` reaches.
/// - **Windows** — the child is assigned to a job object, which
///   `TerminateJobObject` reaches.
///
/// Use it in three steps, in this order: [`prepare`](Self::prepare) before
/// spawning (it may need to modify the command), [`adopt`](Self::adopt) right
/// after, and [`kill`](Self::kill) whenever the tree has to go. A group that was
/// never adopted kills nothing.
///
/// # Why not `taskkill`
///
/// Until 0.21.0 the Windows path shelled out to `taskkill /T /F /PID`. Killing a
/// process by *spawning* one costs what a process spawn costs on that machine,
/// and that cost is neither small nor bounded: **238ms** on a quiet workstation,
/// **6.12s** on that same machine while it was busy, and over **28s** while a
/// parallel build had it loaded. `TerminateJobObject`
/// measured **0.097ms** against the identical children in the same session —
/// roughly three orders of magnitude, and, more to the point, it does not grow
/// with what else the machine is doing.
///
/// This is not a micro-optimisation. The old cost landed inside the response
/// time of every command that reached its deadline, and inside the wall-clock
/// bound of every test that asserted a deadline was enforced.
///
/// A job also closes a hazard the pid-based path carried: a pid can be recycled
/// once the child exits, so "kill the tree at pid N" could reach a tree that is
/// no longer ours. A job names its members directly and cannot be recycled.
///
/// # What this does *not* change
///
/// Membership is not lifetime. The job is created without
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so dropping the handle releases the job
/// and leaves every member running — exactly as before. A command that leaves a
/// background process behind still leaves it behind; only the cost of an
/// explicit kill changed.
#[derive(Debug)]
pub(crate) struct KillGroup {
    /// The child's pid once it exists, 0 before [`adopt`](Self::adopt).
    ///
    /// On Unix this is the group to signal. On Windows it is only the fallback
    /// target for when the job could not be used.
    pid: AtomicU32,
    /// Whether dropping the group should kill whatever is still in it.
    ///
    /// Off unless [`reap_on_drop`](Self::reap_on_drop) turns it on, which is
    /// what makes this type's default behaviour identical to what preceded it.
    reap_on_drop: AtomicBool,
    #[cfg(windows)]
    job: windows_job::Job,
}

impl KillGroup {
    /// Prepare a group for a command that has not been spawned yet.
    ///
    /// Must run before [`OsCommand::spawn`] on Unix, where it installs the
    /// `setsid` hook the group is built on.
    pub(crate) fn prepare(cmd: &mut OsCommand) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: setsid only detaches the child into a new session/group;
            // it touches no shared state in the forked child before exec.
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
        }
        #[cfg(windows)]
        let _ = cmd;

        Self {
            pid: AtomicU32::new(0),
            reap_on_drop: AtomicBool::new(false),
            #[cfg(windows)]
            job: windows_job::Job::create(),
        }
    }

    /// Kill whatever is still in the group when it is dropped.
    ///
    /// This is what turns "the command's descendants are *identified*" into "the
    /// command's descendants are *ended*", and it is off by default because the
    /// difference is visible to callers: a command that deliberately starts a
    /// daemon expects it to outlive the request.
    ///
    /// Drop is the trigger rather than an explicit call at one call site, so
    /// that every way out of the command — the timeout branch, a normal exit, an
    /// early `?` on an I/O error, a panic — reaps the same way. A path that
    /// forgot to call it would leave exactly the processes this exists to stop.
    pub(crate) fn reap_on_drop(&self) {
        self.reap_on_drop.store(true, Ordering::Relaxed);
    }

    /// Take ownership of a freshly spawned child.
    ///
    /// Call this as the statement following `spawn`. On Windows a grandchild
    /// spawned before the assignment would fall outside the job, and the window
    /// in which that is possible is the one between `CreateProcess` returning in
    /// this process and the next call here — the child cannot have finished
    /// loading, let alone run its own `CreateProcess`, in that span.
    pub(crate) fn adopt(&self, child: &Child) {
        self.pid.store(child.id(), Ordering::Relaxed);
        #[cfg(windows)]
        self.job.adopt(child);
    }

    /// Kill the child and every descendant it spawned.
    ///
    /// Harmless when the tree is already gone, and a no-op when nothing was
    /// adopted.
    pub(crate) fn kill(&self) {
        let pid = self.pid.load(Ordering::Relaxed);
        if pid == 0 {
            return;
        }

        #[cfg(windows)]
        {
            if self.job.terminate() {
                return;
            }
            // The kernel refused the job somewhere. Falling back keeps the kill
            // correct at the old cost, which beats a kill that silently does
            // nothing; `Job::create`/`adopt` logged why.
            taskkill_tree(pid);
        }
        #[cfg(unix)]
        {
            // SAFETY: kill with a negative pid targets the process group;
            // harmless if the group is already gone (returns ESRCH).
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
}

impl Drop for KillGroup {
    fn drop(&mut self) {
        if self.reap_on_drop.load(Ordering::Relaxed) {
            // Runs before the fields drop, so on Windows the job handle this
            // needs is still open.
            self.kill();
        }
    }
}

/// The pre-0.21.0 Windows kill, kept only as the fallback in [`KillGroup::kill`].
#[cfg(windows)]
fn taskkill_tree(pid: u32) {
    use std::process::Stdio;

    let _ = OsCommand::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(windows)]
mod windows_job {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject,
    };

    /// An unnamed job object, or nothing when the kernel would not give one.
    pub(super) struct Job {
        handle: HANDLE,
        /// Whether a process actually made it into the job. Terminating a job
        /// nothing was assigned to would report success while killing nothing,
        /// which is the one failure this whole path must not have.
        holds_child: AtomicBool,
    }

    // SAFETY: `handle` is a kernel handle. The three calls made on it here are
    // documented as thread-safe, the handle is never duplicated, and it is
    // closed exactly once, in `Drop`.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl std::fmt::Debug for Job {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Job")
                .field("available", &!self.handle.is_null())
                .field("holds_child", &self.holds_child.load(Ordering::Relaxed))
                .finish()
        }
    }

    /// Whether each degradation has already been reported.
    ///
    /// A job is created per spawned command, so a kernel that refuses one
    /// refuses every one. Warning each time would turn a fixed, systemic
    /// condition into a line per command — the operator learns nothing after the
    /// first and loses the log to it. Once is what "the fast kill is
    /// unavailable" is worth saying.
    static CREATE_WARNED: AtomicBool = AtomicBool::new(false);
    static ASSIGN_WARNED: AtomicBool = AtomicBool::new(false);

    impl Job {
        pub(super) fn create() -> Self {
            // SAFETY: the documented "no security attributes, unnamed" form.
            // The call only allocates a kernel object and returns null on
            // failure, which the rest of this module treats as "no job".
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() && !CREATE_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "could not create a job object; process trees will be killed with taskkill instead, which costs a process spawn per kill. Reported once."
                );
            }
            Self {
                handle,
                holds_child: AtomicBool::new(false),
            }
        }

        pub(super) fn adopt(&self, child: &Child) {
            if self.handle.is_null() {
                return;
            }
            // SAFETY: `handle` is a live job owned by `self`, and the process
            // handle is borrowed from `child`, which outlives this call.
            let assigned =
                unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle() as HANDLE) };
            if assigned == 0 {
                if !ASSIGN_WARNED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "could not assign a child to a job object; its tree will be killed with taskkill instead. Reported once."
                    );
                }
                return;
            }
            self.holds_child.store(true, Ordering::Relaxed);
        }

        /// Returns whether the job was the thing that did the killing.
        pub(super) fn terminate(&self) -> bool {
            if !self.holds_child.load(Ordering::Relaxed) {
                return false;
            }
            // SAFETY: `handle` is a live job owned by `self`. Terminating a job
            // whose members have all exited succeeds and does nothing.
            unsafe { TerminateJobObject(self.handle, 1) != 0 }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            if self.handle.is_null() {
                return;
            }
            // SAFETY: closing a handle this type exclusively owns, once. The
            // job carries no `KILL_ON_JOB_CLOSE` limit, so this releases the
            // job without touching any member process.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Build the platform shell command that runs `command_line` non-interactively.
///
/// On Windows the command line is passed with [`CommandExt::raw_arg`] rather
/// than `arg`. `arg` applies the argument-encoding rules of the C runtime —
/// among them, escaping `"` as `\"` — and `cmd.exe` does not parse its command
/// line that way. The result was that a quote written by the caller arrived at
/// the shell as a literal backslash-quote, so every command needing quoting
/// failed: `dir /b "D:\some\path"` was a syntax error, `powershell -c "a | b"`
/// ran only `a`, and a path containing a space had no working form at all.
/// Measured both ways before choosing; `raw_arg` fixes each of those and leaves
/// unquoted commands byte-identical.
///
/// This grants the caller nothing new. `/execute` hands its string to a shell
/// by definition, so a token holding `exec` could already run anything the
/// account can; what changed is that quoting now means what it says.
///
/// Unix needs no equivalent: `arg` there places the string into `argv` with no
/// encoding step, which is already what `sh -c` expects.
pub(crate) fn shell_command(command_line: &str) -> OsCommand {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut c = OsCommand::new("cmd.exe");
        // Two `raw_arg` calls, and the trailing space in the first, are load
        // bearing: raw arguments are concatenated verbatim, so `/c` and the
        // command must be separated here or they arrive as one token.
        c.raw_arg("/c ").raw_arg(command_line);
        c
    }
    #[cfg(unix)]
    {
        let mut c = OsCommand::new("/bin/sh");
        c.arg("-c").arg(command_line);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn shell_command_runs_a_trivial_command() {
        let output = shell_command("echo shell-tunnel")
            .stdin(Stdio::null())
            .output()
            .expect("shell should be available");
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("shell-tunnel"));
    }

    /// A quote written by the caller must reach the shell as a quote.
    ///
    /// `arg` encodes for the C runtime's parser and turns `"` into `\"`, which
    /// `cmd.exe` does not undo — so the shell saw a literal backslash. This
    /// covers the round trip; `a_quoted_path_is_one_argument` below covers the
    /// case with no workaround.
    #[test]
    fn a_quoted_command_reaches_the_shell_intact() {
        let output = shell_command(r#"echo ["quoted"]"#)
            .stdin(Stdio::null())
            .output()
            .expect("shell should be available");
        let text = String::from_utf8_lossy(&output.stdout);

        // The two shells disagree about what `echo` does with a quote, and the
        // disagreement is what makes each output proof. `cmd.exe` echoes its
        // line verbatim, quotes included. `sh` consumes them as syntax, so the
        // quotes are gone from its output precisely *because* they arrived as
        // quotes — a mangled `\"` would make `sh` print the quote literally,
        // which is the Windows-correct string. Asserting one expectation on
        // both platforms therefore fails on whichever one it was not written
        // for; this test asserted the Windows string and had only ever run on
        // Windows.
        #[cfg(windows)]
        let expected = r#"["quoted"]"#;
        #[cfg(unix)]
        let expected = "[quoted]";

        assert!(
            text.contains(expected),
            "the quote must reach the shell as a quote; wanted {expected:?}, got {text:?}"
        );
        assert!(
            !text.contains(r#"\""#),
            "a backslash the caller never wrote must not appear: {text:?}"
        );
    }

    /// A path in quotes is what quoting exists for, and it is the case with no
    /// workaround: an unquoted path containing a space cannot be expressed at
    /// all. `Cargo.toml` at the crate root is the fixture because it is present
    /// wherever the tests run.
    #[test]
    fn a_quoted_path_is_one_argument() {
        let root = env!("CARGO_MANIFEST_DIR");
        #[cfg(windows)]
        let line = format!(r#"dir /b "{root}\Cargo.toml""#);
        #[cfg(unix)]
        let line = format!(r#"ls "{root}/Cargo.toml""#);

        let output = shell_command(&line)
            .stdin(Stdio::null())
            .output()
            .expect("shell should be available");
        assert!(
            output.status.success(),
            "a quoted path must be understood: {:?} / {:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn killing_a_group_whose_child_already_exited_is_harmless() {
        // Killing a tree that is already gone must not panic or block. Before
        // 0.21.0 this was also the pid-recycling hazard: the pid was all the
        // kill had to go on, and a finished child's pid can be reused.
        let mut cmd = shell_command("exit 0");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let group = KillGroup::prepare(&mut cmd);
        let mut child = cmd.spawn().expect("spawn");
        group.adopt(&child);
        let _ = child.wait();

        group.kill();
    }

    /// Dropping a reaping group ends the tree, and dropping a plain one does not.
    ///
    /// Both halves are asserted here on purpose: the default is a *behaviour
    /// this crate promises*, not merely the absence of a feature, so a change
    /// that started reaping unconditionally has to fail something. Observed
    /// through the inherited pipe, the same way
    /// `a_group_kills_a_background_process_the_command_left_behind` does.
    #[test]
    fn reaping_on_drop_is_opt_in_and_it_works() {
        use std::io::Read;
        use std::sync::mpsc;
        use std::time::Duration;

        // 25 s, not the two minutes the sibling test uses, so the surviving
        // half leaves nothing behind: it exits on its own well after the check.
        // Load can only push that exit *later*, never earlier, so "no EOF yet"
        // cannot become flaky on a busy host.
        #[cfg(windows)]
        let line = r#"start /b powershell -NoProfile -Command "Start-Sleep -Seconds 25""#;
        #[cfg(unix)]
        let line = "sleep 25 &";

        // Returns whether the tree was gone within `wait`.
        fn run(reap: bool, line: &str, wait: Duration) -> bool {
            let mut cmd = shell_command(line);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let group = KillGroup::prepare(&mut cmd);
            if reap {
                group.reap_on_drop();
            }
            let mut child = cmd.spawn().expect("spawn");
            group.adopt(&child);

            let mut pipe = child.stdout.take().expect("piped");
            let _ = child.wait();
            drop(group);

            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut sink = Vec::new();
                let _ = pipe.read_to_end(&mut sink);
                let _ = tx.send(());
            });
            rx.recv_timeout(wait).is_ok()
        }

        assert!(
            run(true, line, Duration::from_secs(20)),
            "a group asked to reap on drop must take the tree with it"
        );
        assert!(
            !run(false, line, Duration::from_secs(5)),
            "a group not asked to reap must leave the background process running: that default is the contract, not an oversight"
        );
    }

    /// The fallback has to stay usable, because nothing else runs it.
    ///
    /// `KillGroup::kill` reaches `taskkill_tree` only when the kernel refused
    /// the job, which no test can provoke on a healthy machine — so the branch
    /// would otherwise be shipped unexecuted. This does not prove the fallback
    /// kills a tree (`taskkill /T` was doing that for every release up to
    /// 0.21.0); it proves the call is still well-formed and returns.
    #[cfg(windows)]
    #[test]
    fn the_taskkill_fallback_still_runs() {
        let mut child = shell_command("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let pid = child.id();
        let _ = child.wait();

        taskkill_tree(pid);
    }

    #[test]
    fn a_group_that_never_adopted_a_child_kills_nothing() {
        // `prepare` runs before `spawn`, so a spawn failure leaves a group with
        // no member. It must be inert rather than reaching for pid 0.
        let mut cmd = shell_command("exit 0");
        let group = KillGroup::prepare(&mut cmd);

        group.kill();
    }

    /// The property the whole type exists for: a background process the command
    /// left running is killed with it.
    ///
    /// Observed through the output pipe rather than by hunting for a pid. A
    /// grandchild inherits the pipe, so the write end stays open for as long as
    /// it lives and the read end cannot reach EOF — the same mechanism that made
    /// the reader threads removed in 0.20.1 hang forever. EOF arriving therefore
    /// *is* the proof that nothing in the tree survived.
    ///
    /// The margin is bought in the command, not in the tolerance: the grandchild
    /// sleeps two minutes, so a tree that survived cannot produce EOF inside the
    /// wait no matter how loaded the host is.
    #[test]
    fn a_group_kills_a_background_process_the_command_left_behind() {
        use std::io::Read;
        use std::sync::mpsc;
        use std::time::Duration;

        // The shell must exit while the grandchild keeps running, which is what
        // `start /b` and a trailing `&` each arrange. `timeout /t` is not usable
        // here — it refuses to run when its output is a pipe.
        #[cfg(windows)]
        let line = r#"start /b powershell -NoProfile -Command "Start-Sleep -Seconds 120""#;
        #[cfg(unix)]
        let line = "sleep 120 &";

        let mut cmd = shell_command(line);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let group = KillGroup::prepare(&mut cmd);
        let mut child = cmd.spawn().expect("spawn");
        group.adopt(&child);

        let mut pipe = child.stdout.take().expect("piped");
        let _ = child.wait();

        group.kill();

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = pipe.read_to_end(&mut sink);
            let _ = tx.send(());
        });

        assert!(
            rx.recv_timeout(Duration::from_secs(20)).is_ok(),
            "the pipe never reached EOF, so something in the tree outlived the kill"
        );
    }
}
