//! In-flight upload sessions.
//!
//! Bytes land in a staging file and are renamed into place only after the whole
//! transfer verifies. A partial file therefore never appears at the destination
//! — a consumer polling that path sees nothing or sees the finished article.

use std::collections::{HashMap, HashSet};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::fs::sha256::Hasher;
use crate::fs::UPLOAD_DIR;

/// Chunk size advertised to clients, and the ceiling a chunk may not exceed.
///
/// Four rather than eight MiB: the relay's body ceiling is 8 MiB
/// (`relay::MAX_BODY`) and a WebSocket frame plus a JSON header ride on top, so
/// sitting on the ceiling turns a 413 into a one-byte accident. The relay's
/// 120s request timeout is also tight for 8 MiB over a slow link.
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Largest value `--fs-chunk-size` may name. At or above the relay's ceiling
/// every relayed transfer would 413, and the symptom looks like a server bug.
pub const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// How long a session may sit idle before it is swept.
pub const SESSION_TTL: Duration = Duration::from_secs(3600);

/// Largest number of upload sessions this process holds open at once.
///
/// A session holds an open file handle for up to `SESSION_TTL` (an hour). The
/// only credential `POST /uploads` requires is `fs.write` — so without a cap,
/// a token scoped to nothing but `fs.write` could open enough sessions to
/// exhaust the process's file descriptors, and fd exhaustion is process-wide:
/// it would degrade `exec` and `session` routes too, which that token has no
/// capability over at all. That makes this a capability-boundary issue, not
/// merely a disk-quota one, so it belongs in this endpoint rather than being
/// left to an operator-configured limit nobody has asked for yet.
///
/// 128 is a fixed constant rather than a CLI knob: generous enough that no
/// legitimate concurrent-upload workload should hit it, small enough that the
/// worst case (128 open file handles) is nowhere near typical per-process fd
/// limits (1024+ on Linux, comparable on Windows). Not configurable — YAGNI
/// until an operator actually needs a different number.
const MAX_CONCURRENT_UPLOADS: usize = 128;

/// Why an upload operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// No such session (unknown id, or already completed/cancelled/expired).
    NotFound,
    /// The chunk did not start where the session expects.
    OffsetMismatch { expected: u64 },
    /// Another live session already targets this destination.
    Conflict,
    /// The chunk exceeds the advertised chunk size.
    TooLarge,
    /// This chunk would push the session past the size declared at creation.
    SizeExceeded,
    /// Too many sessions are already open (see `MAX_CONCURRENT_UPLOADS`).
    TooManySessions,
    /// The assembled bytes do not hash to what was declared.
    Checksum {
        expected: String,
        actual: String,
        /// The destination the rejected session was headed for. Widened for
        /// this field for the same reason `UploadStore::cancel`'s return
        /// type was: an audit event for a terminal upload outcome should be
        /// able to name its subject. `dest_rel` is not consumed before this
        /// variant is built — `take_for_complete` only borrows it (for
        /// `self.release(&dest_rel)`) beforehand — so there was never a
        /// reason it could not be carried here; the field was simply never
        /// added.
        dest_rel: String,
    },
    /// The filesystem refused.
    Io {
        /// Already-rendered detail (`ToString` of the underlying
        /// `io::Error`). A `String`, not the `io::Error` itself: `UploadError`
        /// derives `Clone`/`PartialEq`/`Eq`, neither of which `io::Error`
        /// implements.
        detail: String,
        /// The underlying `io::Error`'s `raw_os_error()`, carried alongside
        /// `detail` so a caller can tell ENOSPC apart from an unrelated
        /// failure without a locale-dependent match on the rendered message
        /// — see `platform::is_out_of_space`, which `upload_error_response`
        /// (`src/api/fs.rs`) uses this to answer.
        raw_os_error: Option<i32>,
    },
}

impl From<std::io::Error> for UploadError {
    fn from(e: std::io::Error) -> Self {
        UploadError::Io {
            raw_os_error: e.raw_os_error(),
            detail: e.to_string(),
        }
    }
}

/// A session whose bytes are all in and whose digest has been computed.
#[derive(Debug, Clone)]
pub struct FinishedUpload {
    pub dest_rel: String,
    pub part_path: PathBuf,
    pub bytes: u64,
    pub digest: String,
    pub expected: String,
}

/// One in-flight upload.
struct Session {
    dest_rel: String,
    /// Absolute canonicalized path to the staging file. Always built from a
    /// canonical prefix (the staging directory derived from an absolute
    /// destination). `has_live_part_under` compares this against caller-supplied
    /// input using `starts_with`, which requires both paths to be canonical.
    /// Building `part_path` from a non-canonicalized destination path would
    /// break that comparison silently, causing the query to return `false` even
    /// when a session is actually under the queried directory.
    part_path: PathBuf,
    declared_size: u64,
    declared_sha256: String,
    offset: u64,
    hasher: Hasher,
    file: std::fs::File,
    touched: Instant,
}

/// All in-flight uploads for this process.
///
/// State lives in memory only. A restart loses sessions and the client starts
/// over; persisting them would mean reconstructing a partial hash across
/// processes, which is a durability feature nobody has asked for yet. The
/// staging files a restart leaves behind are swept on startup
/// (`sweep_orphan_parts`).
///
/// Invariant: no method ever holds the `sessions` lock and the `claimed`
/// lock at the same time. `create` takes `claimed` (in its own block, which
/// closes before anything else runs) and only later, separately, takes
/// `sessions`; `cancel`, `sweep`, and `take_for_complete` take `sessions`
/// first and always drop that guard — explicitly, where it is not the last
/// use in the enclosing statement — before reaching `claimed` through
/// `release`/`release_destination`. That the two methods' orderings are
/// opposite (`claimed` before `sessions` in one, `sessions` before `claimed`
/// in the other) would be a textbook two-lock deadlock *if* either ever held
/// both at once; because neither does, the orderings never actually nest and
/// there is nothing to cycle on. Preserving this is what makes `sessions`
/// vs. `claimed` safe to reason about independently of `append`'s
/// documented (non-deadlocking) contention with `sweep` — see `append`'s
/// doc comment for that argument. Breaking this invariant — folding a
/// `claimed` access inside a still-held `sessions` guard, or vice versa —
/// would reintroduce a real deadlock that no existing test would catch.
pub struct UploadStore {
    sessions: RwLock<HashMap<String, Mutex<Session>>>,
    /// Destinations currently claimed, so two sessions cannot race to one path.
    ///
    /// A set, not a map: no caller has ever read a value out of this (an
    /// earlier version stored the claiming session's id as the value, but
    /// nothing looked it up — `sessions` is the source of truth for which
    /// id owns which destination). Its length also doubles as the
    /// live-session count for `MAX_CONCURRENT_UPLOADS`: every live session
    /// claims exactly one destination and every destination is claimed by
    /// at most one session, so checking `claimed.len()` under `claimed`'s
    /// own lock is an atomic admission check — two concurrent callers
    /// cannot both read a count under the cap and then both insert, because
    /// the check and the insert share one critical section.
    claimed: Mutex<HashSet<String>>,
    chunk_size: usize,
    counter: std::sync::atomic::AtomicU64,
}

impl UploadStore {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            claimed: Mutex::new(HashSet::new()),
            // Upper bound one *less* than `MAX_CHUNK_SIZE`, matching what
            // `--fs-chunk-size`'s own startup check enforces (`main.rs`
            // exits for `size >= MAX_CHUNK_SIZE`). Clamping to
            // `MAX_CHUNK_SIZE` itself (an earlier version did) is not
            // reachable through the CLI today, but it is worse than
            // unreachable: it would silently *accept* exactly the value the
            // CLI's own check exists to refuse, for any future caller that
            // constructs a store directly rather than through the CLI.
            chunk_size: chunk_size.clamp(1, MAX_CHUNK_SIZE - 1),
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The chunk size clients are told to use.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Where staging files live for an upload landing at `dest_abs`.
    ///
    /// Inside a jail that is one directory at the root, as it has always been.
    /// Machine-wide there is no single place it could be: `complete` publishes
    /// by `rename`, which is only atomic within a filesystem, so staging has to
    /// sit on the same one as the destination. Windows makes this unavoidable
    /// rather than merely preferable — a staging directory on `C:` cannot be
    /// renamed onto `D:` at all.
    ///
    /// Taking the destination's own parent, rather than the volume root, keeps
    /// that guarantee on Unix too, where a mount point below `/` is a different
    /// filesystem and `/` is usually not writable by the account running this.
    ///
    /// The cost is that machine-wide staging is no longer one enumerable
    /// directory, which is what `sweep_orphan_parts` needs — see its doc.
    pub fn staging_dir(root: &crate::fs::FsRoot, dest_abs: &Path) -> PathBuf {
        match root.jail_path() {
            Some(jail) => jail.join(UPLOAD_DIR),
            None => match dest_abs.parent() {
                Some(parent) => parent.join(UPLOAD_DIR),
                // A destination with no parent is a filesystem anchor, which
                // `resolve_for_create` already refuses as a create target.
                None => PathBuf::from(UPLOAD_DIR),
            },
        }
    }

    /// 살아있는 세션 중 스테이징 파일이 `dir` 아래에 있는 것이 하나라도 있는가.
    ///
    /// 트리 삭제가 진행 중인 업로드를 지우지 않기 위한 조회다. 근거는 **세션
    /// 목록이지 디스크가 아니다**: 이전 실행이 남긴 고아 `.part`는 아무도
    /// 소유하지 않으므로 "살아있음"이 아니고, 그것까지 살아있다고 답하면
    /// 스윕이 아직 닿지 않은 트리가 무기한 삭제 불가가 된다.
    ///
    /// `sessions` 락만 잡는다. `claimed`을 함께 잡으면 이 타입의 락 불변식이
    /// 깨진다 — 그 이유는 `UploadStore`의 doc comment에 있다.
    /// 살아있는 세션 중 스테이징 파일이 `dir` 아래에 있는 것이 하나라도 있는가.
    ///
    /// 트리 삭제가 진행 중인 업로드를 지우지 않기 위한 조회다. 근거는 **세션
    /// 목록이지 디스크가 아니다**: 이전 실행이 남긴 고아 `.part`는 아무도
    /// 소유하지 않으므로 "살아있음"이 아니고, 그것까지 살아있다고 답하면
    /// 스윕이 아직 닿지 않은 트리가 무기한 삭제 불가가 된다.
    ///
    /// `sessions` 락만 잡는다. `claimed`을 함께 잡으면 이 타입의 락 불변식이
    /// 깨진다 — 그 이유는 `UploadStore`의 doc comment에 있다.
    pub fn has_live_part_under(&self, dir: &Path) -> bool {
        let Ok(sessions) = self.sessions.read() else {
            // 락이 오염됐다면 "없다"고 답할 근거가 없다. 삭제를 막는 쪽이
            // 안전하다 — 이 조회의 유일한 소비자가 그렇게 쓴다.
            return true;
        };
        // 캐노니칼화 실패(경로가 존재하지 않음 등)는 안전하게 "있다"고 답한다.
        // `part_path`는 항상 정규화된 절대경로이고, 정규화되지 않은 경로와는
        // 비교할 수 없다. 확인할 수 없는 경우 삭제를 막는 쪽이 안전하다
        // — 이것은 위의 락 오염 처리와 동일한 입장이다.
        let Ok(canonical_dir) = std::fs::canonicalize(dir) else {
            return true;
        };
        sessions.values().any(|session| {
            session
                .lock()
                .map(|s| s.part_path.starts_with(&canonical_dir))
                .unwrap_or(true)
        })
    }

    /// Open a session for `dest_rel`, which need not exist yet.
    ///
    /// Does *not* sweep expired sessions itself, even opportunistically — an
    /// earlier version did, right here, before anything else ran. That
    /// silently discarded whatever session the sweep reclaimed: `UploadStore`
    /// has no `AuditSink` to record with, so a sweep run from inside this
    /// method structurally cannot leave a trail. The caller
    /// (`create_upload_blocking`, `src/api/fs.rs`) now sweeps via the
    /// audit-aware `sweep_expired_uploads` immediately before calling this,
    /// preserving the ordering the old internal call existed for: reclaim
    /// stale capacity before the cap check below runs, so a session old
    /// enough to matter is freed the moment somebody next asks for a new one
    /// — the same guarantee, just recorded now instead of silent.
    pub fn create(
        &self,
        root: &crate::fs::FsRoot,
        dest_abs: &Path,
        dest_rel: String,
        size: u64,
        sha256: String,
    ) -> Result<String, UploadError> {
        // Claim the destination first: a second session for the same path is a
        // silent-overwrite race, and last-writer-wins loses data quietly.
        {
            let mut claimed = self.claimed.lock().map_err(|_| poisoned())?;
            if claimed.contains(&dest_rel) {
                return Err(UploadError::Conflict);
            }
            if claimed.len() >= MAX_CONCURRENT_UPLOADS {
                return Err(UploadError::TooManySessions);
            }
            claimed.insert(dest_rel.clone());
        }

        let staging = Self::staging_dir(root, dest_abs);
        if let Err(e) = std::fs::create_dir_all(&staging) {
            self.release(&dest_rel);
            return Err(e.into());
        }

        let serial = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // `{serial:016x}` is fixed-width lowercase hex of a server-generated
        // counter — never caller input — so `staging.join` below only ever
        // appends exactly one ordinary, `..`-free, drive-prefix-free
        // component. The postcondition `delete_file_blocking` needs for a
        // caller-supplied name (`src/api/fs.rs`) has nothing to check here.
        let id = format!("up-{serial:016x}");
        let part_path = staging.join(format!("{id}.part"));

        // `create_new` (`O_EXCL` on Unix, `CREATE_NEW` on Windows), not
        // `File::create` (`O_CREAT|O_TRUNC`, no `O_EXCL`). Containment is a
        // property of the moment of resolution, and a session here can live
        // for up to `SESSION_TTL` — long enough for `part_path`'s final
        // component to become a symlink pointing outside the root before this
        // call runs. `File::create` would follow it and write outside the
        // jail; `create_new` fails `EEXIST` on an existing name instead of
        // following it, symlink or not. `part_path` above is safe by
        // construction (server-generated id), so nothing should exist at this
        // exact name yet — `create_new` is what makes "should" load-bearing
        // instead of assumed.
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)
        {
            Ok(file) => file,
            Err(e) => {
                self.release(&dest_rel);
                return Err(e.into());
            }
        };

        let session = Session {
            dest_rel: dest_rel.clone(),
            part_path,
            declared_size: size,
            declared_sha256: sha256,
            offset: 0,
            hasher: Hasher::new(),
            file,
            touched: Instant::now(),
        };

        // Matched rather than `?`-chained (an earlier version chained
        // `.write().map_err(...)?.insert(...)`): a poisoned `sessions` lock
        // must not leak the claim or the staging file already created above
        // — `session` is not moved into the map on this path, so its
        // `part_path` is still reachable to clean up. `sweep`/`cancel` only
        // ever reclaim a claim through a *live* entry in `sessions`; if this
        // session never made it into that map, nothing else will ever
        // release it.
        let mut sessions = match self.sessions.write() {
            Ok(sessions) => sessions,
            Err(_) => {
                std::fs::remove_file(&session.part_path).ok();
                self.release(&dest_rel);
                return Err(poisoned());
            }
        };
        sessions.insert(id.clone(), Mutex::new(session));
        drop(sessions);

        if let Ok(mut claimed) = self.claimed.lock() {
            claimed.insert(dest_rel);
        }
        Ok(id)
    }

    /// How many bytes the session has accepted so far.
    pub fn offset(&self, id: &str) -> Option<u64> {
        let sessions = self.sessions.read().ok()?;
        let session = sessions.get(id)?.lock().ok()?;
        Some(session.offset)
    }

    /// Append one chunk, returning the offset to send next.
    ///
    /// The offset is checked rather than trusted: a retried request that
    /// already landed would otherwise be written twice and corrupt the hash.
    ///
    /// This holds the session's own `Mutex` (and the store-wide `sessions`
    /// `RwLock` in its shared read mode) for the full duration of the
    /// `seek`+`write_all` below, which is blocking disk I/O — not merely an
    /// in-memory update. That means a concurrent `sweep` (which needs
    /// `sessions`' *write* lock) blocks until this call finishes, and so does
    /// any other caller of `append`/`take_for_complete`/`cancel` for this same
    /// session id (nothing else can, since only one request should ever be
    /// live per session anyway). Concurrent `append` calls for *different*
    /// sessions are unaffected — `RwLock` read access is shared. Accepted:
    /// bounded by one write's duration. This is not the only possible
    /// shape, though: `HashMap<String, Arc<Mutex<Session>>>` would let this
    /// function clone the `Arc`, drop the `sessions` read guard immediately,
    /// and hold only the session's own `Mutex` across the write — removing
    /// the contention with `sweep`/`create` entirely while keeping the same
    /// per-session serialization (two chunks for the *same* session still
    /// cannot interleave, since the session `Mutex` alone already prevents
    /// that). That is a real improvement, tracked separately rather than
    /// made here: it restructures the state machine's storage at the tail
    /// of an already-large task, and the contention it would remove is
    /// bounded and documented, not a correctness gap.
    ///
    /// One failure mode this contention analysis does not cover: if a writer
    /// ever panicked while holding `sessions`' *write* guard (`create`'s
    /// insert, `take_for_complete`'s or `sweep`'s remove), `std::sync::RwLock`
    /// poisons permanently — every later `.read()` and `.write()` on it,
    /// including this method's and `sweep`'s own, then fails identically and
    /// forever, not "eventually swept once the panic clears." Unreachable
    /// today, specifically because every write-lock section in this file is a
    /// plain `HashMap` insert or remove with no disk I/O and nothing else
    /// that can panic — not because poisoning itself is impossible. That is
    /// the condition this note depends on, not a permanent property of the
    /// type: if a future change adds a fallible operation (a write, a
    /// panicking conversion, anything that can unwind) inside one of those
    /// three write-lock sections, this analysis no longer holds and the
    /// unreachability claim needs re-checking against whatever was added.
    ///
    /// This says nothing about the per-session `Mutex` acquired below, which
    /// *is* held across the `seek`+`write_all` disk I/O this doc comment
    /// itself describes. It is unreachable for the same underlying reason,
    /// not the same argument: `seek` and `write_all` report failure through
    /// `Result`, propagated with `?` rather than unwound, so nothing in that
    /// critical section can panic either.
    pub fn append(&self, id: &str, offset: u64, bytes: &[u8]) -> Result<u64, UploadError> {
        if bytes.len() > self.chunk_size {
            return Err(UploadError::TooLarge);
        }

        let sessions = self.sessions.read().map_err(|_| poisoned())?;
        let cell = sessions.get(id).ok_or(UploadError::NotFound)?;
        let mut session = cell.lock().map_err(|_| poisoned())?;

        if offset != session.offset {
            return Err(UploadError::OffsetMismatch {
                expected: session.offset,
            });
        }

        // Refused before a single byte is written: without this, a session
        // can stream arbitrarily far past what it declared, and the mismatch
        // is only ever caught at `complete` — after every byte has already
        // hit disk. `checked_add` rather than a plain `+`: `offset` is
        // caller-supplied (via `Content-Range`) and could in principle be
        // adversarially close to `u64::MAX`; overflow is treated the same as
        // exceeding the declared size, not as a wrapped-around pass.
        let next_offset = offset.checked_add(bytes.len() as u64);
        if next_offset.map_or(true, |next| next > session.declared_size) {
            return Err(UploadError::SizeExceeded);
        }

        session
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(UploadError::from)?;
        session.file.write_all(bytes).map_err(UploadError::from)?;

        session.hasher.update(bytes);
        session.offset += bytes.len() as u64;
        session.touched = Instant::now();
        Ok(session.offset)
    }

    /// Finish a session: verify the digest and hand back the staging file.
    ///
    /// The session is always removed from `sessions`. The destination's
    /// *claim*, however, survives a successful call — see
    /// `release_destination`'s doc comment for why. A failed checksum is
    /// different: it is terminal (the bytes on disk are known-wrong, and
    /// leaving them resumable would invite a client to retry into the same
    /// wrong result), and terminal means no rename will ever follow, so the
    /// claim is released immediately in that case — there is nothing left for
    /// a caller to finish acting on.
    pub fn take_for_complete(&self, id: &str) -> Result<FinishedUpload, UploadError> {
        let cell = self
            .sessions
            .write()
            .map_err(|_| poisoned())?
            .remove(id)
            .ok_or(UploadError::NotFound)?;
        let session = cell.into_inner().map_err(|_| poisoned())?;

        let Session {
            dest_rel,
            part_path,
            declared_size,
            declared_sha256,
            offset,
            hasher,
            file,
            ..
        } = session;
        drop(file);

        let digest = hasher.finish();
        if declared_size != offset || digest != declared_sha256 {
            std::fs::remove_file(&part_path).ok();
            self.release(&dest_rel);
            return Err(UploadError::Checksum {
                expected: declared_sha256,
                actual: digest,
                dest_rel,
            });
        }

        // Deliberately not released here — see `release_destination`.
        Ok(FinishedUpload {
            dest_rel,
            part_path,
            bytes: offset,
            digest: digest.clone(),
            expected: declared_sha256,
        })
    }

    /// Release a destination's claim once the caller has finished acting on
    /// the `FinishedUpload` a prior `take_for_complete` handed back — after
    /// the rename lands, or after giving up on it (whichever the caller's
    /// last step was).
    ///
    /// Not folded into `take_for_complete` itself: an earlier version of this
    /// function released the claim there, immediately on success — which
    /// opened a window between "session removed, claim released" and
    /// "staging file renamed into place" where a second `create` for the same
    /// `dest_rel` could succeed and start its own rename racing the first's,
    /// defeating the reason `claimed` exists at all. Keeping the claim alive
    /// until the caller explicitly releases it closes that window; the caller
    /// (`complete_upload` in `src/api/fs.rs`) calls this on every exit path
    /// after `take_for_complete` succeeds, success or failure of the rename
    /// alike, so the claim is always released exactly once.
    pub fn release_destination(&self, dest_rel: &str) {
        self.release(dest_rel);
    }

    /// Discard a session and its staging file.
    ///
    /// Returns the destination and bytes received so far when a session
    /// existed to cancel — `None` means no such session (unknown, already
    /// completed, already cancelled, or already expired). Widened from a
    /// plain `bool` for the same reason `sweep` returns
    /// `(id, destination, bytes_received)` instead of just dropping what it
    /// finds: the caller (`cancel_upload` in `src/api/fs.rs`) records a
    /// terminal audit event, and an event that cannot name which file was
    /// cancelled answers only "a session ended", not "what happened to this
    /// file" — the question an audit trail exists to answer.
    pub fn cancel(&self, id: &str) -> Option<(String, u64)> {
        let Ok(mut sessions) = self.sessions.write() else {
            return None;
        };
        let cell = sessions.remove(id)?;
        // Load-bearing, not tidiness: `release` below takes the `claimed`
        // lock, and `UploadStore`'s struct-level invariant is that `sessions`
        // and `claimed` are never held at once. Removing this `drop` would
        // still compile — `sessions` is unused after this point — but would
        // hold the `sessions` write guard across the `claimed` acquisition,
        // breaking that invariant silently.
        drop(sessions);
        let Ok(session) = cell.into_inner() else {
            return None;
        };
        self.release(&session.dest_rel);
        std::fs::remove_file(&session.part_path).ok();
        Some((session.dest_rel, session.offset))
    }

    /// Drop sessions idle for longer than `ttl`.
    ///
    /// Returns `(id, destination, bytes_received)` for each, so the caller can
    /// record a terminal audit event. A session that begins and never ends
    /// leaves a trail showing only a beginning, which is not a trail.
    pub fn sweep(&self, ttl: Duration) -> Vec<(String, String, u64)> {
        let mut expired = Vec::new();
        let Ok(sessions) = self.sessions.read() else {
            return expired;
        };
        let stale: Vec<String> = sessions
            .iter()
            .filter(|(_, cell)| {
                cell.lock()
                    .map(|s| s.touched.elapsed() >= ttl)
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect();
        // Load-bearing: `std::sync::RwLock` has no upgrade from a read guard
        // to a write guard, so holding this one into the loop below (which
        // needs `sessions.write()`) would deadlock this thread against
        // itself — a different hazard from the `drop` inside the loop below.
        drop(sessions);

        for id in stale {
            let Ok(mut sessions) = self.sessions.write() else {
                break;
            };
            let Some(cell) = sessions.remove(&id) else {
                continue;
            };
            // Load-bearing, not tidiness — same reason as `cancel`'s:
            // `release` below takes `claimed`, and `UploadStore`'s
            // struct-level invariant is that `sessions` and `claimed` are
            // never held at once.
            drop(sessions);
            if let Ok(session) = cell.into_inner() {
                self.release(&session.dest_rel);
                std::fs::remove_file(&session.part_path).ok();
                expired.push((id, session.dest_rel, session.offset));
            }
        }
        expired
    }

    fn release(&self, dest_rel: &str) {
        if let Ok(mut claimed) = self.claimed.lock() {
            claimed.remove(dest_rel);
        }
    }
}

impl std::fmt::Debug for UploadStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadStore")
            .field("chunk_size", &self.chunk_size)
            .finish_non_exhaustive()
    }
}

fn poisoned() -> UploadError {
    UploadError::Io {
        detail: "internal lock poisoned".to_string(),
        raw_os_error: None,
    }
}

/// Remove staging files left behind by a previous run.
///
/// Sessions do not survive a restart, so any `.part` still present is
/// unreachable — nothing can resume it and nothing will complete it.
///
/// Returns `(upload_id, bytes)` for each file removed, so a caller can record
/// a terminal audit event per orphan — same reason `UploadStore::sweep` and
/// `cancel` return what they do, rather than dropping what they find. Two
/// things are recoverable here and one is not: `upload_id` is the filename
/// stem (`up-{serial:016x}`, never caller input, so parsing it back out is
/// safe), and `bytes` is the file's size, which always equals what
/// `append` had written — but the *destination* lived only in the in-memory
/// `Session` a restart already discarded before this function ever runs, so
/// there is nothing here to recover it from. See `AuditEvent::with_upload_id`
/// for how a caller correlates this back to the `upload.start` that does
/// have it.
///
/// An empty `Vec` covers both "nothing to sweep" and "the staging directory
/// could not be read at all" (most commonly: no upload has ever run against
/// this root, so it was never created). Not distinguished, same reasoning as
/// before this was widened: nothing consumes that distinction.
///
/// **Machine-wide scope sweeps nothing here, and that is a real gap rather
/// than an oversight.** With no `--fs-root`, staging follows each destination
/// to its own directory (see [`UploadStore::staging_dir`]), so the set of
/// places a `.part` could be left is every directory anyone has ever uploaded
/// to — not enumerable without walking every drive, which is not a thing a
/// startup path should do. What covers it instead is
/// [`sweep_orphan_parts_in`], called against a single destination's staging
/// directory when an upload next targets it. The practical difference: inside
/// a jail an orphan is reclaimed at the next restart; machine-wide it is
/// reclaimed the next time something uploads to the same directory. Both are
/// invisible to `list`, which refuses the staging directory by name either
/// way.
pub fn sweep_orphan_parts(root: &crate::fs::FsRoot) -> Vec<(String, u64)> {
    let Some(jail) = root.jail_path() else {
        return Vec::new();
    };
    // No age floor: this runs at startup and on an interval against a jail's
    // single staging directory, where "a `.part` exists" already implies no
    // session owns it — sessions do not survive a restart, and the interval
    // caller sweeps expired sessions first.
    sweep_orphan_parts_in(&jail.join(UPLOAD_DIR), Duration::ZERO)
}

/// [`sweep_orphan_parts`] against one staging directory, removing only files
/// that have been untouched for at least `min_age`.
///
/// Split out so machine-wide uploads have a reclaim path at all: the caller
/// that knows a destination knows its staging directory, even though no
/// startup path can enumerate every such directory.
///
/// **`min_age` is what keeps this from destroying a live upload, and it is not
/// optional for a runtime caller.** Machine-wide staging is shared by every
/// upload heading for the same directory, so a sweep run when a second session
/// is created will see the *first* session's `.part` — a file that is very much
/// owned. Removing it does not fail the writes that follow: the session holds
/// an open handle, so `append` keeps succeeding against a name that no longer
/// exists, every chunk answers 200, and only `complete` fails, with
/// `ENOENT` — after the client has uploaded the whole file. That shape (accept
/// everything, then lose it at publication) is the worst available, and it is
/// what an unconditional sweep here produced.
///
/// A live session's file is protected because writing to it updates its mtime,
/// and a session that has gone quiet for longer than the caller's floor has
/// already been reclaimed by `sweep_expired_uploads`, which the API layer runs
/// first. An orphan from a previous run has no such protection, which is the
/// point.
pub fn sweep_orphan_parts_in(staging: &Path, min_age: Duration) -> Vec<(String, u64)> {
    let Ok(entries) = std::fs::read_dir(staging) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("part") {
            continue;
        }
        // Read before removing: there is no size to report once the file is
        // gone. `std::fs::metadata(&path)` — a fresh stat — rather than the
        // cheaper `entry.metadata()`: on Windows, `DirEntry::metadata()`
        // returns the `WIN32_FIND_DATA` captured by the `read_dir`
        // enumeration itself, which can under-report the size of a file
        // still open elsewhere for writing (verified: a session whose
        // staging file was just appended to and never closed reported `0`
        // bytes here, on this platform, until this was changed to a fresh
        // stat). A second, different way the same `DirEntry` API is not what
        // it appears to be: `list`'s own walk (`src/api/fs.rs`) already notes
        // that `DirEntry::metadata` is lstat-like there, so a symlink looks
        // in-root when `metadata` would follow it out — that one is about
        // *which* file the metadata describes, this one is about *how current*
        // it is, but both come from trusting the enumeration's cached view
        // instead of asking the filesystem again. Not reachable in
        // production here — the whole reason a `.part` file is orphaned is
        // that the process that held it open is gone — but a test exercising
        // this without a real restart can still hit it, and the fresh call
        // costs one extra syscall per file, on a path that runs once at
        // startup.
        let meta = std::fs::metadata(&path);
        // Age is read from the same fresh stat, and a file whose age cannot be
        // established is left alone rather than removed: this is the guard that
        // stands between a runtime sweep and a live upload, and a guard that
        // fails open is not one. `Duration::ZERO` makes it a no-op for the
        // startup caller, where nothing can be live.
        if !min_age.is_zero() {
            // `map_or(true, ..)` rather than `is_none_or`: the latter is stable
            // since 1.82 and this crate's MSRV is 1.78. Same meaning — an
            // unreadable or unknowable age counts as young, so the file stays.
            let young_or_unknown = meta
                .as_ref()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .map_or(true, |age| age < min_age);
            if young_or_unknown {
                continue;
            }
        }
        let bytes = meta.map(|m| m.len()).unwrap_or(0);
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            // Not a name this process ever generated (`up-{serial:016x}.part`
            // is always valid UTF-8) — nothing to correlate an event to, so
            // the file is removed but not reported.
            std::fs::remove_file(&path).ok();
            continue;
        };
        let id = id.to_string();
        if std::fs::remove_file(&path).is_ok() {
            removed.push((id, bytes));
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FsRoot;

    fn store() -> (tempfile::TempDir, FsRoot, UploadStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = FsRoot::new(dir.path()).expect("root");
        let store = UploadStore::new(DEFAULT_CHUNK_SIZE);
        (dir, root, store)
    }

    impl UploadStore {
        /// `create` from a root-relative destination, resolving it the way the
        /// API layer does.
        ///
        /// `create` takes the resolved absolute destination because staging
        /// has to land on the destination's own filesystem when no `--fs-root`
        /// narrows the scope (see `staging_dir`). These tests all run against a
        /// jail, where that resolution is uninteresting — doing it here rather
        /// than passing some hand-built path keeps them exercising the same
        /// path the real caller takes.
        fn create_rel(
            &self,
            root: &FsRoot,
            dest: &str,
            size: u64,
            sha256: String,
        ) -> Result<String, UploadError> {
            let absolute = root.resolve_for_create(dest).expect("destination resolves");
            self.create(root, &absolute, dest.to_string(), size, sha256)
        }
    }

    /// The staging directory of a jailed root.
    ///
    /// `staging_dir` takes a destination because machine-wide scope has to put
    /// staging on the destination's own filesystem. A jail ignores it, so these
    /// tests name that explicitly rather than threading a value none of them
    /// care about through every call.
    fn staging_of(root: &FsRoot) -> PathBuf {
        UploadStore::staging_dir(root, Path::new("ignored-when-jailed"))
    }

    /// SHA-256 of b"hello world".
    const HELLO_DIGEST: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    /// 트리 삭제가 진행 중인 업로드를 지우지 않으려면, 어떤 디렉터리 아래에
    /// 살아있는 세션의 스테이징 파일이 있는지 물을 수 있어야 한다. 고아
    /// `.part`는 "살아있음"이 아니다 — 그것까지 살아있다고 답하면 스윕이 늦은
    /// 트리가 무기한 삭제 불가가 된다.
    #[test]
    fn a_live_session_is_visible_under_its_staging_directory() {
        let (dir, root, store) = store();
        let staging = staging_of(&root);

        assert!(
            !store.has_live_part_under(dir.path()),
            "세션이 없으면 아무것도 살아있지 않다"
        );

        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");

        assert!(
            store.has_live_part_under(dir.path()),
            "루트 아래에서 보인다"
        );
        assert!(
            store.has_live_part_under(&staging),
            "스테이징 자신 아래에서도 보인다"
        );
        // 캐노니칼화할 수 있도록 존재하는 디렉터리 생성
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("mkdir elsewhere");
        assert!(
            !store.has_live_part_under(&elsewhere),
            "관계없는 디렉터리 아래에서는 보이지 않는다"
        );

        store.cancel(&id);
        assert!(
            !store.has_live_part_under(dir.path()),
            "취소된 세션은 살아있지 않다"
        );
    }

    /// 세션이 없는 채 남은 `.part`(이전 실행의 고아)는 살아있지 않다.
    /// 이 테스트는 고아 `.part` 파일이 디스크에 존재해도, 세션 목록에
    /// 없으면 "살아있음"이 아님을 증명한다. 구현이 디스크를 조회한다면
    /// 이 테스트는 실패할 것이다.
    #[test]
    fn an_orphan_part_file_is_not_a_live_session() {
        let (dir, root, store) = store();
        let staging = staging_of(&root);
        std::fs::create_dir_all(&staging).expect("mkdir staging");

        // 살아있는 세션을 생성
        let live_id = store
            .create_rel(&root, "upload1.bin", 5, "0".repeat(64))
            .expect("create live session");

        // 세션이 있으므로 true를 반환
        assert!(
            store.has_live_part_under(dir.path()),
            "살아있는 세션이 있으므로 true를 반환한다"
        );

        // 세션을 취소하고, 고아 `.part` 파일을 그 자리에 남김
        store.cancel(&live_id);
        let orphan_path = staging.join("up-0000000000000000.part");
        std::fs::write(&orphan_path, b"orphan content").expect("write orphan");
        assert!(
            orphan_path.exists(),
            "고아 파일이 디스크에 실제로 존재해야 함"
        );

        // 고아 파일이 있어도 세션 목록에 없으므로 false를 반환해야 한다.
        // 구현이 디스크를 조회한다면 이 assertion이 실패할 것이다.
        assert!(
            !store.has_live_part_under(dir.path()),
            "고아 파일이 있어도 세션 목록이 기준이므로 false를 반환한다"
        );
    }

    /// 존재하지 않는 경로(캐노니칼화 불가)에 대한 조회는 안전하게 "있다"고 답한다.
    /// `part_path`는 항상 정규화된 절대경로이므로, 정규화되지 않은 경로와는
    /// 비교할 수 없다. 알 수 없는 경우 삭제를 거부하는 쪽이 안전하다.
    #[test]
    fn a_nonexistent_path_cannot_be_canonicalized_so_answers_true() {
        let (dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");

        // 존재하지 않는 경로: canonicalize가 실패한다
        let nonexistent = dir.path().join("does-not-exist");
        assert!(!nonexistent.exists(), "path must not exist for this test");

        // 캐노니칼화할 수 없으므로 안전하게 "있다"고 답해야 한다
        assert!(
            store.has_live_part_under(&nonexistent),
            "캐노니칼화 불가능한 경로는 안전하게 true를 반환한다"
        );

        store.cancel(&id);
    }

    #[test]
    fn a_session_starts_at_offset_zero() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");
        assert_eq!(store.offset(&id), Some(0));
    }

    #[test]
    fn chunks_advance_the_offset() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");

        assert_eq!(store.append(&id, 0, b"hello ").expect("first"), 6);
        assert_eq!(store.append(&id, 6, b"world").expect("second"), 11);
    }

    #[test]
    fn a_chunk_at_the_wrong_offset_is_refused_with_the_expected_one() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");
        store.append(&id, 0, b"hello ").expect("first");

        assert_eq!(
            store.append(&id, 0, b"again"),
            Err(UploadError::OffsetMismatch { expected: 6 })
        );
    }

    #[test]
    fn two_sessions_may_not_target_the_same_path() {
        let (_dir, root, store) = store();
        store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("first");
        assert_eq!(
            store.create_rel(&root, "out.bin", 11, HELLO_DIGEST.into()),
            Err(UploadError::Conflict)
        );
    }

    #[test]
    fn a_matching_checksum_completes() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");
        store.append(&id, 0, b"hello world").expect("append");

        let finished = store.take_for_complete(&id).expect("complete");
        assert_eq!(finished.bytes, 11);
        assert_eq!(finished.digest, HELLO_DIGEST);
        assert_eq!(finished.dest_rel, "out.bin");
    }

    #[test]
    fn a_mismatched_checksum_is_refused() {
        let (_dir, root, store) = store();
        let wrong = "0".repeat(64);
        let id = store
            .create_rel(&root, "out.bin", 11, wrong.clone())
            .expect("create");
        store.append(&id, 0, b"hello world").expect("append");

        match store.take_for_complete(&id) {
            Err(UploadError::Checksum {
                expected,
                actual,
                dest_rel,
            }) => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, HELLO_DIGEST);
                assert_eq!(dest_rel, "out.bin");
            }
            other => panic!("expected a checksum refusal, got {other:?}"),
        }
        // The session is gone and the staging file with it.
        assert_eq!(store.offset(&id), None);
    }

    #[test]
    fn a_chunk_above_the_ceiling_is_refused() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");
        let oversized = vec![0_u8; DEFAULT_CHUNK_SIZE + 1];
        assert_eq!(store.append(&id, 0, &oversized), Err(UploadError::TooLarge));
    }

    #[test]
    fn a_chunk_that_would_exceed_the_declared_size_is_refused() {
        let (_dir, root, store) = store();
        // Declares 5 bytes; the digest is irrelevant here since the size
        // check runs at `append` time, well before any checksum comparison.
        let id = store
            .create_rel(&root, "out.bin", 5, HELLO_DIGEST.into())
            .expect("create");
        assert_eq!(
            store.append(&id, 0, b"hello world"),
            Err(UploadError::SizeExceeded)
        );
        // Refused before anything was written: the offset must not have moved.
        assert_eq!(store.offset(&id), Some(0));
    }

    #[test]
    fn a_chunk_landing_exactly_on_the_declared_size_is_accepted() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");
        // Exactly 11 bytes against a declared size of 11 — the boundary
        // `a_chunk_that_would_exceed_the_declared_size_is_refused` does not
        // cover, and the one `>` (not `>=`) in the check depends on.
        assert_eq!(store.append(&id, 0, b"hello world").expect("append"), 11);
    }

    #[test]
    fn cancelling_removes_the_session_and_frees_the_destination() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");
        store.append(&id, 0, b"hello ").expect("append");

        let (destination, bytes) = store.cancel(&id).expect("session existed");
        assert_eq!(destination, "out.bin");
        assert_eq!(bytes, 6);
        assert_eq!(store.offset(&id), None);
        // The destination is claimable again.
        assert!(store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .is_ok());
    }

    #[test]
    fn sweeping_drops_sessions_past_their_ttl() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");

        assert_eq!(store.sweep(Duration::ZERO).len(), 1);
        assert_eq!(store.offset(&id), None);
    }

    /// `create` used to sweep opportunistically (with the real, fixed
    /// `SESSION_TTL`) before doing anything else. That call is gone — moved
    /// to the caller, which sweeps through the audit-aware
    /// `sweep_expired_uploads` instead (`src/api/fs.rs`) — because
    /// `UploadStore` has no `AuditSink` to record with, so a sweep run from
    /// inside this method could never leave a trail. This is the regression
    /// guard for that move: even a session that a zero-TTL sweep would call
    /// stale must survive an unrelated `create` call untouched, proving
    /// `create` itself no longer reclaims anything — only an explicit
    /// `sweep`/`sweep_expired_uploads` call does.
    #[test]
    fn create_does_not_sweep_expired_sessions_itself() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "old.bin", 11, HELLO_DIGEST.into())
            .expect("create");

        store
            .create_rel(&root, "new.bin", 11, HELLO_DIGEST.into())
            .expect("second create");

        assert_eq!(
            store.offset(&id),
            Some(0),
            "create must not silently reclaim a stale session; only an explicit sweep call may"
        );
    }

    /// The strongest test in this module: `create` opens the staging file
    /// with `create_new`, which must fail (`EEXIST`) rather than follow an
    /// existing symlink at that exact name. Planted *before* any session
    /// exists, exploiting that a fresh store's counter starts at 0 — so the
    /// first session's id, and therefore its staging path, is predictable
    /// (`up-0000000000000000.part`).
    ///
    /// Two assertions, not one: the create must fail, *and* the outside
    /// target must be untouched. Checking only the error would still pass a
    /// version that wrote through the link and then failed for an unrelated
    /// reason afterward.
    #[test]
    fn a_pre_existing_symlink_at_the_predicted_staging_path_cannot_be_written_through() {
        let outer = tempfile::tempdir().expect("outer tempdir");
        let root_dir = outer.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("mkdir root");
        let root = FsRoot::new(&root_dir).expect("root");
        let store = UploadStore::new(DEFAULT_CHUNK_SIZE);

        let secret = outer.path().join("secret.txt");
        std::fs::write(&secret, b"outside-secret").expect("write secret");

        let staging = staging_of(&root);
        std::fs::create_dir_all(&staging).expect("mkdir staging");
        let predicted = staging.join("up-0000000000000000.part");

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&secret, &predicted).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&secret, &predicted).is_ok();
        #[cfg(not(any(unix, windows)))]
        let linked = false;
        if !linked {
            return; // symlink privilege unavailable on this runner; skip
        }

        let result = store.create_rel(&root, "app-new.bin", 11, HELLO_DIGEST.into());
        assert!(
            matches!(result, Err(UploadError::Io { .. })),
            "create_new must refuse a pre-existing symlink at the staging path \
             rather than follow it, got {result:?}"
        );
        assert_eq!(
            std::fs::read(&secret).expect("read secret"),
            b"outside-secret",
            "the outside target must be untouched: the open must fail before \
             any write reaches it"
        );
    }

    #[test]
    fn a_cap_limits_concurrent_sessions_and_releasing_one_frees_a_slot() {
        let (_dir, root, store) = store();
        let mut ids = Vec::with_capacity(MAX_CONCURRENT_UPLOADS);
        for i in 0..MAX_CONCURRENT_UPLOADS {
            let id = store
                .create_rel(&root, &format!("f{i}.bin"), 1, HELLO_DIGEST.into())
                .unwrap_or_else(|e| panic!("session {i} should fit under the cap: {e:?}"));
            ids.push(id);
        }

        assert_eq!(
            store.create_rel(&root, "one-too-many.bin", 1, HELLO_DIGEST.into()),
            Err(UploadError::TooManySessions)
        );

        // Freeing one slot makes room for exactly one more.
        assert!(store.cancel(&ids[0]).is_some());
        assert!(store
            .create_rel(&root, "one-too-many.bin", 1, HELLO_DIGEST.into())
            .is_ok());
    }

    #[test]
    fn completing_an_upload_keeps_the_destination_claimed_until_explicitly_released() {
        let (_dir, root, store) = store();
        let id = store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .expect("create");
        store.append(&id, 0, b"hello world").expect("append");
        let finished = store.take_for_complete(&id).expect("complete");

        // The caller has not renamed the staging file into place yet (has not
        // called `release_destination`), so the destination must still be
        // refused to a second session — otherwise two sessions could both be
        // mid-publication to the same path.
        assert_eq!(
            store.create_rel(&root, "out.bin", 11, HELLO_DIGEST.into()),
            Err(UploadError::Conflict)
        );

        store.release_destination(&finished.dest_rel);

        // Now that the caller is done with it, the destination is claimable again.
        assert!(store
            .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
            .is_ok());
    }

    #[test]
    fn sweep_orphan_parts_removes_leftover_part_files_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = FsRoot::new(dir.path()).expect("root");
        let staging = staging_of(&root);
        std::fs::create_dir_all(&staging).expect("mkdir staging");
        std::fs::write(staging.join("up-0000000000000000.part"), b"leftover")
            .expect("write orphan");
        std::fs::write(staging.join("up-0000000000000001.part"), b"leftover2")
            .expect("write second orphan");
        // Not a `.part` file — proves the extension filter, not "delete
        // everything in the directory".
        std::fs::write(staging.join("keep.txt"), b"not a part file").expect("write keep");

        let mut removed = sweep_orphan_parts(&root);
        removed.sort();
        assert_eq!(
            removed,
            vec![
                ("up-0000000000000000".to_string(), 8),
                ("up-0000000000000001".to_string(), 9),
            ],
            "each orphan must be reported by its id (the filename stem) and the bytes it held, so a caller can audit it"
        );
        assert!(!staging.join("up-0000000000000000.part").exists());
        assert!(!staging.join("up-0000000000000001.part").exists());
        assert!(
            staging.join("keep.txt").exists(),
            "only .part files are orphans; anything else in staging must survive"
        );
    }

    #[test]
    fn a_poisoned_sessions_lock_does_not_leak_the_claim_or_the_staging_file() {
        let (_dir, root, store) = store();

        // Poison `sessions` by panicking while holding its write guard.
        // `catch_unwind` keeps the panic from taking the test process down;
        // the guard's `Drop` still runs during the unwind and marks the
        // lock poisoned regardless of the panic being caught afterward.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.sessions.write().expect("lock not yet poisoned");
            panic!("poison it");
        }));
        assert!(
            poisoned.is_err(),
            "the closure must have panicked while holding the write guard"
        );

        let outcome = store.create_rel(&root, "out.bin", 11, HELLO_DIGEST.into());
        assert!(
            matches!(outcome, Err(UploadError::Io { .. })),
            "a poisoned sessions lock must surface as an Io error, got {outcome:?}"
        );

        // Recover the lock — a real caller cannot do this, but the test does,
        // purely to inspect whether the failed attempt above left anything
        // behind. If it did, this second `create` for the same destination
        // would come back `Err(Conflict)` instead of succeeding.
        store.sessions.clear_poison();
        assert!(
            store
                .create_rel(&root, "out.bin", 11, HELLO_DIGEST.into())
                .is_ok(),
            "the destination must not still be claimed by the failed attempt"
        );

        let staging = staging_of(&root);
        let leftover_parts = std::fs::read_dir(&staging)
            .expect("staging dir")
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("part"))
            .count();
        assert_eq!(
            leftover_parts, 1,
            "only the second, successful session's staging file should remain"
        );
    }
}
