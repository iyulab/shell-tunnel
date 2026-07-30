//! In-flight upload sessions.
//!
//! Bytes land in a staging file and are renamed into place only after the whole
//! transfer verifies. A partial file therefore never appears at the destination
//! — a consumer polling that path sees nothing or sees the finished article.

use std::collections::{HashMap, HashSet};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
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
    Checksum { expected: String, actual: String },
    /// The filesystem refused.
    Io(String),
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

    /// Where staging files live for `root`.
    pub fn staging_dir(root: &crate::fs::FsRoot) -> PathBuf {
        root.path().join(UPLOAD_DIR)
    }

    /// Open a session for `dest_rel`, which need not exist yet.
    pub fn create(
        &self,
        root: &crate::fs::FsRoot,
        dest_rel: String,
        size: u64,
        sha256: String,
    ) -> Result<String, UploadError> {
        // Opportunistic reclamation: a cap with nothing ever reclaiming past
        // it would eventually leave every one of its slots permanently
        // stuck on an abandoned session. Run the sweep at the point new
        // capacity is being requested rather than on a background timer —
        // simpler, and self-limiting: a session old enough to matter is
        // reclaimed the moment somebody next asks for a new one, which is
        // exactly when reclaiming it matters.
        self.sweep(SESSION_TTL);

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

        let staging = Self::staging_dir(root);
        if let Err(e) = std::fs::create_dir_all(&staging) {
            self.release(&dest_rel);
            return Err(UploadError::Io(e.to_string()));
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
                return Err(UploadError::Io(e.to_string()));
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
            .map_err(|e| UploadError::Io(e.to_string()))?;
        session
            .file
            .write_all(bytes)
            .map_err(|e| UploadError::Io(e.to_string()))?;

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

    /// Discard a session and its staging file. Returns whether it existed.
    pub fn cancel(&self, id: &str) -> bool {
        let Ok(mut sessions) = self.sessions.write() else {
            return false;
        };
        let Some(cell) = sessions.remove(id) else {
            return false;
        };
        // Load-bearing, not tidiness: `release` below takes the `claimed`
        // lock, and `UploadStore`'s struct-level invariant is that `sessions`
        // and `claimed` are never held at once. Removing this `drop` would
        // still compile — `sessions` is unused after this point — but would
        // hold the `sessions` write guard across the `claimed` acquisition,
        // breaking that invariant silently.
        drop(sessions);
        let Ok(session) = cell.into_inner() else {
            return false;
        };
        self.release(&session.dest_rel);
        std::fs::remove_file(&session.part_path).ok();
        true
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
    UploadError::Io("internal lock poisoned".to_string())
}

/// Remove staging files left behind by a previous run.
///
/// Sessions do not survive a restart, so any `.part` still present is
/// unreachable — nothing can resume it and nothing will complete it.
///
/// Returns `0` both when there was nothing to sweep and when the staging
/// directory could not be read at all (most commonly: no upload has ever
/// run against this root, so it was never created). Not distinguished:
/// `main.rs`'s only use of the return value is to log a positive count, and
/// "nothing there" vs. "unreadable" both mean nothing to log. Telling them
/// apart would need a richer return type for a distinction the one caller
/// does not consume.
pub fn sweep_orphan_parts(root: &crate::fs::FsRoot) -> usize {
    let staging = UploadStore::staging_dir(root);
    let Ok(entries) = std::fs::read_dir(&staging) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("part")
            && std::fs::remove_file(&path).is_ok()
        {
            removed += 1;
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

    /// SHA-256 of b"hello world".
    const HELLO_DIGEST: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[test]
    fn a_session_starts_at_offset_zero() {
        let (_dir, root, store) = store();
        let id = store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .expect("create");
        assert_eq!(store.offset(&id), Some(0));
    }

    #[test]
    fn chunks_advance_the_offset() {
        let (_dir, root, store) = store();
        let id = store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .expect("create");

        assert_eq!(store.append(&id, 0, b"hello ").expect("first"), 6);
        assert_eq!(store.append(&id, 6, b"world").expect("second"), 11);
    }

    #[test]
    fn a_chunk_at_the_wrong_offset_is_refused_with_the_expected_one() {
        let (_dir, root, store) = store();
        let id = store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
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
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .expect("first");
        assert_eq!(
            store.create(&root, "out.bin".into(), 11, HELLO_DIGEST.into()),
            Err(UploadError::Conflict)
        );
    }

    #[test]
    fn a_matching_checksum_completes() {
        let (_dir, root, store) = store();
        let id = store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
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
            .create(&root, "out.bin".into(), 11, wrong.clone())
            .expect("create");
        store.append(&id, 0, b"hello world").expect("append");

        match store.take_for_complete(&id) {
            Err(UploadError::Checksum { expected, actual }) => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, HELLO_DIGEST);
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
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
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
            .create(&root, "out.bin".into(), 5, HELLO_DIGEST.into())
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
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
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
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .expect("create");
        assert!(store.cancel(&id));
        assert_eq!(store.offset(&id), None);
        // The destination is claimable again.
        assert!(store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .is_ok());
    }

    #[test]
    fn sweeping_drops_sessions_past_their_ttl() {
        let (_dir, root, store) = store();
        let id = store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .expect("create");

        assert_eq!(store.sweep(Duration::ZERO).len(), 1);
        assert_eq!(store.offset(&id), None);
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

        let staging = UploadStore::staging_dir(&root);
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

        let result = store.create(&root, "app-new.bin".into(), 11, HELLO_DIGEST.into());
        assert!(
            matches!(result, Err(UploadError::Io(_))),
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
                .create(&root, format!("f{i}.bin"), 1, HELLO_DIGEST.into())
                .unwrap_or_else(|e| panic!("session {i} should fit under the cap: {e:?}"));
            ids.push(id);
        }

        assert_eq!(
            store.create(&root, "one-too-many.bin".into(), 1, HELLO_DIGEST.into()),
            Err(UploadError::TooManySessions)
        );

        // Freeing one slot makes room for exactly one more.
        assert!(store.cancel(&ids[0]));
        assert!(store
            .create(&root, "one-too-many.bin".into(), 1, HELLO_DIGEST.into())
            .is_ok());
    }

    #[test]
    fn completing_an_upload_keeps_the_destination_claimed_until_explicitly_released() {
        let (_dir, root, store) = store();
        let id = store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .expect("create");
        store.append(&id, 0, b"hello world").expect("append");
        let finished = store.take_for_complete(&id).expect("complete");

        // The caller has not renamed the staging file into place yet (has not
        // called `release_destination`), so the destination must still be
        // refused to a second session — otherwise two sessions could both be
        // mid-publication to the same path.
        assert_eq!(
            store.create(&root, "out.bin".into(), 11, HELLO_DIGEST.into()),
            Err(UploadError::Conflict)
        );

        store.release_destination(&finished.dest_rel);

        // Now that the caller is done with it, the destination is claimable again.
        assert!(store
            .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
            .is_ok());
    }

    #[test]
    fn sweep_orphan_parts_removes_leftover_part_files_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = FsRoot::new(dir.path()).expect("root");
        let staging = UploadStore::staging_dir(&root);
        std::fs::create_dir_all(&staging).expect("mkdir staging");
        std::fs::write(staging.join("up-0000000000000000.part"), b"leftover")
            .expect("write orphan");
        std::fs::write(staging.join("up-0000000000000001.part"), b"leftover2")
            .expect("write second orphan");
        // Not a `.part` file — proves the extension filter, not "delete
        // everything in the directory".
        std::fs::write(staging.join("keep.txt"), b"not a part file").expect("write keep");

        assert_eq!(sweep_orphan_parts(&root), 2);
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

        let outcome = store.create(&root, "out.bin".into(), 11, HELLO_DIGEST.into());
        assert!(
            matches!(outcome, Err(UploadError::Io(_))),
            "a poisoned sessions lock must surface as an Io error, got {outcome:?}"
        );

        // Recover the lock — a real caller cannot do this, but the test does,
        // purely to inspect whether the failed attempt above left anything
        // behind. If it did, this second `create` for the same destination
        // would come back `Err(Conflict)` instead of succeeding.
        store.sessions.clear_poison();
        assert!(
            store
                .create(&root, "out.bin".into(), 11, HELLO_DIGEST.into())
                .is_ok(),
            "the destination must not still be claimed by the failed attempt"
        );

        let staging = UploadStore::staging_dir(&root);
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
