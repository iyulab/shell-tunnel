//! Filesystem access, confined to a configured root.
//!
//! Placed at the crate root rather than under `security/` because the jail is
//! not a check that sits beside file access — it is the only way file access
//! happens. Filing it with the other validators would invite the reading that
//! it can be bypassed.

pub mod platform;
pub mod root;
pub mod sha256;
pub mod transfer;

pub use root::{FsError, FsRoot};
pub use transfer::{
    sweep_orphan_parts, FinishedUpload, UploadError, UploadStore, DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE, SESSION_TTL,
};

/// Directory under the root where in-flight uploads are staged.
///
/// Declared here rather than beside the upload store because two unrelated
/// callers need it — `list` must hide it, and the transfer layer must create it
/// — and a second copy of the name is a rename waiting to go wrong.
pub const UPLOAD_DIR: &str = ".shell-tunnel-uploads";
