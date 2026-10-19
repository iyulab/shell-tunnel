//! Checking that a downloaded Windows binary is signed by this project.
//!
//! A valid signature is not enough on its own: anything signed by anyone with
//! a code-signing certificate passes `WinVerifyTrust`. What replaces a running
//! device must also be signed by the publisher that signs this project's
//! releases, so the signer's common name is compared as well.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Cryptography::{
    CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// The common name on the certificate that signs this project's releases,
/// read from a shipped release binary rather than written from memory.
pub const EXPECTED_PUBLISHER: &str = "IYULAB INC.";

/// `Ok` when `path` carries a valid Authenticode signature whose signer is
/// [`EXPECTED_PUBLISHER`]. The error says which of the two failed.
///
/// Revocation is not checked: a device may have no route to a CRL, and the
/// archive this binary came from was already matched against the release's
/// own `SHA256SUMS` over HTTPS.
pub fn verify_publisher(path: &Path) -> Result<(), String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `data` and `file` outlive both calls, `wide` is NUL-terminated,
    // and the state opened by VERIFY is closed by the second call on every path.
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        )
    };
    let result = if status != 0 {
        Err(format!(
            "no valid signature (WinVerifyTrust {:#010x})",
            status as u32
        ))
    } else {
        match unsafe { signer_name(data.hWVTStateData) } {
            Some(name) if name == EXPECTED_PUBLISHER => Ok(()),
            Some(name) => Err(format!("signed by {name:?}, not {EXPECTED_PUBLISHER:?}")),
            None => Err("the signer's certificate could not be read".to_string()),
        }
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        );
    }
    result
}

/// The simple display name (the common name) of the leaf certificate of the
/// first signer recorded in `state`.
///
/// # Safety
/// `state` must be the `hWVTStateData` of a successful, not yet closed,
/// `WTD_STATEACTION_VERIFY`.
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    let provider = WTHelperProvDataFromStateData(state);
    if provider.is_null() {
        return None;
    }
    let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
    if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
        return None;
    }
    let cert = (*(*signer).pasCertChain).pCert;
    if cert.is_null() {
        return None;
    }
    let mut buf = [0u16; 256];
    let len = CertGetNameStringW(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    ) as usize;
    // The length includes the terminating NUL; 1 means an empty name.
    if len <= 1 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len - 1]))
}
