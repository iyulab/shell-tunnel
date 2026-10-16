//! Running under the Windows service control manager.
//!
//! A process started by the SCM has 30 seconds to call
//! `StartServiceCtrlDispatcherW`, or the SCM gives up on it — `StartService`
//! fails with 1053 and the process is terminated. Without this module the
//! binary never made that call, so the `sc.exe` recipe in the operating guide
//! registered a service that could not start.
//!
//! Whether this process *is* a service is answered by the same call: outside
//! the SCM it fails at once with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`,
//! and the caller runs as it always has. No flag is involved, so the command
//! line an operator tests in a console is the command line the service runs.
//!
//! Installing the service stays the operator's job (`sc.exe`, as the guide
//! shows): restart policy and start order belong to the SCM. What the binary
//! owes it is the protocol — report running, stop when told, and say whether
//! a stop was a failure, so `sc.exe failure` restarts the right ones.

use std::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use shell_tunnel::Args;

use crate::Exit;

/// What the service runs: the same entry point a console start uses, told to
/// return once `stop` fires.
pub type Serve = fn(Args, Option<Arc<tokio::sync::Notify>>) -> Exit;

/// How long a stop may take, as told to the SCM. The caller's runtime gets a
/// shorter grace than this to wind down; see `main.rs`.
const STOP_WAIT_HINT: Duration = Duration::from_secs(10);

/// Handed from `run_if_service` to `service_main`, which the SCM calls on a
/// thread of its own with no way to pass context.
struct Pending {
    args: Args,
    serve: Serve,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
static EXIT: Mutex<Option<Exit>> = Mutex::new(None);
static STOP: OnceLock<Arc<tokio::sync::Notify>> = OnceLock::new();
static STATUS_HANDLE: OnceLock<usize> = OnceLock::new();

/// Run `serve` as a Windows service if the SCM started this process.
///
/// Returns `Ok(exit)` once the service has stopped, or `Err(args)` — the
/// arguments handed back untouched, boxed because they are large and this is
/// the path every console start takes — when this process is not a service
/// and should run as a console program.
pub fn run_if_service(args: Args, serve: Serve) -> Result<Exit, Box<Args>> {
    *PENDING.lock().expect("not poisoned") = Some(Pending { args, serve });

    // A service of type OWN_PROCESS is the only one in its process, so the SCM
    // does not look at the name; an empty one is what the documentation allows.
    let mut name = [0u16];
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    // Blocks until the service has stopped, when there is one.
    // SAFETY: `table` is a null-terminated array that outlives the call.
    let dispatched = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0;
    if !dispatched {
        // SAFETY: no other call intervenes since the one that failed.
        let error = unsafe { GetLastError() };
        let pending = PENDING.lock().expect("not poisoned").take();
        let pending = pending.expect("service_main never ran, so nothing took it");
        if error != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            // Any other failure is the SCM refusing a process it did start; a
            // console start cannot produce it. Running as a console program
            // would serve nobody and look healthy, so it is said and treated
            // as a failure.
            eprintln!("could not connect to the service control manager (error {error})");
            return Ok(Exit::FAILURE);
        }
        return Err(Box::new(pending.args));
    }
    Ok(EXIT.lock().expect("not poisoned").unwrap_or(Exit::FAILURE))
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let Some(Pending { args, serve }) = PENDING.lock().expect("not poisoned").take() else {
        return;
    };
    let stop = STOP
        .get_or_init(|| Arc::new(tokio::sync::Notify::new()))
        .clone();

    let empty = [0u16];
    // SAFETY: the handler is a plain function and takes no context.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(empty.as_ptr(), Some(control_handler), std::ptr::null())
    };
    if handle.is_null() {
        *EXIT.lock().expect("not poisoned") = Some(Exit::FAILURE);
        return;
    }
    let _ = STATUS_HANDLE.set(handle as usize);

    // A service's working directory is System32. Every relative path an
    // operator wrote — `--audit-log`, the relay's certificate files, a config
    // file — would land there, written as LocalSystem. The directory holding
    // the executable is where an operator who wrote a relative path meant.
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.to_path_buf()))
    {
        let _ = std::env::set_current_dir(dir);
    }

    report(SERVICE_START_PENDING, 0, None);
    // `serve` does not know about the SCM, so running is reported here, before
    // it starts. Startup that then fails ends as a stop with a failure status,
    // which is what the restart policy keys on.
    report(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        None,
    );

    let exit = serve(args, Some(stop));

    *EXIT.lock().expect("not poisoned") = Some(exit);
    report(SERVICE_STOPPED, 0, Some(exit));
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0, None);
            if let Some(stop) = STOP.get() {
                // A permit is stored if nothing waits yet, so a stop that
                // arrives during startup is not lost.
                stop.notify_one();
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// The two exit-code fields of a status report, for an ending (or none yet).
fn exit_codes(exit: Option<Exit>) -> (u32, u32) {
    match exit {
        Some(Exit { code, failed: true }) => (ERROR_SERVICE_SPECIFIC_ERROR, code as u32),
        _ => (NO_ERROR, 0),
    }
}

/// Tell the SCM where the service is.
///
/// A failed `exit` is reported as a service-specific error carrying the exit
/// status, which is what `sc.exe failureflag <name> 1` makes the SCM's restart
/// actions respond to. Anything else is a clean stop — including a non-zero
/// exit that is not a failure (see [`Exit`]).
fn report(state: u32, accepted: u32, exit: Option<Exit>) {
    let Some(&handle) = STATUS_HANDLE.get() else {
        return;
    };
    let (win32, specific) = exit_codes(exit);
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: win32,
        dwServiceSpecificExitCode: specific,
        dwCheckPoint: u32::from(pending),
        dwWaitHint: if pending {
            STOP_WAIT_HINT.as_millis() as u32
        } else {
            0
        },
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and is never
    // closed; the status lives for the duration of the call.
    unsafe {
        SetServiceStatus(handle as SERVICE_STATUS_HANDLE, &status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_is_reported_as_a_service_specific_error_carrying_the_status() {
        let failed = Exit {
            code: 1,
            failed: true,
        };
        assert_eq!(exit_codes(Some(failed)), (ERROR_SERVICE_SPECIFIC_ERROR, 1));
    }

    /// The replaced-device ending exits non-zero for a console caller, and must
    /// still reach the SCM as a clean stop — otherwise `sc.exe failure` restarts
    /// it into the name its replacement now holds.
    #[test]
    fn a_non_zero_ending_that_is_not_a_failure_is_a_clean_stop() {
        let replaced = Exit {
            code: 3,
            failed: false,
        };
        assert_eq!(exit_codes(Some(replaced)), (NO_ERROR, 0));
        assert_eq!(exit_codes(None), (NO_ERROR, 0));
    }
}
