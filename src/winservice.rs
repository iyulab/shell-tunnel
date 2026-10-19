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
/// The name the SCM started this service under (`argv[0]` of `service_main`),
/// NUL-terminated. The process cannot otherwise learn it.
static SERVICE_NAME: OnceLock<Vec<u16>> = OnceLock::new();

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

unsafe extern "system" fn service_main(argc: u32, argv: *mut windows_sys::core::PWSTR) {
    let Some(Pending { args, serve }) = PENDING.lock().expect("not poisoned").take() else {
        return;
    };
    // SAFETY: the SCM passes `argc` valid NUL-terminated strings; the first
    // is the service's name.
    if argc >= 1 && !argv.is_null() {
        let first = unsafe { *argv };
        if !first.is_null() {
            let len = (0..).take_while(|&i| unsafe { *first.add(i) } != 0).count();
            let mut name = unsafe { std::slice::from_raw_parts(first, len) }.to_vec();
            name.push(0);
            let _ = SERVICE_NAME.set(name);
        }
    }
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

#[cfg(all(test, feature = "self-update", feature = "relay-client"))]
pub(crate) fn exit_codes_for_test(exit: Option<Exit>) -> (u32, u32) {
    exit_codes(exit)
}

/// Whether the SCM started this process as a service.
pub fn is_service() -> bool {
    SERVICE_NAME.get().is_some()
}

/// The name the SCM started this service under, or `<name>` outside one.
#[cfg(all(feature = "self-update", feature = "relay-client"))]
pub fn service_name() -> String {
    match SERVICE_NAME.get() {
        Some(name) => String::from_utf16_lossy(&name[..name.len() - 1]),
        None => "<name>".to_string(),
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

/// Reading the service's restart policy, which only following relay updates
/// needs: a Windows device comes back as the new binary by being restarted.
#[cfg(all(feature = "self-update", feature = "relay-client"))]
mod failure_restart {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W, SC_ACTION,
        SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONFIG_FAILURE_ACTIONS,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
        SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_QUERY_CONFIG,
    };

    use super::SERVICE_NAME;

    /// Whether the SCM will start this service again after it ends with a
    /// failure — which is how a Windows device comes back after an update.
    ///
    /// True only when the failure actions include a restart *and* the flag that
    /// applies them to a non-crash failure is on (`sc.exe failureflag <name> 1`):
    /// without the flag a process that exits on purpose, as an update does, is
    /// not restarted. `Err` when this process is not a service or the
    /// configuration cannot be read.
    pub fn restarts_on_failure() -> Result<bool, String> {
        let name = SERVICE_NAME
            .get()
            .ok_or("not running as a Windows service")?;
        // SAFETY: handles are checked before use and closed on every path.
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return Err(format!(
                    "cannot open the service manager (error {})",
                    GetLastError()
                ));
            }
            let service = OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_CONFIG);
            if service.is_null() {
                let error = GetLastError();
                CloseServiceHandle(scm);
                return Err(format!("cannot open this service (error {error})"));
            }
            let result = read_restart_policy(service);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            result
        }
    }

    /// # Safety
    /// `service` must be an open handle with `SERVICE_QUERY_CONFIG`.
    unsafe fn read_restart_policy(service: SC_HANDLE) -> Result<bool, String> {
        let actions = unsafe { query_config(service, SERVICE_CONFIG_FAILURE_ACTIONS) }?;
        // SAFETY: the SCM wrote a SERVICE_FAILURE_ACTIONSW at the buffer's start,
        // and the array it points to lives in the same buffer.
        let fa = unsafe { &*(actions.as_ptr() as *const SERVICE_FAILURE_ACTIONSW) };
        let list: &[SC_ACTION] = if fa.cActions == 0 || fa.lpsaActions.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(fa.lpsaActions, fa.cActions as usize) }
        };
        let flag = unsafe { query_config(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG) }?;
        let flag = unsafe { &*(flag.as_ptr() as *const SERVICE_FAILURE_ACTIONS_FLAG) };
        Ok(restart_policy(
            list,
            flag.fFailureActionsOnNonCrashFailures != 0,
        ))
    }

    /// One `QueryServiceConfig2W` level, in an 8-aligned buffer of the size the
    /// SCM asks for.
    ///
    /// # Safety
    /// `service` must be an open handle with `SERVICE_QUERY_CONFIG`.
    unsafe fn query_config(service: SC_HANDLE, level: u32) -> Result<Vec<u64>, String> {
        let mut needed = 0u32;
        unsafe { QueryServiceConfig2W(service, level, std::ptr::null_mut(), 0, &mut needed) };
        let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let ok = unsafe {
            QueryServiceConfig2W(
                service,
                level,
                buf.as_mut_ptr() as *mut u8,
                (buf.len() * 8) as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(format!(
                "cannot read the service's failure actions (error {})",
                unsafe { GetLastError() }
            ));
        }
        Ok(buf)
    }

    /// The decision itself, apart from reading it out of the SCM.
    fn restart_policy(actions: &[SC_ACTION], on_non_crash_failures: bool) -> bool {
        on_non_crash_failures && actions.iter().any(|a| a.Type == SC_ACTION_RESTART)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_restart_counts_only_when_failure_actions_apply_to_non_crash_failures() {
            use windows_sys::Win32::System::Services::{SC_ACTION_NONE, SC_ACTION_REBOOT};
            let restart = SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5000,
            };
            let none = SC_ACTION {
                Type: SC_ACTION_NONE,
                Delay: 0,
            };
            let reboot = SC_ACTION {
                Type: SC_ACTION_REBOOT,
                Delay: 0,
            };
            assert!(restart_policy(&[none, restart], true));
            // `sc.exe failure` without `failureflag 1`: an exit on purpose is not
            // restarted, so an update would leave the device down.
            assert!(!restart_policy(&[restart], false));
            assert!(!restart_policy(&[], true));
            assert!(!restart_policy(&[reboot, none], true));
        }

        #[test]
        fn outside_a_service_the_restart_policy_is_an_error_not_a_guess() {
            assert!(restarts_on_failure().is_err());
        }
    }
}

#[cfg(all(feature = "self-update", feature = "relay-client"))]
pub use failure_restart::restarts_on_failure;
