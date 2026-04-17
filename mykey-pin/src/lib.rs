// lib.rs — PAM module entry point for MyKey PIN authentication.
//
// Exported symbols: pam_sm_authenticate, pam_sm_setcred
// Built as a cdylib; install as /lib/security/mykeypin.so (or libmykeypin.so
// depending on distribution conventions).

mod daemon_client;
mod pin;

use pam::{export_pam_module, PamModule, PamReturnCode};
use std::ffi::CStr;
use std::os::raw::c_uint;

// ---------------------------------------------------------------------------
// Inline PAM FFI — avoids assumptions about pam_sys binding details.
// libpam is already linked by the `pam` crate dependency.
// ---------------------------------------------------------------------------

mod pam_ffi {
    use libc::{c_char, c_int, c_void};

    /// PAM message styles (pam_message.msg_style).
    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_ERROR_MSG: c_int = 3;

    /// PAM item type for the conversation struct.
    pub const PAM_CONV_ITEM: c_int = 5;

    #[repr(C)]
    pub struct PamMessage {
        pub msg_style: c_int,
        pub msg: *const c_char,
    }

    #[repr(C)]
    pub struct PamResponse {
        pub resp: *mut c_char,
        pub resp_retcode: c_int,
    }

    #[repr(C)]
    pub struct PamConv {
        pub conv: Option<
            unsafe extern "C" fn(
                num_msg: c_int,
                msg: *mut *const PamMessage,
                resp: *mut *mut PamResponse,
                appdata_ptr: *mut c_void,
            ) -> c_int,
        >,
        pub appdata_ptr: *mut c_void,
    }

    extern "C" {
        /// Retrieve a PAM item from the handle.
        pub fn pam_get_item(
            pamh: *const c_void,
            item_type: c_int,
            item: *mut *const c_void,
        ) -> c_int;
    }
}

// ---------------------------------------------------------------------------
// Conversation helper
// ---------------------------------------------------------------------------

/// Send a single PAM message and optionally collect the user's response.
///
/// Returns `Some(response)` for echo-off prompts, `None` for error/info messages.
/// Returns `None` on any conversation error.
///
/// # Safety
/// Caller must ensure `handle` points to a valid PAM handle for the duration of
/// this call.
unsafe fn pam_converse(
    handle: &pam::PamHandle,
    msg_style: libc::c_int,
    msg: &str,
) -> Option<String> {
    use pam_ffi::*;

    // Retrieve the conversation struct from the PAM handle.
    let mut conv_ptr: *const libc::c_void = std::ptr::null();
    let rc = pam_get_item(
        handle as *const pam::PamHandle as *const libc::c_void,
        PAM_CONV_ITEM,
        &mut conv_ptr,
    );
    if rc != 0 || conv_ptr.is_null() {
        return None;
    }
    let conv = &*(conv_ptr as *const PamConv);
    let conv_fn = conv.conv?;

    // Build a single-message array.
    let c_msg = std::ffi::CString::new(msg).ok()?;
    let pam_msg = PamMessage {
        msg_style,
        msg: c_msg.as_ptr(),
    };
    let pam_msg_ptr: *const PamMessage = &pam_msg;
    let mut msg_array: [*const PamMessage; 1] = [pam_msg_ptr];
    let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

    let rc = conv_fn(
        1,
        msg_array.as_mut_ptr() as *mut *const PamMessage,
        &mut resp_ptr,
        conv.appdata_ptr,
    );

    if rc != 0 {
        if !resp_ptr.is_null() {
            libc::free(resp_ptr as *mut libc::c_void);
        }
        return None;
    }

    // For prompts, extract the response string that the conversation filled in.
    if msg_style == PAM_PROMPT_ECHO_OFF {
        if resp_ptr.is_null() {
            return None;
        }
        let resp = &*resp_ptr;
        let result = if !resp.resp.is_null() {
            let s = CStr::from_ptr(resp.resp).to_string_lossy().into_owned();
            libc::free(resp.resp as *mut libc::c_void);
            Some(s)
        } else {
            None
        };
        libc::free(resp_ptr as *mut libc::c_void);
        result
    } else {
        // For PAM_ERROR_MSG / PAM_TEXT_INFO the caller does not expect a response.
        if !resp_ptr.is_null() {
            libc::free(resp_ptr as *mut libc::c_void);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// PAM module implementation
// ---------------------------------------------------------------------------

/// MyKey PIN PAM module.
pub struct MyKeyPinModule;

impl PamModule for MyKeyPinModule {
    /// Authenticate the user by verifying their MyKey PIN against the TPM2-sealed hash.
    fn authenticate(
        handle: &pam::PamHandle,
        _args: Vec<&CStr>,
        _flags: c_uint,
    ) -> PamReturnCode {
        // 1. Cooldown check.
        if let Some(secs_remaining) = pin::is_locked_out() {
            unsafe {
                pam_converse(
                    handle,
                    pam_ffi::PAM_ERROR_MSG,
                    &format!(
                        "MyKey PIN locked. Try again in {} seconds.",
                        secs_remaining
                    ),
                );
            }
            return PamReturnCode::Auth_Err;
        }

        // 2. Prompt for PIN via PAM conversation.
        let entered_pin = unsafe {
            match pam_converse(handle, pam_ffi::PAM_PROMPT_ECHO_OFF, "MyKey PIN: ") {
                Some(p) => p,
                None => return PamReturnCode::Auth_Err,
            }
        };

        // 3. Ensure a PIN has been enrolled.
        if !pin::pin_is_set() {
            unsafe {
                pam_converse(
                    handle,
                    pam_ffi::PAM_ERROR_MSG,
                    "No MyKey PIN is set. Run: mykey-pin set",
                );
            }
            return PamReturnCode::Auth_Err;
        }

        // 4. Read the sealed PIN hash from disk.
        let sealed = match std::fs::read(pin::PIN_FILE) {
            Ok(data) if !data.is_empty() => data,
            _ => {
                unsafe {
                    pam_converse(
                        handle,
                        pam_ffi::PAM_ERROR_MSG,
                        "Failed to read MyKey PIN data.",
                    );
                }
                return PamReturnCode::Auth_Err;
            }
        };

        // 5. Unseal the PIN hash via mykey-daemon over D-Bus.
        let unsealed = {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return PamReturnCode::Auth_Err,
            };

            match rt.block_on(async {
                let client = daemon_client::DaemonClient::connect().await?;
                let result = client.unseal_secret(&sealed).await;
                client.disconnect().await;
                result
            }) {
                Ok(data) => data,
                Err(_) => {
                    unsafe {
                        pam_converse(
                            handle,
                            pam_ffi::PAM_ERROR_MSG,
                            "MyKey daemon error. Is mykey-daemon running?",
                        );
                    }
                    return PamReturnCode::Auth_Err;
                }
            }
        };

        // 6. Compare the hash of the entered PIN against the unsealed reference.
        let entered_hash = pin::hash_pin(&entered_pin);
        if entered_hash == unsealed {
            pin::record_success();
            PamReturnCode::Success
        } else {
            pin::record_failed_attempt();
            let state = pin::read_attempts();
            unsafe {
                if state.failed_sessions >= pin::MAX_ATTEMPTS {
                    pam_converse(
                        handle,
                        pam_ffi::PAM_ERROR_MSG,
                        &format!(
                            "Too many failed attempts. Locked for {} seconds.",
                            pin::cooldown_secs(state.failed_sessions)
                        ),
                    );
                } else {
                    pam_converse(handle, pam_ffi::PAM_ERROR_MSG, "Incorrect MyKey PIN.");
                }
            }
            PamReturnCode::Auth_Err
        }
    }

    /// No-op; credential management is not required for this module.
    fn set_credentials(
        _handle: &pam::PamHandle,
        _args: Vec<&CStr>,
        _flags: c_uint,
    ) -> PamReturnCode {
        PamReturnCode::Success
    }
}

export_pam_module!(MyKeyPinModule);
