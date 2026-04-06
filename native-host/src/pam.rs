// pam.rs — PAM user-presence verification.
//
// Every WebAuthn operation must pass through this gate before key material is
// touched.  The conversation handler reads prompts and secret input from
// /dev/tty so that stdin/stdout remain available for the Chrome Native
// Messaging protocol.
//
// PAM service file: /etc/pam.d/mykey-proxy  (created by scripts/install.sh)

use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::unix::io::AsRawFd;

use log::{error, info, warn};

// ---------------------------------------------------------------------------
// Conversation handler
// ---------------------------------------------------------------------------

struct TtyConversation {
    username: String,
}

impl pam::Conversation for TtyConversation {
    /// Echo-on prompt — typically the username.  Return the already-known user.
    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()> {
        let prompt = msg.to_string_lossy().into_owned();
        tty_print(&prompt);
        CString::new(self.username.as_bytes()).map_err(|_| ())
    }

    /// Echo-off prompt — password or PIN.  Read from /dev/tty with echo off.
    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()> {
        let prompt = msg.to_string_lossy().into_owned();
        read_tty_secret(&prompt).map_err(|e| {
            error!("Failed to read secret from /dev/tty: {}", e);
        })
    }

    fn info(&mut self, msg: &CStr) {
        let s = msg.to_string_lossy().into_owned();
        info!("PAM info: {}", s);
        tty_print(&format!("{}\n", s));
    }

    fn error(&mut self, msg: &CStr) {
        let s = msg.to_string_lossy().into_owned();
        warn!("PAM error message: {}", s);
        tty_print(&format!("Error: {}\n", s));
    }
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Verify that the logged-in user is physically present by performing a full
/// PAM authentication against the "mykey-proxy" service.
///
/// Returns `true` on success, `false` if the challenge fails or is cancelled.
/// Never logs credential content.
pub fn verify_user_presence() -> bool {
    let username = current_username();
    info!("Starting PAM user-presence check for '{}'", username);

    let conv = TtyConversation { username: username.clone() };

    let mut client = match pam::Client::with_conversation("mykey-proxy", conv) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to initialise PAM client: {}", e);
            return false;
        }
    };

    match client.authenticate() {
        Ok(()) => {
            info!("PAM authentication succeeded for '{}'", username);
            true
        }
        Err(e) => {
            warn!("PAM authentication failed for '{}': {}", username, e);
            false
        }
    }
}

// ---------------------------------------------------------------------------
// /dev/tty helpers
// ---------------------------------------------------------------------------

/// Write a message to /dev/tty (bypasses stdin/stdout messaging channel).
fn tty_print(msg: &str) {
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = tty.write_all(msg.as_bytes());
        let _ = tty.flush();
    }
}

/// Read a secret line from /dev/tty with terminal echo disabled.
/// Restores echo and prints a newline before returning.
fn read_tty_secret(prompt: &str) -> Result<CString, String> {
    use std::io::BufRead;

    // Separate handles: one for writing prompts, one for reading input.
    // Both refer to the same terminal device so tcsetattr on the read fd
    // affects both.
    let mut tty_out = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("Cannot open /dev/tty for writing: {e}"))?;

    let tty_in = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(|e| format!("Cannot open /dev/tty for reading: {e}"))?;

    let fd = tty_in.as_raw_fd();

    // Print the prompt
    write!(tty_out, "{}", prompt).ok();
    tty_out.flush().ok();

    // Save current termios state
    let mut old_term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut old_term) } != 0 {
        return Err(format!("tcgetattr failed: {}", std::io::Error::last_os_error()));
    }

    // Disable echo
    let mut no_echo = old_term;
    no_echo.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &no_echo) } != 0 {
        return Err(format!("tcsetattr(disable echo) failed: {}", std::io::Error::last_os_error()));
    }

    // Read the secret (BufReader scope ends before we restore termios)
    let secret = {
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(&tty_in);
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read_line from /dev/tty failed: {e}"))?;
        line
    };

    // Restore echo and print a newline so the cursor moves down
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &old_term) };
    writeln!(tty_out).ok();

    let trimmed = secret.trim_end_matches(|c: char| c == '\n' || c == '\r');
    CString::new(trimmed).map_err(|_| "Secret contains a null byte".to_string())
}

// ---------------------------------------------------------------------------
// Username resolution
// ---------------------------------------------------------------------------

/// Determine the current user's login name.
///
/// Priority: $USER → $LOGNAME → getpwuid(getuid()).
fn current_username() -> String {
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() {
            return u;
        }
    }
    if let Ok(u) = std::env::var("LOGNAME") {
        if !u.is_empty() {
            return u;
        }
    }
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let name = CStr::from_ptr((*pw).pw_name);
            return name.to_string_lossy().into_owned();
        }
    }
    "unknown".to_string()
}
