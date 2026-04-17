// pin.rs — Shared PIN logic used by both the PAM module and CLI.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PIN_DIR: &str = "/etc/mykey/pin";
pub const PIN_FILE: &str = "/etc/mykey/pin/sealed_pin";
pub const ATTEMPTS_FILE: &str = "/etc/mykey/pin/attempts";
pub const MAX_ATTEMPTS: usize = 3;

/// Current time as Unix seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Cooldown duration in seconds for a given number of consecutive failed sessions.
pub fn cooldown_secs(failed_sessions: usize) -> u64 {
    match failed_sessions {
        1 => 60,
        2 => 5 * 60,
        3 => 15 * 60,
        4 => 30 * 60,
        _ => 3600,
    }
}

/// Persistent state for brute-force tracking.
#[derive(Serialize, Deserialize, Default)]
pub struct AttemptsState {
    /// Number of consecutive sessions where authentication failed.
    pub failed_sessions: usize,
    /// Unix timestamp after which authentication is permitted again; 0 = no cooldown.
    pub cooldown_until: u64,
}

/// Returns `true` if `PIN_FILE` exists and is non-empty.
pub fn pin_is_set() -> bool {
    std::fs::metadata(PIN_FILE)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// SHA-256 hash of the PIN bytes, returned as a `Vec<u8>`.
pub fn hash_pin(pin: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    hasher.finalize().to_vec()
}

/// Read the current attempts state from `ATTEMPTS_FILE`.
///
/// Returns a zeroed-out default if the file is missing or unparseable.
pub fn read_attempts() -> AttemptsState {
    std::fs::read_to_string(ATTEMPTS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Write `state` to `ATTEMPTS_FILE` as JSON.  Best-effort; errors are ignored.
pub fn write_attempts(state: &AttemptsState) {
    if let Ok(json) = serde_json::to_string(state) {
        let _ = std::fs::write(ATTEMPTS_FILE, json);
    }
}

/// Returns `Some(seconds_remaining)` if a cooldown is currently active, or `None`.
pub fn is_locked_out() -> Option<u64> {
    let state = read_attempts();
    let now = now_secs();
    if state.cooldown_until > now {
        Some(state.cooldown_until - now)
    } else {
        None
    }
}

/// Increment the failed-session counter and impose a new cooldown.
pub fn record_failed_attempt() {
    let mut state = read_attempts();
    state.failed_sessions += 1;
    state.cooldown_until = now_secs() + cooldown_secs(state.failed_sessions);
    write_attempts(&state);
}

/// Reset the failed-session counter and clear any active cooldown.
pub fn record_success() {
    write_attempts(&AttemptsState {
        failed_sessions: 0,
        cooldown_until: 0,
    });
}
