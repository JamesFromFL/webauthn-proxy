// pam.rs — User presence verification via polkit.
//
// The daemon runs as a system user with no terminal. Polkit handles
// authentication dialogs on the user's desktop session correctly.
//
// polkit action: com.mykey.authenticate
// This prompts the user with their system password or fingerprint
// via the desktop's authentication agent.
//
// Brute-force protection:
//   - Up to 3 pkcheck attempts per session before the session is counted as failed.
//   - Increasing cooldown periods after consecutive failed sessions.
//   - A successful authentication resets the failed-session counter to zero.

use log::{error, info, warn};
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Count of consecutive sessions where all 3 attempts failed.
static FAILED_SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// Unix timestamp (seconds) after which authentication is permitted again.
/// Zero means no active cooldown.
static COOLDOWN_UNTIL: AtomicU64 = AtomicU64::new(0);

/// Current time as Unix seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Cooldown duration in seconds for a given number of consecutive failed sessions.
fn cooldown_secs(failed_sessions: usize) -> u64 {
    match failed_sessions {
        1 => 60,
        2 => 5 * 60,
        3 => 15 * 60,
        4 => 30 * 60,
        5 => 3600,
        6 => 2 * 3600,
        _ => 5 * 3600,
    }
}

/// Verify user presence using polkit.
///
/// Allows up to 3 pkcheck attempts per call.  If all 3 fail the session is
/// counted as failed and a cooldown is imposed.  Returns `Err` immediately
/// if a cooldown is currently active.
///
/// A successful authentication resets the failed-session counter to zero.
pub async fn verify_user_presence(calling_pid: u32) -> Result<bool, String> {
    // ── 1. Cooldown check (fast path — no blocking thread needed) ─────────
    let now = now_secs();
    let locked_until = COOLDOWN_UNTIL.load(Ordering::Relaxed);
    if now < locked_until {
        let remaining = locked_until - now;
        return Err(format!(
            "Authentication locked. Try again in {}m {}s",
            remaining / 60,
            remaining % 60,
        ));
    }

    // ── 2. Up to 3 attempts inside a blocking task ────────────────────────
    tokio::task::spawn_blocking(move || {
        info!("Starting polkit user-presence check for pid={}", calling_pid);

        for attempt in 1u32..=3 {
            let output = Command::new("pkcheck")
                .args([
                    "--action-id", "com.mykey.authenticate",
                    "--process", &calling_pid.to_string(),
                    "--allow-user-interaction",
                ])
                .output()
                .map_err(|e| format!("pkcheck failed to run: {e}"))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // pkcheck exit code 0 = authorized.
            // Some polkit versions also print "auth_self" or "auth_admin" to
            // stdout when the action was granted after a credential challenge —
            // accept those as success even if the exit code is non-zero.
            if output.status.success()
                || stdout.contains("auth_self")
                || stdout.contains("auth_admin")
            {
                info!("Polkit user-presence check succeeded for pid={}", calling_pid);
                FAILED_SESSIONS.store(0, Ordering::Relaxed);
                COOLDOWN_UNTIL.store(0, Ordering::Relaxed);
                return Ok(true);
            }

            error!(
                "Polkit attempt {}/3 failed for pid={}: stdout={} stderr={}",
                attempt, calling_pid, stdout, stderr
            );
        }

        // ── 3. All 3 attempts exhausted → record failed session + cooldown ─
        let failed = FAILED_SESSIONS.fetch_add(1, Ordering::Relaxed) + 1;
        let secs = cooldown_secs(failed);
        COOLDOWN_UNTIL.store(now_secs() + secs, Ordering::Relaxed);
        warn!(
            "All 3 polkit attempts failed for pid={} — \
             failed sessions: {}, cooldown: {}s",
            calling_pid, failed, secs
        );
        Ok(false)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}
