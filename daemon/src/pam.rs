// pam.rs — User presence verification via polkit.
//
// The daemon runs as a system user with no terminal. Polkit handles
// authentication dialogs on the user's desktop session correctly.
//
// polkit action: com.webauthnproxy.authenticate
// This prompts the user with their system password or fingerprint
// via the desktop's authentication agent.

use log::{error, info};
use std::process::Command;

/// Verify user presence using polkit.
///
/// Calls pkcheck to verify the calling user can perform the
/// com.webauthnproxy.authenticate action. This triggers the
/// desktop authentication agent to prompt the user.
pub async fn verify_user_presence(calling_pid: u32) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || {
        info!("Starting polkit user-presence check for pid={}", calling_pid);

        let output = Command::new("pkcheck")
            .args([
                "--action-id", "com.webauthnproxy.authenticate",
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
            Ok(true)
        } else {
            error!(
                "Polkit check failed for pid={}: stdout={} stderr={}",
                calling_pid, stdout, stderr
            );
            Ok(false)
        }
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}
