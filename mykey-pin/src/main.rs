// main.rs — CLI entry point for MyKey PIN management.
//
// Usage:
//   mykey-pin set      Set or update your MyKey PIN
//   mykey-pin change   Change your MyKey PIN
//   mykey-pin reset    Reset PIN using your Linux password
//   mykey-pin status   Show PIN and lockout status

mod daemon_client;
mod pin;

use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("set") => run_set().await,
        Some("change") => run_change().await,
        Some("reset") => run_reset(),
        Some("status") => run_status(),
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("mykey-pin set      Set or update your MyKey PIN");
    println!("mykey-pin change   Change your MyKey PIN");
    println!("mykey-pin reset    Reset PIN using your Linux password");
    println!("mykey-pin status   Show PIN and lockout status");
}

// ---------------------------------------------------------------------------
// set
// ---------------------------------------------------------------------------

async fn run_set() {
    // If a PIN is already enrolled, verify it before allowing a change.
    if pin::pin_is_set() {
        if !run_verify_current("Current MyKey PIN: ").await {
            eprintln!("Current PIN verification failed.");
            std::process::exit(1);
        }
    }
    set_new_pin().await;
}

// ---------------------------------------------------------------------------
// change
// ---------------------------------------------------------------------------

async fn run_change() {
    if !pin::pin_is_set() {
        eprintln!("No MyKey PIN is set. Use 'mykey-pin set' first.");
        std::process::exit(1);
    }
    if !run_verify_current("Current MyKey PIN: ").await {
        eprintln!("Current PIN verification failed.");
        std::process::exit(1);
    }
    set_new_pin().await;
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

fn run_reset() {
    println!("Resetting PIN requires your Linux password.");
    // Use sudo to remove the PIN file; this naturally prompts for the Linux
    // password and confirms the user's identity before deleting root-owned data.
    let status = std::process::Command::new("sudo")
        .args(["rm", "-f", pin::PIN_FILE])
        .status()
        .unwrap_or_else(|e| {
            eprintln!("Failed to run sudo: {e}");
            std::process::exit(1);
        });

    if status.success() {
        pin::record_success();
        println!("✓ MyKey PIN reset. Run mykey-pin set to create a new PIN.");
    } else {
        eprintln!("Authentication failed.");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn run_status() {
    let set = pin::pin_is_set();
    let locked = pin::is_locked_out();

    println!("MyKey PIN status:");
    println!("  PIN set:    {}", if set { "yes" } else { "no" });
    match locked {
        Some(secs) => println!("  Locked out: yes ({} seconds remaining)", secs),
        None => println!("  Locked out: no"),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Prompt for the current PIN and verify it against the TPM2-sealed hash.
///
/// Returns `true` if the PIN matches, `false` otherwise.
async fn run_verify_current(prompt: &str) -> bool {
    let entered = match prompt_pin(prompt) {
        Some(p) => p,
        None => return false,
    };

    let sealed = match std::fs::read(pin::PIN_FILE) {
        Ok(data) if !data.is_empty() => data,
        _ => {
            eprintln!("Failed to read MyKey PIN data.");
            return false;
        }
    };

    let client = match daemon_client::DaemonClient::connect().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            return false;
        }
    };

    let unsealed = match client.unseal_secret(&sealed).await {
        Ok(data) => {
            client.disconnect().await;
            data
        }
        Err(e) => {
            client.disconnect().await;
            eprintln!("Daemon unseal error: {e}");
            return false;
        }
    };

    pin::hash_pin(&entered) == unsealed
}

/// Prompt for a new PIN twice, confirm they match, seal and store it.
async fn set_new_pin() {
    let new_pin = match prompt_pin("Enter new MyKey PIN: ") {
        Some(p) => p,
        None => {
            eprintln!("Failed to read PIN.");
            std::process::exit(1);
        }
    };
    let confirm = match prompt_pin("Confirm new MyKey PIN: ") {
        Some(p) => p,
        None => {
            eprintln!("Failed to read PIN confirmation.");
            std::process::exit(1);
        }
    };

    if new_pin != confirm {
        eprintln!("PINs do not match.");
        std::process::exit(1);
    }

    let hash = Zeroizing::new(pin::hash_pin(&new_pin));

    let client = match daemon_client::DaemonClient::connect().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(1);
        }
    };

    let sealed = match client.seal_secret(&hash).await {
        Ok(blob) => {
            client.disconnect().await;
            blob
        }
        Err(e) => {
            client.disconnect().await;
            eprintln!("Daemon seal error: {e}");
            std::process::exit(1);
        }
    };

    // Ensure the directory exists (requires appropriate filesystem permissions).
    if let Err(e) = std::fs::create_dir_all(pin::PIN_DIR) {
        eprintln!("Could not create {}: {e}", pin::PIN_DIR);
        std::process::exit(1);
    }

    if let Err(e) = std::fs::write(pin::PIN_FILE, &sealed) {
        eprintln!("Could not write PIN file: {e}");
        std::process::exit(1);
    }

    pin::record_success();
    println!("✓ MyKey PIN set successfully.");
}

/// Prompt for a PIN with no terminal echo.  Returns `None` on I/O error.
fn prompt_pin(prompt: &str) -> Option<String> {
    rpassword::prompt_password(prompt).ok()
}
