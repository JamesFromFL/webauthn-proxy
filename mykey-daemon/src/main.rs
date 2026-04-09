// main.rs — MyKey Proxy D-Bus daemon entry point.
//
// Startup order:
//   1. Initialise file logger (never stdout/stderr in production)
//   2. Enforce prerequisites (Secure Boot, TPM2, binary integrity)
//   3. Build shared daemon state (session store, replay cache)
//   4. Register D-Bus service "com.mykey.Daemon" on the system bus
//   5. Run the tokio event loop indefinitely

use std::sync::Arc;
use log::{error, info};

mod authentication;
mod credentials;
mod crypto;
mod crypto_ops;
mod dbus_interface;
mod pam;
mod prereqs;
mod protocol;
mod registration;
mod replay;
mod session;
mod tpm;
mod validator;

use dbus_interface::DaemonInterface;

// ---------------------------------------------------------------------------
// Logger — file only; daemon must never write to stdout/stderr carelessly
// ---------------------------------------------------------------------------

fn setup_logger() {
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/mykey-daemon.log")
        .expect("Failed to open /tmp/mykey-daemon.log");

    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs()
        .init();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    setup_logger();

    info!(
        "mykey-daemon starting (pid={}, version={})",
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );

    // ── Prerequisites ─────────────────────────────────────────────────────
    if let Err(e) = prereqs::enforce_prereqs() {
        error!("Prerequisites check failed: {}", e);
        eprintln!("[mykey-daemon] Prerequisites check failed: {e}");
        std::process::exit(1);
    }

    // ── Shared state ──────────────────────────────────────────────────────
    let state = Arc::new(dbus_interface::DaemonState::new());

    // ── D-Bus service ─────────────────────────────────────────────────────
    let interface = DaemonInterface::new(Arc::clone(&state));

    let conn = match zbus::connection::Builder::system()
        .and_then(|b| b.name("com.mykey.Daemon"))
        .and_then(|b| b.serve_at("/com/mykey/Daemon", interface))
    {
        Ok(builder) => match builder.build().await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to build D-Bus connection: {}", e);
                eprintln!("[mykey-daemon] D-Bus connection failed: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            error!("Failed to configure D-Bus builder: {}", e);
            eprintln!("[mykey-daemon] D-Bus builder failed: {e}");
            std::process::exit(1);
        }
    };

    info!(
        "D-Bus service registered: name='com.mykey.Daemon' path='/com/mykey/Daemon'"
    );

    // Keep the connection alive.  The daemon exits only on signal or fatal error.
    // `conn` must stay in scope — dropping it closes the D-Bus connection.
    let _ = conn;
    std::future::pending::<()>().await;
}
