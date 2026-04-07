// main.rs — MyKey Proxy system tray application entry point.

mod tray;

use log::info;

fn setup_logger() {
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/mykey-proxy-tray.log")
        .expect("Failed to open /tmp/mykey-proxy-tray.log");

    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs()
        .init();
}

fn main() {
    setup_logger();
    info!(
        "mykey-proxy-tray started (pid={}, version={})",
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );

    let service = ksni::TrayService::new(tray::WebAuthnTray::new());
    service.spawn();

    info!("[tray] Tray service spawned, entering idle loop");

    // Park the main thread — the tray runs on its own D-Bus thread.
    // SIGTERM / Quit menu item will call process::exit directly.
    loop {
        std::thread::park();
    }
}
