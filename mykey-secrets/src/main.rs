// main.rs — Entry point for mykey-secrets, the freedesktop Secret Service provider.
//
// Registers on the D-Bus session bus as "org.freedesktop.secrets" and serves
// the Secret Service API at /org/freedesktop/secrets.

mod collection;
mod daemon_client;
mod item;
mod service;
mod session;
mod storage;

use std::process;
use log::{error, info};
use zbus::ConnectionBuilder;

#[tokio::main]
async fn main() {
    // Initialise file logger
    let log_path = "/tmp/mykey-secrets.log";
    let target = Box::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap_or_else(|e| {
                eprintln!("Cannot open log file {log_path}: {e}");
                process::exit(1);
            }),
    );
    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(target))
        .filter_level(log::LevelFilter::Debug)
        .init();

    info!("mykey-secrets starting");

    let svc = service::ServiceInterface::new();

    let conn = ConnectionBuilder::session()
        .unwrap_or_else(|e| {
            error!("Failed to connect to session bus: {e}");
            process::exit(1);
        })
        .name("org.freedesktop.secrets")
        .unwrap_or_else(|e| {
            error!("Failed to claim org.freedesktop.secrets: {e}");
            process::exit(1);
        })
        .serve_at("/org/freedesktop/secrets", svc)
        .unwrap_or_else(|e| {
            error!("Failed to serve at /org/freedesktop/secrets: {e}");
            process::exit(1);
        })
        .build()
        .await
        .unwrap_or_else(|e| {
            error!("Failed to build D-Bus connection: {e}");
            process::exit(1);
        });

    info!("mykey-secrets ready on org.freedesktop.secrets");

    // Run forever
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        let _ = &conn;
    }
}
