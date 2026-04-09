// main.rs — Chrome Native Messaging host entry point.
//
// Chrome Native Messaging protocol:
//   - Every message is prefixed with a 4-byte little-endian u32 length field.
//   - The payload is that many bytes of UTF-8 JSON.
//   - stdout is exclusively the response channel — NEVER write anything else to it.
//   - Log to a file; never to stdout or stderr in a way Chrome would misinterpret.

use std::io::{self, Read, Write};
use log::{debug, error, info};

mod authentication;
mod crypto;
mod dbus_client;
mod pam;
mod protocol;
mod registration;
mod session;
mod tpm;

// ---------------------------------------------------------------------------
// Logger setup — file only, never stdout
// ---------------------------------------------------------------------------

fn setup_logger() {
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/mykey-host.log")
        .expect("Failed to open /tmp/mykey-host.log");

    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs()
        .init();
}

// ---------------------------------------------------------------------------
// Framing: 4-byte LE length prefix
// ---------------------------------------------------------------------------

fn read_message(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_message(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(data)?;
    writer.flush()
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn error_response(request_id: &str, code: &str, message: &str) -> Vec<u8> {
    serde_json::json!({
        "requestId": request_id,
        "status":    "error",
        "code":      code,
        "message":   message,
    })
    .to_string()
    .into_bytes()
}

fn dispatch(raw: &[u8], session: &session::DaemonSession) -> Vec<u8> {
    let envelope: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(e) => {
            error!("JSON parse error: {e}");
            return error_response("unknown", "parse_error", &format!("JSON parse error: {e}"));
        }
    };

    let request_id = envelope["requestId"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned();

    let msg_type = match envelope["type"].as_str() {
        Some(t) => t,
        None => {
            error!("Message missing 'type' field, requestId={request_id}");
            return error_response(&request_id, "missing_type", "Message is missing 'type'");
        }
    };

    debug!("dispatch: type={msg_type} requestId={request_id}");

    match msg_type {
        "create" => {
            let req: protocol::CreateRequest = match serde_json::from_value(envelope) {
                Ok(r) => r,
                Err(e) => {
                    error!("Failed to deserialise CreateRequest: {e}");
                    return error_response(&request_id, "bad_request", &format!("{e}"));
                }
            };
            match registration::handle_create(req, session) {
                Ok(resp)  => wrap_ok(&request_id, resp),
                Err(e)    => { error!("Registration error: {e}"); error_response(&request_id, "registration_error", &e) }
            }
        }

        "get" => {
            let req: protocol::GetRequest = match serde_json::from_value(envelope) {
                Ok(r) => r,
                Err(e) => {
                    error!("Failed to deserialise GetRequest: {e}");
                    return error_response(&request_id, "bad_request", &format!("{e}"));
                }
            };
            match authentication::handle_get(req, session) {
                Ok(resp)  => wrap_ok(&request_id, resp),
                Err(e)    => { error!("Authentication error: {e}"); error_response(&request_id, "authentication_error", &e) }
            }
        }

        unknown => {
            error!("Unknown message type: {unknown}");
            error_response(&request_id, "unknown_type", &format!("Unknown type: {unknown}"))
        }
    }
}

fn wrap_ok<T: serde::Serialize>(request_id: &str, payload: T) -> Vec<u8> {
    let mut value = serde_json::to_value(payload).expect("serialise response");
    value["requestId"] = serde_json::json!(request_id);
    value["status"]    = serde_json::json!("ok");
    serde_json::to_vec(&value).expect("serialise to bytes")
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    setup_logger();
    info!(
        "mykey-host started (pid={}, version={})",
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );

    let session = match session::DaemonSession::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to daemon: {e}");
            std::process::exit(1);
        }
    };
    info!("Connected to daemon, session established");

    let stdin  = io::stdin();
    let stdout = io::stdout();
    let mut stdin_lock  = stdin.lock();
    let mut stdout_lock = stdout.lock();

    loop {
        match read_message(&mut stdin_lock) {
            Ok(Some(bytes)) if bytes.is_empty() => {
                debug!("Received zero-length message, ignoring");
            }
            Ok(Some(bytes)) => {
                let response = dispatch(&bytes, &session);
                if let Err(e) = write_message(&mut stdout_lock, &response) {
                    error!("Failed to write response: {e}");
                    break;
                }
            }
            Ok(None) => {
                info!("stdin closed — shutting down");
                break;
            }
            Err(e) => {
                error!("Read error on stdin: {e}");
                break;
            }
        }
    }

    let _ = session.client.disconnect(std::process::id());
    info!("mykey-host exiting");
}
