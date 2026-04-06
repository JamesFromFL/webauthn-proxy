// replay.rs — Replay attack prevention via sequence numbers and timestamps.
//
// Every authenticated request carries a sequence number and a Unix timestamp.
// The ReplayCache rejects requests outside a 30-second window and any sequence
// number it has already seen.  Old entries are pruned on each check.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use log::{debug, warn};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ReplayError {
    /// Request timestamp is outside the acceptance window.
    Expired { timestamp_secs: u64, now: u64, window: u64 },
    /// Sequence number has already been processed.
    Replay { sequence: u64 },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::Expired { timestamp_secs, now, window } => write!(
                f,
                "request expired: timestamp={timestamp_secs} now={now} window={window}s"
            ),
            ReplayError::Replay { sequence } => {
                write!(f, "replay detected: sequence={sequence} already seen")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayCache
// ---------------------------------------------------------------------------

/// Seen sequence numbers with their acceptance timestamp, plus the window size.
pub struct ReplayCache {
    /// sequence → the Unix second at which it was recorded
    seen: HashMap<u64, u64>,
    window_seconds: u64,
}

impl ReplayCache {
    pub fn new(window_seconds: u64) -> Self {
        ReplayCache {
            seen: HashMap::new(),
            window_seconds,
        }
    }

    /// Validate and record a (sequence, timestamp) pair.
    ///
    /// Rejects if:
    ///   - `timestamp_secs` is more than `window_seconds` in the past or future
    ///   - `sequence` has already been seen within the window
    ///
    /// On accept, records the sequence number and prunes entries older than
    /// `window_seconds`.
    pub fn check_and_record(
        &mut self,
        sequence: u64,
        timestamp_secs: u64,
    ) -> Result<(), ReplayError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Timestamp window check
        let age = now.saturating_sub(timestamp_secs);
        let skew = timestamp_secs.saturating_sub(now);
        if age > self.window_seconds || skew > self.window_seconds {
            warn!(
                "[replay] Rejecting expired request: seq={sequence} ts={timestamp_secs} now={now}"
            );
            return Err(ReplayError::Expired {
                timestamp_secs,
                now,
                window: self.window_seconds,
            });
        }

        // Replay check
        if self.seen.contains_key(&sequence) {
            warn!("[replay] Replay attack detected: seq={sequence} already seen");
            return Err(ReplayError::Replay { sequence });
        }

        // Record and prune
        self.seen.insert(sequence, now);
        self.prune(now);

        debug!("[replay] Accepted: seq={sequence} ts={timestamp_secs}");
        Ok(())
    }

    /// Remove sequence numbers whose recorded timestamp is outside the window.
    fn prune(&mut self, now: u64) {
        self.seen.retain(|_seq, recorded_at| {
            now.saturating_sub(*recorded_at) <= self.window_seconds
        });
    }

    /// Count of currently tracked sequence numbers (for diagnostics).
    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

// ---------------------------------------------------------------------------
// Async wrapper
// ---------------------------------------------------------------------------

/// Thread-safe replay cache for use in the async daemon.
pub struct AsyncReplayCache {
    inner: Mutex<ReplayCache>,
}

impl AsyncReplayCache {
    pub fn new() -> Self {
        AsyncReplayCache {
            inner: Mutex::new(ReplayCache::new(30)), // 30-second window
        }
    }

    pub async fn check_and_record(
        &self,
        sequence: u64,
        timestamp_secs: u64,
    ) -> Result<(), ReplayError> {
        self.inner.lock().await.check_and_record(sequence, timestamp_secs)
    }

    /// Clear all seen sequence numbers.
    ///
    /// Called on Connect() so that each new native host session starts with a
    /// clean replay window — the host's sequence counter resets to 1 on each
    /// DaemonSession::new(), and the daemon cache must match.
    pub async fn clear_for_session(&self) {
        let mut cache = self.inner.lock().await;
        cache.seen.clear();
        debug!("[replay] Cache cleared for new session");
    }
}
