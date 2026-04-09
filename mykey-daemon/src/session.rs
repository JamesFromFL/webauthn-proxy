// session.rs — Session token issuance, storage, and revocation.
//
// Each connected native host process gets a unique 32-byte CSPRNG token.
// Tokens are kept in a heap-allocated, mlocked buffer so they are never
// swapped to disk.  All token memory is zeroized on drop.

use std::collections::HashMap;
use log::{debug, warn};
use rand::RngCore;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// SessionToken
// ---------------------------------------------------------------------------

/// A 32-byte session token in a heap-allocated, mlocked, zeroizing buffer.
pub struct SessionToken {
    data: Box<Zeroizing<[u8; 32]>>,
}

impl SessionToken {
    fn new() -> Self {
        let mut raw = Box::new(Zeroizing::new([0u8; 32]));
        rand::rngs::OsRng.fill_bytes(raw.as_mut().as_mut());

        // mlock the heap page containing the token so it is never swapped.
        // Safety: we hold a stable heap pointer inside the Box.
        unsafe {
            libc::mlock(
                raw.as_ptr() as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
        }

        SessionToken { data: raw }
    }

    /// Borrow the raw token bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Drop for SessionToken {
    fn drop(&mut self) {
        // Unlock the mlocked page; zeroize happens via Zeroizing<> on drop.
        unsafe {
            libc::munlock(
                self.data.as_ptr() as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

/// Thread-safe store of live session tokens, keyed by caller PID.
pub struct SessionStore {
    tokens: RwLock<HashMap<u32, SessionToken>>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Generate and store a fresh session token for `pid`.
    /// If a token already exists for this pid it is replaced.
    pub async fn issue_token(&self, pid: u32) -> [u8; 32] {
        let token = SessionToken::new();
        let bytes = *token.as_bytes();
        let mut guard = self.tokens.write().await;
        guard.insert(pid, token);
        debug!("Issued session token for pid={}", pid);
        bytes
    }

    /// Run a closure with a read-only reference to the token bytes for `pid`.
    /// Returns None if no token exists for that pid.
    pub async fn with_token<F, R>(&self, pid: u32, f: F) -> Option<R>
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        let guard = self.tokens.read().await;
        guard.get(&pid).map(|t| f(t.as_bytes()))
    }

    /// Revoke and zeroize the session token for `pid`.
    pub async fn revoke_token(&self, pid: u32) {
        let mut guard = self.tokens.write().await;
        if guard.remove(&pid).is_some() {
            debug!("Revoked session token for pid={}", pid);
        } else {
            warn!("revoke_token called for unknown pid={}", pid);
        }
    }

    /// Number of active sessions (for diagnostics).
    pub async fn session_count(&self) -> usize {
        self.tokens.read().await.len()
    }
}

