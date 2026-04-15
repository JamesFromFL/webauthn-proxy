// session.rs — Session tracking and D-Bus interface for the Secret Service API.
//
// Each OpenSession call creates a Session entry identified by a UUID and
// registers a SessionInterface object on the D-Bus object server so that
// clients can call org.freedesktop.Secret.Session.Close() on it.
// Only the "plain" algorithm is supported in this implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use log::info;
use uuid::Uuid;

/// A single Secret Service session.
pub struct Session {
    pub id: String,
    pub algorithm: String,
}

/// In-memory store of active sessions.
pub struct SessionStore {
    sessions: HashMap<String, Session>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: HashMap::new(),
        }
    }

    /// Create a new session with the given algorithm and return its ID.
    pub fn create(&mut self, algorithm: String) -> String {
        let id = Uuid::new_v4().to_string();
        self.sessions.insert(id.clone(), Session { id: id.clone(), algorithm });
        id
    }

    /// Look up a session by ID.
    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Remove a session by ID.
    pub fn remove(&mut self, id: &str) {
        self.sessions.remove(id);
    }
}

// ---------------------------------------------------------------------------
// SessionInterface — org.freedesktop.Secret.Session D-Bus object
// ---------------------------------------------------------------------------

/// Implements org.freedesktop.Secret.Session for a single session.
///
/// Registered at /org/freedesktop/secrets/session/{id} by OpenSession.
/// Clients (libsecret, git-credential-libsecret) call Close() when they are
/// done with a session; without this object being registered they receive an
/// UnknownObject error which can confuse the client.
pub struct SessionInterface {
    pub session_id: String,
    /// Shared session store so Close() can remove this session on cleanup.
    pub sessions: Arc<Mutex<SessionStore>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Session")]
impl SessionInterface {
    /// Close this session.  Removes it from the in-memory SessionStore.
    async fn close(&self) -> Result<(), zbus::fdo::Error> {
        info!("[session] Close called for session={}", self.session_id);
        self.sessions.lock().unwrap().remove(&self.session_id);
        Ok(())
    }
}
