// session.rs — Session tracking for the Secret Service API.
//
// Each OpenSession call creates a Session entry identified by a UUID.
// Only the "plain" algorithm is supported in this implementation.

use std::collections::HashMap;
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
