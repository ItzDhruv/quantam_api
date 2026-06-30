use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::did::model::DidDocument;

/// In-memory registry of created DID documents, shared as Axum router state.
///
/// This is the first persistence increment: it survives across requests within
/// a single running process but not across restarts. The `insert`/`get` surface
/// is intentionally storage-agnostic so it can later be backed by a database or
/// IPFS without changing the handlers (see `resolve_did_handler` /
/// `get_public_keys_handler`).
#[derive(Clone, Default)]
pub struct DidStore {
    inner: Arc<RwLock<HashMap<String, DidDocument>>>,
}

impl DidStore {
    /// Store (or overwrite) the document for `did`.
    pub fn insert(&self, did: String, doc: DidDocument) {
        // A poisoned lock means another thread panicked while holding it; that
        // is an unrecoverable internal invariant, not user-controlled input.
        self.inner
            .write()
            .expect("DID store lock poisoned")
            .insert(did, doc);
    }

    /// Return a clone of the stored document for `did`, if it exists.
    pub fn get(&self, did: &str) -> Option<DidDocument> {
        self.inner
            .read()
            .expect("DID store lock poisoned")
            .get(did)
            .cloned()
    }
}
