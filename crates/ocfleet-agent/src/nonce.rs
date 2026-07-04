use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct NonceCache {
    entries: HashMap<(String, String), Instant>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        remote_endpoint_id: impl Into<String>,
        nonce: impl Into<String>,
        ttl: Duration,
    ) -> bool {
        self.prune_expired();

        let key = (remote_endpoint_id.into(), nonce.into());
        if self.entries.contains_key(&key) {
            return false;
        }

        self.entries.insert(key, Instant::now() + ttl);
        true
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, expires_at| *expires_at > now);
    }
}
