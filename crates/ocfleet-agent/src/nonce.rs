use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceLimitScope {
    Global,
    PerPeer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceDecision {
    Accepted,
    Replay,
    ResourceExhausted {
        scope: NonceLimitScope,
        limit: usize,
    },
}

#[derive(Debug)]
pub struct NonceCache {
    entries: HashMap<(String, String), Instant>,
    max_live_global: usize,
    max_live_per_peer: usize,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::with_limits(usize::MAX, usize::MAX)
    }

    pub fn with_limits(max_live_global: usize, max_live_per_peer: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_live_global,
            max_live_per_peer,
        }
    }

    pub fn register(
        &mut self,
        remote_endpoint_id: impl Into<String>,
        nonce: impl Into<String>,
        ttl: Duration,
    ) -> NonceDecision {
        self.prune_expired();

        let remote_endpoint_id = remote_endpoint_id.into();
        let nonce = nonce.into();
        let key = (remote_endpoint_id.clone(), nonce);
        if self.entries.contains_key(&key) {
            return NonceDecision::Replay;
        }

        let peer_live_count = self
            .entries
            .keys()
            .filter(|(peer, _)| peer == &remote_endpoint_id)
            .count();
        if peer_live_count >= self.max_live_per_peer {
            return NonceDecision::ResourceExhausted {
                scope: NonceLimitScope::PerPeer,
                limit: self.max_live_per_peer,
            };
        }

        if self.entries.len() >= self.max_live_global {
            return NonceDecision::ResourceExhausted {
                scope: NonceLimitScope::Global,
                limit: self.max_live_global,
            };
        }

        self.entries.insert(key, Instant::now() + ttl);
        NonceDecision::Accepted
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, expires_at| *expires_at > now);
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}
