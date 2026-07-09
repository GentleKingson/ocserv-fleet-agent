use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
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
    peers: HashMap<String, PeerNonceState>,
    expirations: BinaryHeap<Reverse<ExpiryEntry>>,
    live_total: usize,
    max_live_global: usize,
    max_live_per_peer: usize,
}

#[derive(Debug, Default)]
struct PeerNonceState {
    nonces: HashMap<String, Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExpiryEntry {
    expires_at: Instant,
    peer_id: String,
    nonce: String,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::with_limits(usize::MAX, usize::MAX)
    }

    pub fn with_limits(max_live_global: usize, max_live_per_peer: usize) -> Self {
        Self {
            peers: HashMap::new(),
            expirations: BinaryHeap::new(),
            live_total: 0,
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
        self.register_at(Instant::now(), remote_endpoint_id, nonce, ttl)
    }

    fn register_at(
        &mut self,
        now: Instant,
        remote_endpoint_id: impl Into<String>,
        nonce: impl Into<String>,
        ttl: Duration,
    ) -> NonceDecision {
        self.prune_expired_at(now);
        let remote_endpoint_id = remote_endpoint_id.into();
        let nonce = nonce.into();

        let peer_live_count = self
            .peers
            .get(&remote_endpoint_id)
            .map_or(0, |peer| peer.nonces.len());
        if self
            .peers
            .get(&remote_endpoint_id)
            .is_some_and(|peer| peer.nonces.contains_key(&nonce))
        {
            return NonceDecision::Replay;
        }
        if peer_live_count >= self.max_live_per_peer {
            return NonceDecision::ResourceExhausted {
                scope: NonceLimitScope::PerPeer,
                limit: self.max_live_per_peer,
            };
        }

        if self.live_total >= self.max_live_global {
            return NonceDecision::ResourceExhausted {
                scope: NonceLimitScope::Global,
                limit: self.max_live_global,
            };
        }

        let expires_at = now.checked_add(ttl).unwrap_or(now);
        self.peers
            .entry(remote_endpoint_id.clone())
            .or_default()
            .nonces
            .insert(nonce.clone(), expires_at);
        self.live_total += 1;
        self.expirations.push(Reverse(ExpiryEntry {
            expires_at,
            peer_id: remote_endpoint_id,
            nonce,
        }));
        NonceDecision::Accepted
    }

    fn prune_expired_at(&mut self, now: Instant) -> usize {
        let mut popped = 0;
        while let Some(Reverse(entry)) = self.expirations.peek() {
            if entry.expires_at > now {
                break;
            }

            let Reverse(entry) = self.expirations.pop().expect("peeked expiry entry exists");
            popped += 1;
            let current_expires_at = self
                .peers
                .get(&entry.peer_id)
                .and_then(|peer| peer.nonces.get(&entry.nonce))
                .copied();
            if current_expires_at != Some(entry.expires_at) {
                continue;
            }

            let remove_peer = if let Some(peer) = self.peers.get_mut(&entry.peer_id) {
                if peer.nonces.remove(&entry.nonce).is_some() {
                    self.live_total = self.live_total.saturating_sub(1);
                }
                peer.nonces.is_empty()
            } else {
                false
            };
            if remove_peer {
                self.peers.remove(&entry.peer_id);
            }
        }
        popped
    }

    #[cfg(test)]
    fn live_len(&self) -> usize {
        self.live_total
    }

    #[cfg(test)]
    fn peer_live_len(&self, peer_id: &str) -> usize {
        self.peers.get(peer_id).map_or(0, |peer| peer.nonces.len())
    }

    #[cfg(test)]
    fn heap_len(&self) -> usize {
        self.expirations.len()
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;

    #[test]
    fn expired_nonce_releases_global_and_per_peer_capacity_at_controlled_time() {
        let start = Instant::now();
        let mut cache = NonceCache::with_limits(1, 1);

        assert_eq!(
            cache.register_at(start, "remote-a", "nonce-1", Duration::from_secs(5)),
            NonceDecision::Accepted
        );
        assert_eq!(
            cache.register_at(
                start + Duration::from_secs(4),
                "remote-a",
                "nonce-2",
                Duration::from_secs(5)
            ),
            NonceDecision::ResourceExhausted {
                scope: NonceLimitScope::PerPeer,
                limit: 1,
            }
        );
        assert_eq!(
            cache.register_at(
                start + Duration::from_secs(5),
                "remote-a",
                "nonce-2",
                Duration::from_secs(5)
            ),
            NonceDecision::Accepted
        );
        assert_eq!(cache.live_len(), 1);
        assert_eq!(cache.peer_live_len("remote-a"), 1);
    }

    #[test]
    fn same_peer_same_nonce_is_accepted_after_expiration_at_controlled_time() {
        let start = Instant::now();
        let mut cache = NonceCache::new();

        assert_eq!(
            cache.register_at(start, "remote-a", "nonce-1", Duration::from_secs(5)),
            NonceDecision::Accepted
        );
        assert_eq!(
            cache.register_at(
                start + Duration::from_secs(4),
                "remote-a",
                "nonce-1",
                Duration::from_secs(5)
            ),
            NonceDecision::Replay
        );
        assert_eq!(
            cache.register_at(
                start + Duration::from_secs(5),
                "remote-a",
                "nonce-1",
                Duration::from_secs(5)
            ),
            NonceDecision::Accepted
        );
    }

    #[test]
    fn stale_heap_entry_does_not_delete_newer_live_nonce_for_same_peer_and_nonce() {
        let start = Instant::now();
        let mut cache = NonceCache::new();

        assert_eq!(
            cache.register_at(start, "remote-a", "nonce-1", Duration::from_secs(60)),
            NonceDecision::Accepted
        );
        cache.expirations.push(Reverse(ExpiryEntry {
            expires_at: start + Duration::from_secs(1),
            peer_id: "remote-a".to_string(),
            nonce: "nonce-1".to_string(),
        }));

        assert_eq!(cache.prune_expired_at(start + Duration::from_secs(2)), 1);
        assert_eq!(cache.live_len(), 1);
        assert_eq!(cache.peer_live_len("remote-a"), 1);
        assert_eq!(
            cache.register_at(
                start + Duration::from_secs(3),
                "remote-a",
                "nonce-1",
                Duration::from_secs(60)
            ),
            NonceDecision::Replay
        );
    }

    #[test]
    fn prune_does_not_walk_unexpired_live_entries() {
        let start = Instant::now();
        let mut cache = NonceCache::with_limits(20_000, 2);

        for index in 0..10_001 {
            assert_eq!(
                cache.register_at(
                    start,
                    format!("remote-{index}"),
                    "nonce-1",
                    Duration::from_secs(60)
                ),
                NonceDecision::Accepted
            );
        }

        let heap_len = cache.heap_len();
        assert_eq!(cache.prune_expired_at(start + Duration::from_secs(1)), 0);
        assert_eq!(cache.live_len(), 10_001);
        assert_eq!(cache.heap_len(), heap_len);
    }

    #[test]
    fn peer_state_is_removed_after_last_nonce_expires() {
        let start = Instant::now();
        let mut cache = NonceCache::new();

        assert_eq!(
            cache.register_at(start, "remote-a", "nonce-1", Duration::from_secs(5)),
            NonceDecision::Accepted
        );
        assert_eq!(cache.peer_live_len("remote-a"), 1);

        assert_eq!(cache.prune_expired_at(start + Duration::from_secs(5)), 1);
        assert_eq!(cache.live_len(), 0);
        assert_eq!(cache.peer_live_len("remote-a"), 0);
        assert!(!cache.peers.contains_key("remote-a"));
    }
}
