use std::collections::HashMap;
use std::time::{Duration, Instant};

use ocfleet_config::agent::AuditConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditLimitDecision {
    Write {
        suppressed_count: u64,
        limit_key: String,
    },
    Suppress,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LimitKey {
    remote_endpoint_id: String,
    resource: String,
    error_code: String,
}

impl LimitKey {
    fn new(remote_endpoint_id: Option<&str>, resource: &str, error_code: &str) -> Self {
        Self {
            remote_endpoint_id: remote_endpoint_id.unwrap_or("unknown").to_string(),
            resource: resource.to_string(),
            error_code: error_code.to_string(),
        }
    }

    fn label(&self) -> String {
        format!(
            "{}:{}:{}",
            self.remote_endpoint_id, self.resource, self.error_code
        )
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: usize,
    suppressed_count: u64,
    last_refill: Instant,
    last_seen: Instant,
    last_write: Option<Instant>,
}

impl Bucket {
    fn new(burst: usize, now: Instant) -> Self {
        Self {
            tokens: burst,
            suppressed_count: 0,
            last_refill: now,
            last_seen: now,
            last_write: None,
        }
    }

    fn refill(&mut self, burst: usize, refill_per_sec: usize, now: Instant) {
        let elapsed_secs = now.saturating_duration_since(self.last_refill).as_secs() as usize;
        if elapsed_secs == 0 {
            return;
        }
        let refill = elapsed_secs.saturating_mul(refill_per_sec);
        self.tokens = self.tokens.saturating_add(refill).min(burst);
        self.last_refill = now;
    }
}

#[derive(Debug)]
pub struct RejectedAuditLimiter {
    burst: usize,
    refill_per_sec: usize,
    max_buckets: usize,
    bucket_ttl: Duration,
    aggregate_interval: Duration,
    buckets: HashMap<LimitKey, Bucket>,
    overflow: Option<Bucket>,
}

impl RejectedAuditLimiter {
    pub fn new(config: &AuditConfig) -> Self {
        Self {
            burst: config.rejected_peer_log_burst,
            refill_per_sec: config.rejected_peer_log_refill_per_sec,
            max_buckets: config.rejected_peer_log_max_buckets,
            bucket_ttl: Duration::from_secs(config.rejected_peer_log_bucket_ttl_seconds),
            aggregate_interval: Duration::from_secs(
                config.rejected_peer_log_aggregate_interval_seconds,
            ),
            buckets: HashMap::new(),
            overflow: None,
        }
    }

    pub fn check(
        &mut self,
        remote_endpoint_id: Option<&str>,
        resource: &str,
        error_code: &str,
    ) -> AuditLimitDecision {
        let now = Instant::now();
        self.prune_stale(now);
        let key = LimitKey::new(remote_endpoint_id, resource, error_code);

        if self.buckets.contains_key(&key) || self.buckets.len() < self.max_buckets {
            let burst = self.burst;
            let refill_per_sec = self.refill_per_sec;
            let bucket = self
                .buckets
                .entry(key.clone())
                .or_insert_with(|| Bucket::new(burst, now));
            return check_bucket(
                bucket,
                burst,
                refill_per_sec,
                now,
                key.label(),
                self.aggregate_interval,
            );
        }

        let bucket = self
            .overflow
            .get_or_insert_with(|| Bucket::new(self.burst, now));
        check_bucket(
            bucket,
            self.burst,
            self.refill_per_sec,
            now,
            "overflow".to_string(),
            self.aggregate_interval,
        )
    }

    fn prune_stale(&mut self, now: Instant) {
        let ttl = self.bucket_ttl;
        self.buckets
            .retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) <= ttl);
        if self
            .overflow
            .as_ref()
            .is_some_and(|bucket| now.saturating_duration_since(bucket.last_seen) > ttl)
        {
            self.overflow = None;
        }
    }

    pub fn bucket_count_for_tests(&self) -> usize {
        self.buckets.len() + usize::from(self.overflow.is_some())
    }

    pub fn suppressed_count_for_tests(
        &self,
        remote_endpoint_id: Option<&str>,
        resource: &str,
        error_code: &str,
    ) -> u64 {
        let key = LimitKey::new(remote_endpoint_id, resource, error_code);
        self.buckets
            .get(&key)
            .map(|bucket| bucket.suppressed_count)
            .unwrap_or(0)
    }

    pub fn overflow_suppressed_count_for_tests(&self) -> u64 {
        self.overflow
            .as_ref()
            .map(|bucket| bucket.suppressed_count)
            .unwrap_or(0)
    }
}

fn check_bucket(
    bucket: &mut Bucket,
    burst: usize,
    refill_per_sec: usize,
    now: Instant,
    limit_key: String,
    aggregate_interval: Duration,
) -> AuditLimitDecision {
    bucket.refill(burst, refill_per_sec, now);
    bucket.last_seen = now;
    if bucket.tokens > 0 {
        if bucket.suppressed_count > 0
            && bucket.last_write.is_some_and(|last_write| {
                now.saturating_duration_since(last_write) < aggregate_interval
            })
        {
            bucket.suppressed_count = bucket.suppressed_count.saturating_add(1);
            return AuditLimitDecision::Suppress;
        }

        bucket.tokens -= 1;
        let suppressed_count = bucket.suppressed_count;
        bucket.suppressed_count = 0;
        bucket.last_write = Some(now);
        return AuditLimitDecision::Write {
            suppressed_count,
            limit_key,
        };
    }

    bucket.suppressed_count = bucket.suppressed_count.saturating_add(1);
    AuditLimitDecision::Suppress
}
