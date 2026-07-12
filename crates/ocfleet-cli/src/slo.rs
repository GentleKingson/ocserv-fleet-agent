use serde::Serialize;
use std::collections::BTreeSet;

use crate::store::HealthRollupRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SloWindow {
    Hours24,
    Days7,
    Days30,
}

impl SloWindow {
    pub const fn seconds(self) -> u64 {
        match self {
            Self::Hours24 => 86_400,
            Self::Days7 => 604_800,
            Self::Days30 => 2_592_000,
        }
    }

    pub const fn bucket_seconds(self) -> u64 {
        match self {
            Self::Hours24 => 300,
            Self::Days7 => 3_600,
            Self::Days30 => 86_400,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hours24 => "24h",
            Self::Days7 => "7d",
            Self::Days30 => "30d",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthSloProjection {
    pub node_id: String,
    pub window: String,
    pub from: String,
    pub to: String,
    pub bucket_seconds: u64,
    pub expected_buckets: u64,
    pub present_buckets: u64,
    pub expected_slots: u64,
    pub covered_slots: u64,
    pub missing_slots: u64,
    pub covered_duration_seconds: u64,
    pub missing_duration_seconds: u64,
    pub coverage_basis_points: Option<u64>,
    pub health_samples: u64,
    pub healthy_samples: u64,
    pub degraded_samples: u64,
    pub unreachable_samples: u64,
    pub stale_samples: u64,
    pub disabled_samples: u64,
    pub unknown_samples: u64,
    pub healthy_duration_seconds: u64,
    pub degraded_duration_seconds: u64,
    pub unreachable_duration_seconds: u64,
    pub stale_duration_seconds: u64,
    pub disabled_duration_seconds: u64,
    pub unknown_duration_seconds: u64,
    pub availability_eligible_samples: u64,
    pub service_available_basis_points: Option<u64>,
    pub strictly_healthy_basis_points: Option<u64>,
    pub observation_count: u64,
    pub observation_error_count: u64,
    pub observation_error_basis_points: Option<u64>,
    pub duration_sample_count: u64,
    pub latency_p50_ms_min: Option<u64>,
    pub latency_p50_ms_max: Option<u64>,
    pub latency_p95_ms_max: Option<u64>,
    pub cert_warning_count: u64,
    pub cert_critical_count: u64,
    pub fingerprint_sample_count: u64,
    pub fingerprint_change_count: u64,
}

pub fn project_health_slo(
    node_id: &str,
    window: SloWindow,
    from: &str,
    to: &str,
    rows: &[HealthRollupRecord],
) -> Option<HealthSloProjection> {
    let expected_buckets = window.seconds() / window.bucket_seconds();
    let expected_slots = window.seconds() / 300;
    if rows.len() > usize::try_from(expected_buckets).ok()? {
        return None;
    }
    let mut bucket_starts = BTreeSet::new();
    for row in rows {
        let status_total = row
            .healthy_count
            .checked_add(row.degraded_count)?
            .checked_add(row.unreachable_count)?
            .checked_add(row.stale_count)?
            .checked_add(row.disabled_count)?
            .checked_add(row.unknown_count)?;
        if row.node_id != node_id
            || row.bucket_seconds != window.bucket_seconds()
            || row.bucket_start.as_str() < from
            || row.bucket_start.as_str() >= to
            || row.expected_slots != row.bucket_seconds / 300
            || row.health_samples != row.covered_slots
            || row.covered_slots > row.expected_slots
            || status_total != row.health_samples
            || row.observation_error_count > row.observation_count
            || row.fingerprint_change_count > row.fingerprint_sample_count
            || (row.duration_sample_count == 0)
                != (row.duration_p50_ms.is_none() && row.duration_p95_ms.is_none())
            || row
                .duration_p50_ms
                .zip(row.duration_p95_ms)
                .is_some_and(|(p50, p95)| p50 > p95)
            || !bucket_starts.insert(row.bucket_start.as_str())
        {
            return None;
        }
    }
    let sum = |field: fn(&HealthRollupRecord) -> u64| {
        rows.iter().map(field).try_fold(0_u64, u64::checked_add)
    };
    let health_samples = sum(|row| row.health_samples)?;
    let covered_slots = sum(|row| row.covered_slots)?.min(expected_slots);
    let missing_slots = expected_slots.checked_sub(covered_slots)?;
    let observation_count = sum(|row| row.observation_count)?;
    let observation_error_count = sum(|row| row.observation_error_count)?;
    let healthy_samples = sum(|row| row.healthy_count)?;
    let degraded_samples = sum(|row| row.degraded_count)?;
    let unreachable_samples = sum(|row| row.unreachable_count)?;
    let stale_samples = sum(|row| row.stale_count)?;
    let disabled_samples = sum(|row| row.disabled_count)?;
    let unknown_samples = sum(|row| row.unknown_count)?;
    let availability_eligible_samples = healthy_samples
        .checked_add(degraded_samples)?
        .checked_add(unreachable_samples)?
        .checked_add(stale_samples)?;
    Some(HealthSloProjection {
        node_id: node_id.to_string(),
        window: window.as_str().to_string(),
        from: from.to_string(),
        to: to.to_string(),
        bucket_seconds: window.bucket_seconds(),
        expected_buckets,
        present_buckets: u64::try_from(rows.len()).ok()?.min(expected_buckets),
        expected_slots,
        covered_slots,
        missing_slots,
        covered_duration_seconds: covered_slots.checked_mul(300)?,
        missing_duration_seconds: missing_slots.checked_mul(300)?,
        coverage_basis_points: ratio_basis_points(covered_slots, expected_slots),
        health_samples,
        healthy_samples,
        degraded_samples,
        unreachable_samples,
        stale_samples,
        disabled_samples,
        unknown_samples,
        healthy_duration_seconds: healthy_samples.checked_mul(300)?,
        degraded_duration_seconds: degraded_samples.checked_mul(300)?,
        unreachable_duration_seconds: unreachable_samples.checked_mul(300)?,
        stale_duration_seconds: stale_samples.checked_mul(300)?,
        disabled_duration_seconds: disabled_samples.checked_mul(300)?,
        unknown_duration_seconds: unknown_samples.checked_mul(300)?,
        availability_eligible_samples,
        service_available_basis_points: ratio_basis_points(
            healthy_samples.checked_add(degraded_samples)?,
            availability_eligible_samples,
        ),
        strictly_healthy_basis_points: ratio_basis_points(
            healthy_samples,
            availability_eligible_samples,
        ),
        observation_count,
        observation_error_count,
        observation_error_basis_points: ratio_basis_points(
            observation_error_count,
            observation_count,
        ),
        duration_sample_count: sum(|row| row.duration_sample_count)?,
        latency_p50_ms_min: rows.iter().filter_map(|row| row.duration_p50_ms).min(),
        latency_p50_ms_max: rows.iter().filter_map(|row| row.duration_p50_ms).max(),
        latency_p95_ms_max: rows.iter().filter_map(|row| row.duration_p95_ms).max(),
        cert_warning_count: sum(|row| row.cert_warning_count)?,
        cert_critical_count: sum(|row| row.cert_critical_count)?,
        fingerprint_sample_count: sum(|row| row.fingerprint_sample_count)?,
        fingerprint_change_count: sum(|row| row.fingerprint_change_count)?,
    })
}

fn ratio_basis_points(numerator: u64, denominator: u64) -> Option<u64> {
    if denominator == 0 {
        None
    } else {
        numerator.checked_mul(10_000)?.checked_div(denominator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> HealthRollupRecord {
        HealthRollupRecord {
            node_id: "node-a".into(),
            bucket_seconds: 3_600,
            bucket_start: "2026-07-11T00:00:00Z".into(),
            bucket_end: "2026-07-11T01:00:00Z".into(),
            input_watermark: "a".repeat(64),
            health_samples: 10,
            covered_slots: 10,
            expected_slots: 12,
            healthy_count: 7,
            degraded_count: 1,
            unreachable_count: 2,
            stale_count: 0,
            disabled_count: 0,
            unknown_count: 0,
            observation_count: 5,
            observation_error_count: 1,
            duration_sample_count: 5,
            duration_p50_ms: Some(10),
            duration_p95_ms: Some(50),
            cert_warning_count: 1,
            cert_critical_count: 0,
            fingerprint_sample_count: 2,
            fingerprint_change_count: 1,
            computed_at: "2026-07-11T01:00:00Z".into(),
        }
    }

    #[test]
    fn projection_keeps_missing_coverage_out_of_availability_denominator() {
        let projection = project_health_slo(
            "node-a",
            SloWindow::Days7,
            "2026-07-05T00:00:00Z",
            "2026-07-12T00:00:00Z",
            &[row()],
        )
        .expect("projection");
        assert_eq!(projection.covered_slots, 10);
        assert_eq!(projection.missing_slots, 2_006);
        assert_eq!(projection.service_available_basis_points, Some(8_000));
        assert_eq!(projection.coverage_basis_points, Some(49));
        assert_eq!(projection.unreachable_duration_seconds, 600);
    }
}
