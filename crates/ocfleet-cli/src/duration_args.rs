use anyhow::{Context, bail};

pub fn parse_duration_seconds(value: &str, label: &str) -> anyhow::Result<u64> {
    let Some(unit) = value.chars().last() else {
        bail!("{label} must use s, m, h, or d suffix");
    };
    let number = &value[..value.len().saturating_sub(unit.len_utf8())];
    if number.is_empty() {
        bail!("{label} must include a positive number");
    }
    let amount: u64 = number
        .parse()
        .with_context(|| format!("invalid {label} value: {value}"))?;
    if amount == 0 {
        bail!("{label} must be greater than zero");
    }
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        _ => bail!("{label} must use s, m, h, or d suffix"),
    };
    amount
        .checked_mul(multiplier)
        .with_context(|| format!("{label} is too large"))
}
