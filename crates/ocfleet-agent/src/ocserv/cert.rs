use std::fs;
use std::path::Path;

use base64::Engine;
use ocfleet_config::agent::OcservCertificateConfig;
use ocfleet_protocol::error::ErrorCode;
use ocfleet_protocol::ocserv::{
    OCSERV_CERT_MAX_ENTRIES, OcservCertExpiry, OcservCertExpiryResponse, OcservCertStatus,
    OcservFreshness, OcservReadonlyMeta, OcservReadonlySource, is_valid_ocserv_name,
};
use sha2::{Digest, Sha256};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::ocserv::{OcservReadonlyError, OcservReadonlyProvider, sanitize};

const CERT_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CertificateExpiryProvider {
    certificates: Vec<OcservCertificateConfig>,
}

#[derive(Debug, Clone)]
struct ParsedCertificate {
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    fingerprint_sha256: String,
}

impl CertificateExpiryProvider {
    pub fn new(certificates: Vec<OcservCertificateConfig>) -> Self {
        Self { certificates }
    }

    fn read_certificate(
        &self,
        certificate: &OcservCertificateConfig,
    ) -> Result<OcservCertExpiry, OcservReadonlyError> {
        if !is_valid_ocserv_name(&certificate.name) {
            return Ok(invalid_cert(&certificate.name, OcservCertStatus::Invalid));
        }
        let bytes = match read_bounded_regular_file(&certificate.cert_path, CERT_MAX_BYTES) {
            Ok(bytes) => bytes,
            Err(err)
                if matches!(
                    err.code(),
                    ErrorCode::OcservOutputBoundExceeded | ErrorCode::OcservProviderUnsafeSource
                ) =>
            {
                return Err(err);
            }
            Err(_) => {
                return Ok(OcservCertExpiry {
                    name: certificate.name.clone(),
                    not_before: None,
                    not_after: None,
                    days_remaining: None,
                    status: OcservCertStatus::Unreadable,
                    fingerprint_sha256: None,
                });
            }
        };
        match parse_certificate(&bytes) {
            Some(parsed) => Ok(cert_expiry_from_parsed(&certificate.name, parsed)),
            None => Ok(invalid_cert(&certificate.name, OcservCertStatus::Invalid)),
        }
    }
}

impl OcservReadonlyProvider for CertificateExpiryProvider {
    fn service_summary(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservServiceSummaryResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv service provider is unavailable",
        ))
    }

    fn version(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservVersionResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv version provider is unavailable",
        ))
    }

    fn sessions_summary(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservSessionsSummaryResponse, OcservReadonlyError> {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv sessions provider is unavailable",
        ))
    }

    fn cert_expiry(&self) -> Result<OcservCertExpiryResponse, OcservReadonlyError> {
        if self.certificates.len() > OCSERV_CERT_MAX_ENTRIES {
            return Err(OcservReadonlyError::new(
                ErrorCode::OcservOutputBoundExceeded,
                "ocserv certificate response is too large",
            ));
        }
        let certs = self
            .certificates
            .iter()
            .map(|certificate| self.read_certificate(certificate))
            .collect::<Result<Vec<_>, _>>()?;
        sanitize::cert_expiry(OcservCertExpiryResponse {
            certs,
            meta: OcservReadonlyMeta {
                source: OcservReadonlySource::Provider,
                collected_at: now_rfc3339(),
                freshness: OcservFreshness::Live,
            },
        })
    }

    fn config_fingerprint(
        &self,
    ) -> Result<ocfleet_protocol::ocserv::OcservConfigFingerprintResponse, OcservReadonlyError>
    {
        Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv config fingerprint provider is unavailable",
        ))
    }
}

fn cert_expiry_from_parsed(name: &str, parsed: ParsedCertificate) -> OcservCertExpiry {
    let now = OffsetDateTime::now_utc();
    let days_remaining = (parsed.not_after - now).whole_days();
    let status = if parsed.not_after <= now {
        OcservCertStatus::Expired
    } else if days_remaining <= 30 {
        OcservCertStatus::ExpiringSoon
    } else {
        OcservCertStatus::Valid
    };
    OcservCertExpiry {
        name: name.to_string(),
        not_before: Some(format_rfc3339(parsed.not_before)),
        not_after: Some(format_rfc3339(parsed.not_after)),
        days_remaining: Some(days_remaining),
        status,
        fingerprint_sha256: Some(parsed.fingerprint_sha256),
    }
}

fn invalid_cert(name: &str, status: OcservCertStatus) -> OcservCertExpiry {
    OcservCertExpiry {
        name: name.to_string(),
        not_before: None,
        not_after: None,
        days_remaining: None,
        status,
        fingerprint_sha256: None,
    }
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, OcservReadonlyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv certificate is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnsafeSource,
            "ocserv certificate source is unsafe",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservOutputBoundExceeded,
            "ocserv certificate is too large",
        ));
    }
    reject_world_writable(&metadata)?;
    fs::read(path).map_err(|_| {
        OcservReadonlyError::new(
            ErrorCode::OcservProviderUnavailable,
            "ocserv certificate is unavailable",
        )
    })
}

#[cfg(unix)]
fn reject_world_writable(metadata: &fs::Metadata) -> Result<(), OcservReadonlyError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o002 != 0 {
        return Err(OcservReadonlyError::new(
            ErrorCode::OcservProviderUnsafeSource,
            "ocserv certificate source is unsafe",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_world_writable(_metadata: &fs::Metadata) -> Result<(), OcservReadonlyError> {
    Ok(())
}

fn parse_certificate(bytes: &[u8]) -> Option<ParsedCertificate> {
    let der = certificate_der(bytes)?;
    let fingerprint_sha256 = hex_sha256(&der);
    let (not_before, not_after) = parse_der_validity(&der)?;
    Some(ParsedCertificate {
        not_before,
        not_after,
        fingerprint_sha256,
    })
}

fn certificate_der(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(bytes);
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    if !text.contains(begin) {
        return Some(bytes.to_vec());
    }

    let mut encoded = String::new();
    let mut in_body = false;
    for line in text.lines() {
        if line.trim() == begin {
            in_body = true;
            continue;
        }
        if line.trim() == end {
            break;
        }
        if in_body {
            encoded.push_str(line.trim());
        }
    }
    if encoded.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn parse_der_validity(der: &[u8]) -> Option<(OffsetDateTime, OffsetDateTime)> {
    let mut certificate = DerReader::new(der);
    let certificate_body = certificate.read_expected(0x30)?;
    let mut certificate_body = DerReader::new(certificate_body);
    let tbs = certificate_body.read_expected(0x30)?;
    let mut tbs = DerReader::new(tbs);
    if tbs.peek_tag() == Some(0xa0) {
        tbs.read_any()?;
    }
    tbs.read_any()?;
    tbs.read_any()?;
    tbs.read_any()?;
    let validity = tbs.read_expected(0x30)?;
    let mut validity = DerReader::new(validity);
    let not_before = validity.read_time()?;
    let not_after = validity.read_time()?;
    Some((not_before, not_after))
}

struct DerReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.position).copied()
    }

    fn read_any(&mut self) -> Option<&'a [u8]> {
        self.read_tlv().map(|(_, value)| value)
    }

    fn read_expected(&mut self, expected_tag: u8) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        (tag == expected_tag).then_some(value)
    }

    fn read_time(&mut self) -> Option<OffsetDateTime> {
        let (tag, value) = self.read_tlv()?;
        let text = std::str::from_utf8(value).ok()?;
        match tag {
            0x17 => parse_utc_time(text),
            0x18 => parse_generalized_time(text),
            _ => None,
        }
    }

    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.data.get(self.position)?;
        self.position += 1;
        let length = self.read_length()?;
        let end = self.position.checked_add(length)?;
        let value = self.data.get(self.position..end)?;
        self.position = end;
        Some((tag, value))
    }

    fn read_length(&mut self) -> Option<usize> {
        let first = *self.data.get(self.position)?;
        self.position += 1;
        if first & 0x80 == 0 {
            return Some(first as usize);
        }
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = (length << 8) | usize::from(*self.data.get(self.position)?);
            self.position += 1;
        }
        Some(length)
    }
}

fn parse_utc_time(value: &str) -> Option<OffsetDateTime> {
    if value.len() != 13 || !value.ends_with('Z') {
        return None;
    }
    let year = parse_u8(&value[0..2])?;
    let year = if year >= 50 {
        1900 + i32::from(year)
    } else {
        2000 + i32::from(year)
    };
    parse_datetime(
        year,
        parse_u8(&value[2..4])?,
        parse_u8(&value[4..6])?,
        parse_u8(&value[6..8])?,
        parse_u8(&value[8..10])?,
        parse_u8(&value[10..12])?,
    )
}

fn parse_generalized_time(value: &str) -> Option<OffsetDateTime> {
    if value.len() != 15 || !value.ends_with('Z') {
        return None;
    }
    parse_datetime(
        parse_i32(&value[0..4])?,
        parse_u8(&value[4..6])?,
        parse_u8(&value[6..8])?,
        parse_u8(&value[8..10])?,
        parse_u8(&value[10..12])?,
        parse_u8(&value[12..14])?,
    )
}

fn parse_datetime(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<OffsetDateTime> {
    let month = Month::try_from(month).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

fn parse_u8(value: &str) -> Option<u8> {
    value.parse().ok()
}

fn parse_i32(value: &str) -> Option<i32> {
    value.parse().ok()
}

fn now_rfc3339() -> String {
    format_rfc3339(OffsetDateTime::now_utc())
}

fn format_rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting succeeds")
}
