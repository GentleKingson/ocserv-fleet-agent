mod cert;
mod collector_snapshot;
mod config_fingerprint;
mod disabled;
mod provider;
mod sanitize;
mod snapshot;
mod trusted_file;

pub use cert::CertificateExpiryProvider;
pub use collector_snapshot::CollectorSnapshotOcservReadonlyProvider;
pub use config_fingerprint::ConfigFingerprintProvider;
pub use disabled::DisabledOcservReadonlyProvider;
pub use provider::{OcservReadonlyError, OcservReadonlyProvider};
pub use snapshot::SnapshotOcservReadonlyProvider;

use ocfleet_config::agent::{OcservReadonlyConfig, OcservReadonlyProviderKind};

pub fn provider_from_config(config: &OcservReadonlyConfig) -> Box<dyn OcservReadonlyProvider> {
    if !config.enabled {
        return Box::new(DisabledOcservReadonlyProvider);
    }

    match config.provider {
        OcservReadonlyProviderKind::Disabled => Box::new(DisabledOcservReadonlyProvider),
        OcservReadonlyProviderKind::Snapshot => {
            let snapshot_path = config
                .snapshot_path
                .clone()
                .unwrap_or_else(|| "/var/lib/ocfleet-agent/ocserv-readonly.json".into());
            Box::new(provider::CompositeOcservReadonlyProvider::new(
                Box::new(SnapshotOcservReadonlyProvider::new(snapshot_path)),
                CertificateExpiryProvider::new(config.certificates.clone()),
                ConfigFingerprintProvider::new(config.config_fingerprint.clone()),
            ))
        }
        OcservReadonlyProviderKind::CollectorSnapshot => {
            let snapshot_path = config
                .snapshot_path
                .clone()
                .unwrap_or_else(|| "/var/lib/ocfleet-agent/ocserv-live-snapshot.json".into());
            Box::new(provider::CompositeOcservReadonlyProvider::new(
                Box::new(CollectorSnapshotOcservReadonlyProvider::new(snapshot_path)),
                CertificateExpiryProvider::new(config.certificates.clone()),
                ConfigFingerprintProvider::new(config.config_fingerprint.clone()),
            ))
        }
    }
}
