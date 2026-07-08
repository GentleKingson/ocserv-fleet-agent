mod cert;
mod config_fingerprint;
mod disabled;
mod provider;
mod sanitize;
mod snapshot;

pub use cert::CertificateExpiryProvider;
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
                SnapshotOcservReadonlyProvider::new(snapshot_path),
                CertificateExpiryProvider::new(config.certificates.clone()),
                ConfigFingerprintProvider::new(config.config_fingerprint.clone()),
            ))
        }
    }
}
