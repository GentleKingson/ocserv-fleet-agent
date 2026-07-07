use std::io::Read;
use std::path::Path;

use ocfleet_protocol::enrollment::{AgentEnrollmentState, TrustBundle};
use thiserror::Error;

use crate::private_file;

#[derive(Debug, Error)]
pub enum AgentEnrollmentError {
    #[error("enrollment state io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("enrollment state json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct AgentEnrollment;

impl AgentEnrollment {
    pub fn load(path: &Path) -> Result<AgentEnrollmentState, AgentEnrollmentError> {
        let mut file = private_file::open_existing_private_read(path)?;
        let mut payload = String::new();
        file.read_to_string(&mut payload)?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn load_or_create_pending(
        path: &Path,
        request_id: impl Into<String>,
        token_id: impl Into<String>,
    ) -> Result<AgentEnrollmentState, AgentEnrollmentError> {
        match Self::load(path) {
            Ok(state) => Ok(state),
            Err(AgentEnrollmentError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                let state = AgentEnrollmentState::Pending {
                    request_id: request_id.into(),
                    token_id: token_id.into(),
                };
                Self::write(path, &state)?;
                Ok(state)
            }
            Err(err) => Err(err),
        }
    }

    pub fn activate(
        path: &Path,
        trust_bundle: TrustBundle,
    ) -> Result<AgentEnrollmentState, AgentEnrollmentError> {
        let state = AgentEnrollmentState::Active { trust_bundle };
        Self::write(path, &state)?;
        Ok(state)
    }

    fn write(path: &Path, state: &AgentEnrollmentState) -> Result<(), AgentEnrollmentError> {
        let payload = serde_json::to_vec_pretty(state)?;
        private_file::write_private_replace(path, &payload)?;
        Ok(())
    }
}

pub trait AgentEnrollmentStateExt {
    fn is_pending(&self) -> bool;
    fn is_active(&self) -> bool;
    fn trust_bundle(&self) -> Option<&TrustBundle>;
}

impl AgentEnrollmentStateExt for AgentEnrollmentState {
    fn is_pending(&self) -> bool {
        matches!(self, AgentEnrollmentState::Pending { .. })
    }

    fn is_active(&self) -> bool {
        matches!(self, AgentEnrollmentState::Active { .. })
    }

    fn trust_bundle(&self) -> Option<&TrustBundle> {
        match self {
            AgentEnrollmentState::Pending { .. } => None,
            AgentEnrollmentState::Active { trust_bundle } => Some(trust_bundle),
        }
    }
}
