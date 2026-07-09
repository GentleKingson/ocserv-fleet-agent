use std::fmt;

/// Fixed governance roles. This is a policy vocabulary, not a remote
/// authorization surface; the local CLI continues to rely on OS access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Operator,
    SecurityAdmin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    ReadOnlyQuery,
    ControllerLocalOperation,
    TrustAdministration,
}

impl Role {
    pub const fn permits(self, permission: Permission) -> bool {
        matches!(
            (self, permission),
            (_, Permission::ReadOnlyQuery)
                | (Self::Operator, Permission::ControllerLocalOperation)
                | (Self::SecurityAdmin, Permission::ControllerLocalOperation)
                | (Self::SecurityAdmin, Permission::TrustAdministration)
        )
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::SecurityAdmin => "security-admin",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_is_strictly_read_only() {
        assert!(Role::Viewer.permits(Permission::ReadOnlyQuery));
        assert!(!Role::Viewer.permits(Permission::ControllerLocalOperation));
        assert!(!Role::Viewer.permits(Permission::TrustAdministration));
    }

    #[test]
    fn operator_cannot_administer_trust() {
        assert!(Role::Operator.permits(Permission::ReadOnlyQuery));
        assert!(Role::Operator.permits(Permission::ControllerLocalOperation));
        assert!(!Role::Operator.permits(Permission::TrustAdministration));
    }

    #[test]
    fn security_admin_has_the_explicit_policy_permissions() {
        for permission in [
            Permission::ReadOnlyQuery,
            Permission::ControllerLocalOperation,
            Permission::TrustAdministration,
        ] {
            assert!(Role::SecurityAdmin.permits(permission));
        }
    }
}
