//! Project-scoped authorization.
//!
//! Installation admins may do anything. Other users act on a project only through a role
//! assignment in that project: `viewer` may view it, and `operator` may also operate it.
//! Managing a project's members is reserved for installation admins.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use vn_core::{Project, ProjectPermissions, ProjectRole};

use crate::auth::Principal;
use crate::error::ApiFailure;

/// Something a caller may want to do within one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectPermission {
    /// Read the project and its resources.
    View,
    /// Change the project's resources (deployments and jobs, as they arrive).
    Operate,
    /// Change who has access to the project.
    ManageMembers,
    /// Create and revoke enrollment tokens, and revoke agents. Reserved for installation
    /// admins in the first release.
    ManageAgents,
}

impl ProjectPermission {
    /// Whether a holder of `role` in the project has this permission.
    fn granted_by(self, role: ProjectRole) -> bool {
        match self {
            ProjectPermission::View => true,
            ProjectPermission::Operate => role >= ProjectRole::Operator,
            ProjectPermission::ManageMembers | ProjectPermission::ManageAgents => false,
        }
    }
}

/// Decides a project permission from the caller's installation and project roles.
pub(crate) fn allows(
    installation_admin: bool,
    role: Option<ProjectRole>,
    permission: ProjectPermission,
) -> bool {
    installation_admin || role.is_some_and(|role| permission.granted_by(role))
}

#[derive(sqlx::FromRow)]
struct ProjectRow {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    role: Option<String>,
}

impl ProjectRow {
    fn into_project(self, installation_admin: bool) -> Result<Project, ApiFailure> {
        let role = match self.role {
            None => None,
            Some(role) => Some(ProjectRole::from_db(&role).ok_or_else(|| {
                ApiFailure::internal(format!("unknown project role `{role}` in database"))
            })?),
        };
        let can = |permission| allows(installation_admin, role, permission);
        Ok(Project {
            id: self.id,
            slug: self.slug,
            name: self.name,
            created_at: self.created_at,
            role,
            permissions: ProjectPermissions {
                view: can(ProjectPermission::View),
                operate: can(ProjectPermission::Operate),
                manage_members: can(ProjectPermission::ManageMembers),
            },
        })
    }
}

/// Loads the project `slug` if the caller holds `permission` in it.
///
/// A project the caller has no access to at all answers 404, the same as one that does
/// not exist, so project names are not disclosed. A visible project the caller may not
/// act on answers 403.
pub(crate) async fn authorize_project(
    db: &PgPool,
    principal: &Principal,
    slug: &str,
    permission: ProjectPermission,
) -> Result<Project, ApiFailure> {
    let row: Option<ProjectRow> = sqlx::query_as(
        "SELECT p.id, p.slug, p.name, p.created_at, a.role FROM projects p \
         LEFT JOIN project_role_assignments a ON a.project_id = p.id AND a.user_id = $2 \
         WHERE p.slug = $1",
    )
    .bind(slug)
    .bind(principal.user.id)
    .fetch_optional(db)
    .await?;
    let not_found = || ApiFailure::not_found(format!("no project `{slug}`"));
    let project = row
        .ok_or_else(not_found)?
        .into_project(principal.installation_admin)?;
    if !principal.installation_admin && project.role.is_none() {
        return Err(not_found());
    }
    if !allows(principal.installation_admin, project.role, permission) {
        return Err(ApiFailure::forbidden(format!(
            "Your role in project `{slug}` does not allow this."
        )));
    }
    Ok(project)
}

/// Projects the caller can see: all of them for installation admins, otherwise those with
/// a role assignment.
pub(crate) async fn visible_projects(
    db: &PgPool,
    principal: &Principal,
) -> Result<Vec<Project>, ApiFailure> {
    let rows: Vec<ProjectRow> = sqlx::query_as(
        "SELECT p.id, p.slug, p.name, p.created_at, a.role FROM projects p \
         LEFT JOIN project_role_assignments a ON a.project_id = p.id AND a.user_id = $1 \
         WHERE $2 OR a.user_id IS NOT NULL \
         ORDER BY p.slug",
    )
    .bind(principal.user.id)
    .bind(principal.installation_admin)
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|row| row.into_project(principal.installation_admin))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProjectPermission::*;
    use ProjectRole::*;

    #[test]
    fn viewers_can_only_view() {
        assert!(allows(false, Some(Viewer), View));
        assert!(!allows(false, Some(Viewer), Operate));
        assert!(!allows(false, Some(Viewer), ManageMembers));
        assert!(!allows(false, Some(Viewer), ManageAgents));
    }

    #[test]
    fn operators_can_view_and_operate() {
        assert!(allows(false, Some(Operator), View));
        assert!(allows(false, Some(Operator), Operate));
        assert!(!allows(false, Some(Operator), ManageMembers));
        assert!(!allows(false, Some(Operator), ManageAgents));
    }

    #[test]
    fn users_without_a_role_have_no_access() {
        for permission in [View, Operate, ManageMembers, ManageAgents] {
            assert!(!allows(false, None, permission), "{permission:?}");
        }
    }

    #[test]
    fn installation_admins_have_every_permission() {
        for role in [None, Some(Viewer), Some(Operator)] {
            for permission in [View, Operate, ManageMembers, ManageAgents] {
                assert!(allows(true, role, permission), "{role:?} {permission:?}");
            }
        }
    }
}
