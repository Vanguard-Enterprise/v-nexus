//! Project and user endpoints under `/api/v1`. Every route here sits behind
//! [`crate::auth::require_session`].

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;
use vn_core::{
    AssignRoleRequest, CreateProjectRequest, Project, ProjectList, ProjectMember,
    ProjectMemberList, ProjectRole, User, UserList,
};

use crate::audit::AuditEvent;
use crate::auth::Principal;
use crate::authz::{self, ProjectPermission};
use crate::error::{ApiFailure, ApiJson, ApiPath};
use crate::router::AppState;

const MAX_PROJECT_NAME_CHARS: usize = 200;

/// `GET /api/v1/projects`
pub(crate) async fn list(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<ProjectList>, ApiFailure> {
    let projects = authz::visible_projects(&state.db, &principal).await?;
    Ok(Json(ProjectList { projects }))
}

/// `POST /api/v1/projects` (installation admins)
pub(crate) async fn create(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(request): ApiJson<CreateProjectRequest>,
) -> Result<Response, ApiFailure> {
    principal.require_admin()?;
    let slug = request.slug;
    if !is_valid_slug(&slug) {
        return Err(ApiFailure::invalid(
            "`slug` must be 1 to 63 lowercase letters, digits, or hyphens, \
             starting and ending with a letter or digit.",
        ));
    }
    let name = request.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > MAX_PROJECT_NAME_CHARS {
        return Err(ApiFailure::invalid(format!(
            "`name` must be 1 to {MAX_PROJECT_NAME_CHARS} characters."
        )));
    }

    let mut tx = state.db.begin().await?;
    let inserted: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "INSERT INTO projects (slug, name, created_by) VALUES ($1, $2, $3) \
         ON CONFLICT (slug) DO NOTHING RETURNING id, created_at",
    )
    .bind(&slug)
    .bind(&name)
    .bind(principal.user.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, created_at)) = inserted else {
        return Err(ApiFailure::conflict(format!(
            "A project with slug `{slug}` already exists."
        )));
    };
    AuditEvent::new("project.create", principal.user.id)
        .project(id)
        .details(json!({ "slug": slug }))
        .record(&mut tx)
        .await?;
    tx.commit().await?;

    let project = Project {
        id,
        slug,
        name,
        created_at,
        role: None,
        permissions: vn_core::ProjectPermissions {
            view: true,
            operate: true,
            manage_members: true,
        },
    };
    Ok((StatusCode::CREATED, Json(project)).into_response())
}

/// `GET /api/v1/projects/{slug}`
pub(crate) async fn show(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath(slug): ApiPath<String>,
) -> Result<Json<Project>, ApiFailure> {
    let project =
        authz::authorize_project(&state.db, &principal, &slug, ProjectPermission::View).await?;
    Ok(Json(project))
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    user_id: Uuid,
    issuer: String,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
    role: String,
    granted_at: DateTime<Utc>,
}

impl MemberRow {
    fn into_member(self) -> Result<ProjectMember, ApiFailure> {
        let role = ProjectRole::from_db(&self.role).ok_or_else(|| {
            ApiFailure::internal(format!("unknown project role `{}` in database", self.role))
        })?;
        Ok(ProjectMember {
            user: User {
                id: self.user_id,
                issuer: self.issuer,
                subject: self.subject,
                email: self.email,
                display_name: self.display_name,
            },
            role,
            granted_at: self.granted_at,
        })
    }
}

/// `GET /api/v1/projects/{slug}/members`
pub(crate) async fn members(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath(slug): ApiPath<String>,
) -> Result<Json<ProjectMemberList>, ApiFailure> {
    let project =
        authz::authorize_project(&state.db, &principal, &slug, ProjectPermission::View).await?;
    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT u.id AS user_id, u.issuer, u.subject, u.email, u.display_name, \
                a.role, a.granted_at \
         FROM project_role_assignments a JOIN users u ON u.id = a.user_id \
         WHERE a.project_id = $1 ORDER BY u.display_name NULLS LAST, u.subject",
    )
    .bind(project.id)
    .fetch_all(&state.db)
    .await?;
    let members = rows
        .into_iter()
        .map(MemberRow::into_member)
        .collect::<Result<_, _>>()?;
    Ok(Json(ProjectMemberList { members }))
}

/// `PUT /api/v1/projects/{slug}/members/{user_id}` (installation admins): grants or
/// changes a user's role in the project.
pub(crate) async fn assign(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath((slug, user_id)): ApiPath<(String, Uuid)>,
    ApiJson(request): ApiJson<AssignRoleRequest>,
) -> Result<Json<ProjectMember>, ApiFailure> {
    let project = authz::authorize_project(
        &state.db,
        &principal,
        &slug,
        ProjectPermission::ManageMembers,
    )
    .await?;
    let mut tx = state.db.begin().await?;
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT role FROM project_role_assignments \
         WHERE project_id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(project.id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let row: Option<MemberRow> = sqlx::query_as(
        "WITH assigned AS ( \
             INSERT INTO project_role_assignments (project_id, user_id, role, granted_by) \
             SELECT $1, u.id, $3, $4 FROM users u WHERE u.id = $2 \
             ON CONFLICT (project_id, user_id) DO UPDATE \
             SET role = EXCLUDED.role, granted_at = now(), granted_by = EXCLUDED.granted_by \
             RETURNING user_id, role, granted_at \
         ) \
         SELECT u.id AS user_id, u.issuer, u.subject, u.email, u.display_name, \
                assigned.role, assigned.granted_at \
         FROM assigned JOIN users u ON u.id = assigned.user_id",
    )
    .bind(project.id)
    .bind(user_id)
    .bind(request.role.as_str())
    .bind(principal.user.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Err(ApiFailure::not_found(format!(
            "no user `{user_id}`; users appear after their first sign-in"
        )));
    };
    AuditEvent::new("project.role_assign", principal.user.id)
        .project(project.id)
        .target_user(user_id)
        .details(json!({ "role": request.role, "previous_role": previous }))
        .record(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(Json(row.into_member()?))
}

/// `DELETE /api/v1/projects/{slug}/members/{user_id}` (installation admins)
pub(crate) async fn unassign(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath((slug, user_id)): ApiPath<(String, Uuid)>,
) -> Result<StatusCode, ApiFailure> {
    let project = authz::authorize_project(
        &state.db,
        &principal,
        &slug,
        ProjectPermission::ManageMembers,
    )
    .await?;
    let mut tx = state.db.begin().await?;
    let removed: Option<String> = sqlx::query_scalar(
        "DELETE FROM project_role_assignments WHERE project_id = $1 AND user_id = $2 \
         RETURNING role",
    )
    .bind(project.id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(role) = removed else {
        return Err(ApiFailure::not_found(format!(
            "user `{user_id}` has no role in project `{slug}`"
        )));
    };
    AuditEvent::new("project.role_remove", principal.user.id)
        .project(project.id)
        .target_user(user_id)
        .details(json!({ "previous_role": role }))
        .record(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/users` (installation admins): everyone who has signed in, for role
/// assignment.
pub(crate) async fn users(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<UserList>, ApiFailure> {
    principal.require_admin()?;
    let users: Vec<UserRow> = sqlx::query_as(
        "SELECT id, issuer, subject, email, display_name FROM users \
         ORDER BY display_name NULLS LAST, subject",
    )
    .fetch_all(&state.db)
    .await?;
    let users = users.into_iter().map(UserRow::into_user).collect();
    Ok(Json(UserList { users }))
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    issuer: String,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
}

impl UserRow {
    fn into_user(self) -> User {
        User {
            id: self.id,
            issuer: self.issuer,
            subject: self.subject,
            email: self.email,
            display_name: self.display_name,
        }
    }
}

/// Matches the `projects.slug` check constraint.
fn is_valid_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    let allowed = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (1..=63).contains(&bytes.len())
        && bytes.first().is_some_and(allowed)
        && bytes.last().is_some_and(allowed)
        && bytes.iter().all(|b| allowed(b) || *b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_slugs_like_the_database() {
        for ok in ["a", "prod", "team-a", "x1-y2", &"a".repeat(63)] {
            assert!(is_valid_slug(ok), "{ok}");
        }
        for bad in ["", "-a", "a-", "Prod", "a_b", "a.b", "é", &"a".repeat(64)] {
            assert!(!is_valid_slug(bad), "{bad}");
        }
    }
}
