//! Agent enrollment tokens, enrollment, and revocation.
//!
//! For the first release only installation admins create and revoke enrollment tokens
//! and agents ([`ProjectPermission::ManageAgents`]). Project members with view access can
//! list a project's agents.

mod enroll;
mod token;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;
use vn_core::{
    AGENT_PROTOCOL_VERSIONS, Agent, AgentKind, AgentList, AgentRevocationReason, AgentServerInfo,
    AgentStatus, CreateEnrollmentTokenRequest, CreatedEnrollmentToken,
    DEFAULT_ENROLLMENT_TOKEN_MINUTES, EnrollmentTarget, EnrollmentToken, EnrollmentTokenList,
    EnrollmentTokenStatus, MAX_ENROLLMENT_TOKEN_MINUTES,
};

pub(crate) use enroll::enroll;

use crate::audit::AuditEvent;
use crate::auth::{Principal, Token};
use crate::authz::{self, ProjectPermission};
use crate::error::{ApiFailure, ApiJson, ApiPath};
use crate::router::AppState;

/// PostgreSQL notification channel announcing revoked agents. The payload is the agent
/// ID. Servers holding an open connection for that agent close it.
pub(crate) const AGENT_REVOKED_CHANNEL: &str = "vn_agent_revoked";

const MAX_CLUSTER_NAME_CHARS: usize = 200;

/// This installation's ID.
pub(crate) async fn installation_id(db: impl PgExecutor<'_>) -> sqlx::Result<Uuid> {
    sqlx::query_scalar("SELECT installation_id FROM installation")
        .fetch_one(db)
        .await
}

/// `GET /api/v1/agent/info` (unauthenticated)
pub(crate) async fn info(
    State(state): State<AppState>,
) -> Result<Json<AgentServerInfo>, ApiFailure> {
    Ok(Json(AgentServerInfo {
        installation_id: installation_id(&state.db).await?,
        protocol_versions: AGENT_PROTOCOL_VERSIONS.to_vec(),
    }))
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: Uuid,
    project_id: Uuid,
    agent_kind: String,
    target_cluster_name: Option<String>,
    target_source_id: Option<Uuid>,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_by: Option<Uuid>,
}

const TOKEN_COLUMNS: &str = "id, project_id, agent_kind, target_cluster_name, \
    target_source_id, created_by, created_at, expires_at, used_at, revoked_at, revoked_by";

impl TokenRow {
    fn status(&self, now: DateTime<Utc>) -> EnrollmentTokenStatus {
        if self.revoked_at.is_some() {
            EnrollmentTokenStatus::Revoked
        } else if self.used_at.is_some() {
            EnrollmentTokenStatus::Used
        } else if now >= self.expires_at {
            EnrollmentTokenStatus::Expired
        } else {
            EnrollmentTokenStatus::Active
        }
    }

    fn into_token(self, now: DateTime<Utc>) -> Result<EnrollmentToken, ApiFailure> {
        let status = self.status(now);
        let kind = parse_kind(&self.agent_kind)?;
        let target = match (self.target_cluster_name, self.target_source_id) {
            (Some(display_name), None) => EnrollmentTarget::NewCluster { display_name },
            (None, Some(source_id)) => EnrollmentTarget::ReplaceSource { source_id },
            _ => {
                return Err(ApiFailure::internal(format!(
                    "enrollment token {} has an invalid target",
                    self.id
                )));
            }
        };
        Ok(EnrollmentToken {
            id: self.id,
            project_id: self.project_id,
            kind,
            target,
            status,
            created_by: self.created_by,
            created_at: self.created_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
            revoked_at: self.revoked_at,
            revoked_by: self.revoked_by,
        })
    }
}

fn parse_kind(value: &str) -> Result<AgentKind, ApiFailure> {
    AgentKind::from_db(value)
        .ok_or_else(|| ApiFailure::internal(format!("unknown agent kind `{value}` in database")))
}

/// `POST /api/v1/projects/{slug}/enrollment-tokens` (installation admins)
pub(crate) async fn create_token(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath(slug): ApiPath<String>,
    ApiJson(request): ApiJson<CreateEnrollmentTokenRequest>,
) -> Result<Response, ApiFailure> {
    let project = authz::authorize_project(
        &state.db,
        &principal,
        &slug,
        ProjectPermission::ManageAgents,
    )
    .await?;
    let minutes = request
        .expires_in_minutes
        .unwrap_or(DEFAULT_ENROLLMENT_TOKEN_MINUTES);
    if !(1..=MAX_ENROLLMENT_TOKEN_MINUTES).contains(&minutes) {
        return Err(ApiFailure::invalid(format!(
            "`expires_in_minutes` must be 1 to {MAX_ENROLLMENT_TOKEN_MINUTES}."
        )));
    }
    let target = match request.target {
        EnrollmentTarget::NewCluster { display_name } => {
            let display_name = display_name.trim().to_owned();
            if display_name.is_empty() || display_name.chars().count() > MAX_CLUSTER_NAME_CHARS {
                return Err(ApiFailure::invalid(format!(
                    "`target.display_name` must be 1 to {MAX_CLUSTER_NAME_CHARS} characters."
                )));
            }
            EnrollmentTarget::NewCluster { display_name }
        }
        target @ EnrollmentTarget::ReplaceSource { .. } => target,
    };
    let (cluster_name, source_id) = match &target {
        EnrollmentTarget::NewCluster { display_name } => (Some(display_name.as_str()), None),
        EnrollmentTarget::ReplaceSource { source_id } => (None, Some(*source_id)),
    };
    let secret = Token::generate().map_err(ApiFailure::internal)?;

    let mut tx = state.db.begin().await?;
    if let Some(source_id) = source_id {
        let found: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM sources s JOIN clusters c ON c.id = s.cluster_id \
             WHERE s.id = $1 AND c.project_id = $2",
        )
        .bind(source_id)
        .bind(project.id)
        .fetch_optional(&mut *tx)
        .await?;
        if found.is_none() {
            return Err(ApiFailure::not_found(format!(
                "no source `{source_id}` in project `{slug}`"
            )));
        }
    }
    let row: TokenRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "INSERT INTO enrollment_tokens \
             (secret_hash, project_id, agent_kind, target_cluster_name, target_source_id, \
              created_by, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now() + $7 * interval '1 minute') \
         RETURNING {TOKEN_COLUMNS}"
    )))
    .bind(secret.hash())
    .bind(project.id)
    .bind(request.kind.as_str())
    .bind(cluster_name)
    .bind(source_id)
    .bind(principal.user.id)
    .bind(i32::try_from(minutes).map_err(ApiFailure::internal)?)
    .fetch_one(&mut *tx)
    .await?;
    AuditEvent::new("enrollment_token.create", principal.user.id)
        .project(project.id)
        .details(json!({
            "token_id": row.id,
            "kind": request.kind,
            "target": target,
            "expires_at": row.expires_at,
        }))
        .record(&mut tx)
        .await?;
    let installation_id = installation_id(&mut *tx).await?;
    tx.commit().await?;

    let secret = token::format(row.id, secret.expose());
    let token = row.into_token(Utc::now())?;
    let body = CreatedEnrollmentToken {
        token,
        secret,
        installation_id,
    };
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// `GET /api/v1/projects/{slug}/enrollment-tokens` (installation admins)
pub(crate) async fn list_tokens(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath(slug): ApiPath<String>,
) -> Result<Json<EnrollmentTokenList>, ApiFailure> {
    let project = authz::authorize_project(
        &state.db,
        &principal,
        &slug,
        ProjectPermission::ManageAgents,
    )
    .await?;
    let rows: Vec<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {TOKEN_COLUMNS} FROM enrollment_tokens WHERE project_id = $1 \
         ORDER BY created_at DESC, id"
    )))
    .bind(project.id)
    .fetch_all(&state.db)
    .await?;
    let now = Utc::now();
    let tokens = rows
        .into_iter()
        .map(|row| row.into_token(now))
        .collect::<Result<_, _>>()?;
    Ok(Json(EnrollmentTokenList { tokens }))
}

/// `POST /api/v1/projects/{slug}/enrollment-tokens/{token_id}/revoke` (installation
/// admins): revokes a token that has not been used.
pub(crate) async fn revoke_token(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath((slug, token_id)): ApiPath<(String, Uuid)>,
) -> Result<Json<EnrollmentToken>, ApiFailure> {
    let project = authz::authorize_project(
        &state.db,
        &principal,
        &slug,
        ProjectPermission::ManageAgents,
    )
    .await?;
    let mut tx = state.db.begin().await?;
    let revoked: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE enrollment_tokens SET revoked_at = now(), revoked_by = $3 \
         WHERE id = $1 AND project_id = $2 AND used_at IS NULL AND revoked_at IS NULL \
         RETURNING {TOKEN_COLUMNS}"
    )))
    .bind(token_id)
    .bind(project.id)
    .bind(principal.user.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = revoked else {
        let existing: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM enrollment_tokens WHERE id = $1 AND project_id = $2"
        )))
        .bind(token_id)
        .bind(project.id)
        .fetch_optional(&mut *tx)
        .await?;
        return Err(match existing {
            None => ApiFailure::not_found(format!(
                "no enrollment token `{token_id}` in project `{slug}`"
            )),
            Some(row) if row.used_at.is_some() => ApiFailure::conflict(
                "The enrollment token has already been used. Revoke the agent instead.",
            ),
            Some(_) => ApiFailure::conflict("The enrollment token is already revoked."),
        });
    };
    AuditEvent::new("enrollment_token.revoke", principal.user.id)
        .project(project.id)
        .details(json!({ "token_id": row.id }))
        .record(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(Json(row.into_token(Utc::now())?))
}

#[derive(sqlx::FromRow)]
struct AgentRow {
    id: Uuid,
    kind: String,
    project_id: Uuid,
    cluster_id: Uuid,
    cluster_name: String,
    source_id: Uuid,
    key_id: String,
    cluster_fingerprint: String,
    agent_version: String,
    protocol_versions: Vec<i32>,
    enrollment_token_id: Uuid,
    enrolled_by: Option<Uuid>,
    enrolled_at: DateTime<Utc>,
    source_address: Option<String>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_by: Option<Uuid>,
    revocation_reason: Option<String>,
}

const AGENT_SELECT: &str = "SELECT a.id, a.kind, a.project_id, a.cluster_id, \
        c.display_name AS cluster_name, a.source_id, a.key_id, a.cluster_fingerprint, \
        a.agent_version, a.protocol_versions, a.enrollment_token_id, a.enrolled_by, \
        a.enrolled_at, host(a.source_address) AS source_address, a.revoked_at, a.revoked_by, \
        a.revocation_reason \
    FROM agents a JOIN clusters c ON c.id = a.cluster_id";

impl AgentRow {
    fn into_agent(self) -> Result<Agent, ApiFailure> {
        let revocation_reason = match self.revocation_reason.as_deref() {
            None => None,
            Some(reason) => Some(AgentRevocationReason::from_db(reason).ok_or_else(|| {
                ApiFailure::internal(format!("unknown revocation reason `{reason}` in database"))
            })?),
        };
        Ok(Agent {
            id: self.id,
            kind: parse_kind(&self.kind)?,
            status: if self.revoked_at.is_some() {
                AgentStatus::Revoked
            } else {
                AgentStatus::Active
            },
            project_id: self.project_id,
            cluster_id: self.cluster_id,
            cluster_name: self.cluster_name,
            source_id: self.source_id,
            key_id: self.key_id,
            cluster_fingerprint: self.cluster_fingerprint,
            agent_version: self.agent_version,
            protocol_versions: self
                .protocol_versions
                .into_iter()
                .map(|v| u32::try_from(v).map_err(ApiFailure::internal))
                .collect::<Result<_, _>>()?,
            enrollment_token_id: self.enrollment_token_id,
            enrolled_by: self.enrolled_by,
            enrolled_at: self.enrolled_at,
            source_address: self.source_address,
            revoked_at: self.revoked_at,
            revoked_by: self.revoked_by,
            revocation_reason,
        })
    }
}

async fn load_agent(
    db: impl PgExecutor<'_>,
    project_id: Uuid,
    agent_id: Uuid,
) -> Result<Option<AgentRow>, ApiFailure> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{AGENT_SELECT} WHERE a.id = $1 AND a.project_id = $2"
    )))
    .bind(agent_id)
    .bind(project_id)
    .fetch_optional(db)
    .await?)
}

/// `GET /api/v1/projects/{slug}/agents`
pub(crate) async fn list(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath(slug): ApiPath<String>,
) -> Result<Json<AgentList>, ApiFailure> {
    let project =
        authz::authorize_project(&state.db, &principal, &slug, ProjectPermission::View).await?;
    let rows: Vec<AgentRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{AGENT_SELECT} WHERE a.project_id = $1 ORDER BY a.enrolled_at DESC, a.id"
    )))
    .bind(project.id)
    .fetch_all(&state.db)
    .await?;
    let agents = rows
        .into_iter()
        .map(AgentRow::into_agent)
        .collect::<Result<_, _>>()?;
    Ok(Json(AgentList { agents }))
}

/// `POST /api/v1/projects/{slug}/agents/{agent_id}/revoke` (installation admins)
///
/// One transaction marks the agent revoked, records the audit event, and notifies
/// [`AGENT_REVOKED_CHANNEL`]. The cluster, its source, and its inventory stay.
pub(crate) async fn revoke(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath((slug, agent_id)): ApiPath<(String, Uuid)>,
) -> Result<Json<Agent>, ApiFailure> {
    let project = authz::authorize_project(
        &state.db,
        &principal,
        &slug,
        ProjectPermission::ManageAgents,
    )
    .await?;
    let mut tx = state.db.begin().await?;
    let revoked: Option<Uuid> = sqlx::query_scalar(
        "UPDATE agents SET revoked_at = now(), revoked_by = $3, revocation_reason = $4 \
         WHERE id = $1 AND project_id = $2 AND revoked_at IS NULL RETURNING id",
    )
    .bind(agent_id)
    .bind(project.id)
    .bind(principal.user.id)
    .bind(AgentRevocationReason::Revoked.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    if revoked.is_none() {
        return Err(match load_agent(&mut *tx, project.id, agent_id).await? {
            None => ApiFailure::not_found(format!("no agent `{agent_id}` in project `{slug}`")),
            Some(_) => ApiFailure::conflict("The agent is already revoked."),
        });
    }
    AuditEvent::new("agent.revoke", principal.user.id)
        .project(project.id)
        .agent(agent_id)
        .details(json!({ "reason": AgentRevocationReason::Revoked }))
        .record(&mut tx)
        .await?;
    notify_revoked(&mut tx, agent_id).await?;
    let row = load_agent(&mut *tx, project.id, agent_id)
        .await?
        .ok_or_else(|| ApiFailure::internal("revoked agent vanished"))?;
    tx.commit().await?;
    Ok(Json(row.into_agent()?))
}

/// Announces a revocation on [`AGENT_REVOKED_CHANNEL`]. PostgreSQL delivers it when the
/// transaction commits, and not at all if it rolls back.
async fn notify_revoked(conn: &mut PgConnection, agent_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(AGENT_REVOKED_CHANNEL)
        .bind(agent_id.to_string())
        .execute(conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    fn row(expires_in: TimeDelta) -> TokenRow {
        let now = Utc::now();
        TokenRow {
            id: Uuid::nil(),
            project_id: Uuid::nil(),
            agent_kind: "kubernetes".into(),
            target_cluster_name: Some("c".into()),
            target_source_id: None,
            created_by: None,
            created_at: now,
            expires_at: now + expires_in,
            used_at: None,
            revoked_at: None,
            revoked_by: None,
        }
    }

    #[test]
    fn token_status_prefers_revoked_then_used_then_expired() {
        let now = Utc::now();
        assert_eq!(
            row(TimeDelta::hours(1)).status(now),
            EnrollmentTokenStatus::Active
        );
        assert_eq!(
            row(TimeDelta::zero()).status(now + TimeDelta::seconds(1)),
            EnrollmentTokenStatus::Expired
        );
        let used = TokenRow {
            used_at: Some(now),
            ..row(TimeDelta::zero())
        };
        assert_eq!(
            used.status(now + TimeDelta::hours(2)),
            EnrollmentTokenStatus::Used
        );
        let revoked = TokenRow {
            revoked_at: Some(now),
            ..row(TimeDelta::hours(1))
        };
        assert_eq!(revoked.status(now), EnrollmentTokenStatus::Revoked);
    }

    #[test]
    fn token_rows_map_their_target() {
        let token = row(TimeDelta::hours(1)).into_token(Utc::now()).unwrap();
        assert_eq!(
            token.target,
            EnrollmentTarget::NewCluster {
                display_name: "c".into()
            }
        );
        let broken = TokenRow {
            target_source_id: Some(Uuid::nil()),
            ..row(TimeDelta::hours(1))
        };
        assert!(broken.into_token(Utc::now()).is_err());
    }
}
