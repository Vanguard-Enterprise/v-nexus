//! Audit history of security-relevant actions.
//!
//! Details are small JSON objects of identifiers and role names. Never put tokens,
//! secrets, or raw identity-provider claims in them.

use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

pub(crate) struct AuditEvent {
    pub(crate) action: &'static str,
    pub(crate) actor_user_id: Option<Uuid>,
    pub(crate) project_id: Option<Uuid>,
    pub(crate) target_user_id: Option<Uuid>,
    pub(crate) details: Value,
}

impl AuditEvent {
    pub(crate) fn new(action: &'static str, actor_user_id: Uuid) -> Self {
        Self {
            action,
            actor_user_id: Some(actor_user_id),
            project_id: None,
            target_user_id: None,
            details: Value::Object(serde_json::Map::new()),
        }
    }

    pub(crate) fn project(mut self, project_id: Uuid) -> Self {
        self.project_id = Some(project_id);
        self
    }

    pub(crate) fn target_user(mut self, user_id: Uuid) -> Self {
        self.target_user_id = Some(user_id);
        self
    }

    pub(crate) fn details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    /// Records the event. Call it inside the transaction that makes the change, so the
    /// change and its audit record commit together.
    pub(crate) async fn record(self, conn: &mut PgConnection) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO audit_events (action, actor_user_id, project_id, target_user_id, details) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(self.action)
        .bind(self.actor_user_id)
        .bind(self.project_id)
        .bind(self.target_user_id)
        .bind(sqlx::types::Json(self.details))
        .execute(conn)
        .await?;
        Ok(())
    }
}
