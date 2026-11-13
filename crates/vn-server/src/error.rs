//! JSON error responses for the API.

use std::fmt;

use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::{Json, extract};
use serde::de::DeserializeOwned;
use vn_core::ApiError;

/// An API error answered with the shared [`ApiError`] JSON body.
#[derive(Debug)]
pub(crate) struct ApiFailure {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiFailure {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", message)
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// Logs `err` and answers with a generic 500 that reveals nothing about it.
    pub(crate) fn internal(err: impl fmt::Display) -> Self {
        tracing::error!(error = %err, "request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "The server hit an unexpected error.",
        )
    }
}

impl From<sqlx::Error> for ApiFailure {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::PoolTimedOut => {
                tracing::warn!("database connection pool timed out");
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "unavailable",
                    "The database is unavailable.",
                )
            }
            err => Self::internal(err),
        }
    }
}

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        (self.status, Json(ApiError::new(self.code, self.message))).into_response()
    }
}

pub(crate) fn api_error(status: StatusCode, code: &'static str, message: String) -> Response {
    ApiFailure::new(status, code, message).into_response()
}

/// JSON request body whose rejections use the API error shape.
pub(crate) struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiFailure;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection(&rejection)),
        }
    }
}

fn json_rejection(rejection: &JsonRejection) -> ApiFailure {
    let code = match rejection {
        JsonRejection::MissingJsonContentType(_) => "unsupported_media_type",
        _ => "invalid_request",
    };
    ApiFailure::new(rejection.status(), code, rejection.body_text())
}

/// Path parameters whose rejections use the API error shape.
pub(crate) struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiFailure;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(extract::Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(path_rejection(&rejection)),
        }
    }
}

fn path_rejection(rejection: &PathRejection) -> ApiFailure {
    ApiFailure::new(rejection.status(), "invalid_request", rejection.body_text())
}
