use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ember_proto::ApiError;

#[derive(Debug)]
pub struct ApiErr(pub StatusCode, pub String);

pub type ApiResult<T> = Result<T, ApiErr>;

pub fn bad_request(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::BAD_REQUEST, msg.into())
}

pub fn not_found(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::NOT_FOUND, msg.into())
}

pub fn conflict(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::CONFLICT, msg.into())
}

impl From<anyhow::Error> for ApiErr {
    fn from(e: anyhow::Error) -> Self {
        // This API has one trusted operator, and full causes make failures fixable from the panel.
        ApiErr(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(ApiError { error: self.1 })).into_response()
    }
}
