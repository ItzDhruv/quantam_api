use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::did::store::DidStore;

/// GET /did/{did}
///
/// Resolves a previously created DID to its stored DID document.
pub async fn resolve_did_handler(
    State(store): State<DidStore>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    match store.get(&did) {
        Some(doc) => Json(serde_json::json!({
            "did": did,
            "did_document": doc,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "did": did,
                "error": "DID not found",
            })),
        )
            .into_response(),
    }
}
