use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::did::store::DidStore;

/// GET /did/{did}/keys
///
/// Returns the verification and key-agreement public keys recorded in the
/// stored DID document.
pub async fn get_public_keys_handler(
    State(store): State<DidStore>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let Some(doc) = store.get(&did) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "did": did,
                "error": "DID not found",
            })),
        )
            .into_response();
    };

    let verification_method: Vec<_> = doc
        .verificationMethod
        .iter()
        .map(|vm| {
            json!({
                "id": vm.id,
                "type": vm.r#type,
                "publicKeyHex": vm.publicKeyHex,
            })
        })
        .collect();

    let key_agreement: Vec<_> = doc
        .keyAgreement
        .iter()
        .map(|ka| {
            json!({
                "id": ka.id,
                "type": ka.r#type,
                "publicKeyHex": ka.publicKeyHex,
            })
        })
        .collect();

    Json(json!({
        "did": did,
        "verificationMethod": verification_method,
        "keyAgreement": key_agreement,
    }))
    .into_response()
}
