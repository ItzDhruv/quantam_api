use axum::{extract::Path, Json};

pub async fn resolve_did_handler(
    Path(did): Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "did": did,
        "note": "Resolver will fetch DID document from IPFS later"
    }))
}
