use axum::{extract::Path, Json};

pub async fn get_public_keys_handler(
    Path(did): Path<String>,
) -> Json<serde_json::Value> {

    Json(serde_json::json!({
        "did": did,
        "public_keys": {
            "dilithium_pk": "from did_document.verificationMethod",
            "sr25519_pk": "from did_document.verificationMethod",
            "kyber_pk": "from did_document.keyAgreement"
        }
    }))
}
