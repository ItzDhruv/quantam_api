use axum::{Json, response::IntoResponse};
use crate::did::model::*;
use crate::signature::sr25519_hybrid::get_hybrid_keypair_json;

/// POST /did/create
pub async fn create_did_handler() -> impl IntoResponse {

    let hybrid = get_hybrid_keypair_json();

    let did = format!(
        "did:scanbo:{}",
        &hybrid.public_key.compressed_key[..16]
    );

    let doc = DidDocument {
        id: did.clone(),
        controller: did.clone(),

        verificationMethod: vec![
            VerificationMethod {
                id: format!("{}#dilithium-1", did),
                r#type: "Dilithium2VerificationKey2025".into(),
                controller: did.clone(),
                publicKeyHex: hybrid.public_key.dilithium_pk,
            },
            VerificationMethod {
                id: format!("{}#sr25519-1", did),
                r#type: "Sr25519VerificationKey2020".into(),
                controller: did.clone(),
                publicKeyHex: hybrid.public_key.sr25519_pk,
            },
        ],

        keyAgreement: vec![
            KeyAgreement {
                id: format!("{}#kyber-1", did),
                r#type: "Kyber768KeyAgreement2025".into(),
                controller: did.clone(),
                publicKeyHex: hybrid.public_key.kyber_pk,
            }
        ],
    };

    Json(serde_json::json!({
        "did": did,
        "did_document": doc
    }))
}
