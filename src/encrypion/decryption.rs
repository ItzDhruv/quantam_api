use axum::{
    extract::Json,
    response::IntoResponse,
};
use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret};
use serde::{Serialize, Deserialize};
use hex;

use chacha20poly1305::{
    ChaCha20Poly1305,
    Key,
    Nonce,
};
use chacha20poly1305::aead::{Aead, KeyInit};

use pqcrypto_kyber::kyber768;

/// Same structs
#[derive(Serialize, Deserialize)]
pub struct KyberEncryptedKey {
    pub kem_ciphertext: String,
    pub encrypted_chacha_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub nonce: String,
    pub ciphertext: String,
    pub kyber_keys: Vec<KyberEncryptedKey>,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub encrypted_payload: EncryptedPayload,
    pub kyber_secret_key: String,
}

/// ----------------------------------------------------------------
/// CORE DECRYPT LOGIC (WITH LOGS)
/// ----------------------------------------------------------------
fn decrypt_payload(
    payload: &EncryptedPayload,
    kyber_sk_bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {

    println!("\n[DEC-1] Starting decryption");
    println!(
        "[DEC-2] Secret key length = {} bytes",
        kyber_sk_bytes.len()
    );

    let sk = kyber768::SecretKey::from_bytes(kyber_sk_bytes)
        .map_err(|_| "invalid kyber secret key")?;

    let nonce_bytes = hex::decode(&payload.nonce).unwrap();
    let ciphertext = hex::decode(&payload.ciphertext).unwrap();

    println!(
        "[DEC-3] Nonce = {} | Ciphertext = {} bytes",
        payload.nonce,
        ciphertext.len()
    );

    let nonce = Nonce::from_slice(&nonce_bytes);

    for (idx, entry) in payload.kyber_keys.iter().enumerate() {

        println!(
            "\n[DEC-4.{}] kem_ciphertext hex length = {}",
            idx,
            entry.kem_ciphertext.len()
        );

        let kem_ct_bytes = hex::decode(&entry.kem_ciphertext)
            .map_err(|_| "invalid kem hex")?;

        println!(
            "[DEC-5.{}] kem_ciphertext decoded = {} bytes",
            idx,
            kem_ct_bytes.len()
        );

        let kem_ct = kyber768::Ciphertext::from_bytes(&kem_ct_bytes)
            .map_err(|_| "invalid kyber ciphertext")?;

        let shared_secret = kyber768::decapsulate(&kem_ct, &sk);

        println!(
            "[DEC-6.{}] Shared secret derived = {} bytes",
            idx,
            shared_secret.as_bytes().len()
        );

        let kek = blake3::derive_key(
            "kyber768-chacha20-key-wrap-v1",
            shared_secret.as_bytes(),
        );

        let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
        let wrap_nonce = Nonce::from_slice(b"kyber-wrap12");

        let wrapped_key = hex::decode(&entry.encrypted_chacha_key).unwrap();

        let chacha_key = match wrap_cipher.decrypt(wrap_nonce, wrapped_key.as_ref()) {
            Ok(k) => {
                println!("[DEC-7.{}] ChaCha key unwrap SUCCESS", idx);
                k
            }
            Err(_) => {
                println!("[DEC-7.{}] ChaCha key unwrap FAILED", idx);
                continue;
            }
        };

        let file_cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));

        if let Ok(plaintext) = file_cipher.decrypt(nonce, ciphertext.as_ref()) {
            println!("[DEC-8] File decrypted SUCCESS");
            return Ok(plaintext);
        }
    }

    Err("decryption failed: not an authorized recipient")
}

/// ----------------------------------------------------------------
/// AXUM HANDLER
/// ----------------------------------------------------------------
pub async fn decrypt_file_handler(
    Json(req): Json<DecryptRequest>,
) -> impl IntoResponse {

    println!("\n[DEC-HANDLER] Incoming decrypt request");

    let kyber_sk = hex::decode(&req.kyber_secret_key).unwrap();

    match decrypt_payload(&req.encrypted_payload, &kyber_sk) {
        Ok(plaintext) => (
            axum::http::StatusCode::OK,
            plaintext,
        ).into_response(),
        Err(e) => (
            axum::http::StatusCode::UNAUTHORIZED,
            e,
        ).into_response(),
    }
}

