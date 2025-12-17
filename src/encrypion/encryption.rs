use axum::{
    extract::Multipart,
    response::IntoResponse,
    Json,
};
use pqcrypto_traits::kem::{PublicKey, SharedSecret, Ciphertext};
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;
use rand::RngCore;
use hex;

use chacha20poly1305::{
    ChaCha20Poly1305,
    Key,
    Nonce,
};
use chacha20poly1305::aead::{Aead, KeyInit};

use pqcrypto_kyber::kyber768;

/// Kyber-encrypted ChaCha key (per recipient)
#[derive(Serialize, Deserialize)]
pub struct KyberEncryptedKey {
    pub kem_ciphertext: String,
    pub encrypted_chacha_key: String,
}

/// Final encrypted payload
#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub nonce: String,
    pub ciphertext: String,
    pub kyber_keys: Vec<KyberEncryptedKey>,
}

/// ----------------------------------------------------------------
/// CORE ENCRYPTION LOGIC (WITH LOGS)
/// ----------------------------------------------------------------
fn encrypt_bytes_for_recipients(
    plaintext: &[u8],
    kyber_public_keys: Vec<Vec<u8>>,
) -> Result<EncryptedPayload, &'static str> {

    println!("\n[ENC-1] Plaintext size = {} bytes", plaintext.len());

    //  Generate ChaCha key
    let mut chacha_key = [0u8; 32];
    OsRng.fill_bytes(&mut chacha_key);
    println!("[ENC-2] ChaCha key generated (32 bytes)");

    let file_cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));

    // Nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    println!("[ENC-3] Nonce generated = {}", hex::encode(nonce_bytes));

    let nonce = Nonce::from_slice(&nonce_bytes);

    //  Encrypt file
    let ciphertext = file_cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "file encryption failed")?;

    println!(
        "[ENC-4] File encrypted. Ciphertext size = {} bytes",
        ciphertext.len()
    );

    let mut kyber_outputs = Vec::new();

    //  Kyber wrap ChaCha key
    for (idx, pk_bytes) in kyber_public_keys.iter().enumerate() {

        println!(
            "\n[ENC-5.{}] Kyber public key length = {} bytes",
            idx,
            pk_bytes.len()
        );

        let pk = kyber768::PublicKey::from_bytes(pk_bytes)
            .map_err(|_| "invalid Kyber public key")?;

        let (shared_secret, kem_ct) = kyber768::encapsulate(&pk);

        // let (kem_ct, shared_secret) = kyber768::encapsulate(&pk);

        println!(
            "[ENC-6.{}] Kyber encapsulated | kem_ct = {} bytes | shared_secret = {} bytes",
            idx,
            kem_ct.as_bytes().len(),
            shared_secret.as_bytes().len()
        );

        let wrap_key = blake3::derive_key(
            "kyber768-chacha20-key-wrap-v1",
            shared_secret.as_bytes(),
        );

        let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key));
        let wrap_nonce = Nonce::from_slice(b"kyber-wrap12");

        let encrypted_chacha_key = wrap_cipher
            .encrypt(wrap_nonce, chacha_key.as_ref())
            .map_err(|_| "key wrap failed")?;

        println!(
            "[ENC-7.{}] ChaCha key wrapped | wrapped_key = {} bytes",
            idx,
            encrypted_chacha_key.len()
        );

        kyber_outputs.push(KyberEncryptedKey {
            kem_ciphertext: hex::encode(kem_ct.as_bytes()),
            encrypted_chacha_key: hex::encode(encrypted_chacha_key),
        });
    }

    println!("\n[ENC-8] Encryption finished successfully");

    Ok(EncryptedPayload {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        kyber_keys: kyber_outputs,
    })
}

/// ----------------------------------------------------------------
/// AXUM HANDLER
/// ----------------------------------------------------------------
pub async fn encrypt_file_handler(
    mut multipart: Multipart,
) -> impl IntoResponse {

    println!("\n[ENC-HANDLER] Incoming encryption request");

    let mut file_bytes = Vec::new();
    let mut kyber_pubkeys = Vec::new();

    while let Some(field) = multipart.next_field().await.unwrap() {
        match field.name().unwrap_or("") {

            "file" => {
                file_bytes = field.bytes().await.unwrap().to_vec();
                println!(
                    "[ENC-HANDLER] File received ({} bytes)",
                    file_bytes.len()
                );
            }

            "kyber_pubkeys" => {
    let value = field.text().await.unwrap();

    println!("[ENC-HANDLER] Raw kyber_pubkeys field received");

    for (idx, hex_pk) in value.split(',').enumerate() {
        let hex_pk = hex_pk.trim();

        if hex_pk.is_empty() {
            continue;
        }

        let decoded = match hex::decode(hex_pk) {
            Ok(v) => v,
            Err(_) => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("invalid hex in kyber_pubkeys at index {}", idx),
                )
                    .into_response();
            }
        };

        println!(
            "[ENC-HANDLER] Kyber public key {} decoded ({} bytes)",
            idx,
            decoded.len()
        );

        if decoded.len() != kyber768::public_key_bytes() {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                format!(
                    "kyber_pubkeys[{}] invalid size (expected {} bytes)",
                    idx,
                    kyber768::public_key_bytes()
                ),
            )
                .into_response();
        }

        kyber_pubkeys.push(decoded);
    }
}


            _ => {}
        }
    }

    match encrypt_bytes_for_recipients(&file_bytes, kyber_pubkeys) {
        Ok(payload) => Json(payload).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e).into_response(),
    }
}
