use axum::{
    extract::Multipart,
    response::IntoResponse,
    Json,
};
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;
use rand::RngCore;
use hex;
use blake3::Hasher;

use chacha20poly1305::{
    ChaCha20Poly1305,
    Key,
    Nonce,
};
use chacha20poly1305::aead::{Aead, NewAead};

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    PublicKey as KemPublicKey,
    Ciphertext,
    SharedSecret,
};


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

/// -------- CORE ENCRYPTION --------
fn encrypt_bytes_for_recipients(
    plaintext: &[u8],
    kyber_public_keys: Vec<Vec<u8>>,
) -> EncryptedPayload {
    // ChaCha key
    let mut chacha_key = [0u8; 32];
    OsRng.fill_bytes(&mut chacha_key);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));

    // Nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt file
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("file encryption failed");

    // Encrypt ChaCha key for each recipient
    let mut kyber_outputs = Vec::new();

    for pk_bytes in kyber_public_keys {
        let pk = kyber768::PublicKey::from_bytes(&pk_bytes)
            .expect("invalid kyber public key");

        let (kem_ct, shared_secret) = kyber768::encapsulate(&pk);

        let mut hasher = Hasher::new();
        hasher.update(shared_secret.as_bytes());
        let wrapping_key = hasher.finalize();

        let mut wrapped_key = [0u8; 32];
        for i in 0..32 {
            wrapped_key[i] = chacha_key[i] ^ wrapping_key.as_bytes()[i];
        }

        kyber_outputs.push(KyberEncryptedKey {
            kem_ciphertext: hex::encode(kem_ct.as_bytes()),
            encrypted_chacha_key: hex::encode(wrapped_key),
        });
    }

    EncryptedPayload {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        kyber_keys: kyber_outputs,
    }
}

/// -------- AXUM HANDLER --------
/// POST /encrypt/file
/// multipart:
/// - file: binary
/// - kyber_pubkeys: comma-separated hex strings
pub async fn encrypt_file_handler(
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut file_bytes: Vec<u8> = Vec::new();
    let mut kyber_pubkeys: Vec<Vec<u8>> = Vec::new();

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("");

        match name {
            "file" => {
                file_bytes = field.bytes().await.unwrap().to_vec();
            }
            "kyber_pubkeys" => {
                let value = field.text().await.unwrap();
                for pk_hex in value.split(',') {
                    kyber_pubkeys.push(hex::decode(pk_hex.trim()).unwrap());
                }
            }
            _ => {}
        }
    }

    if file_bytes.is_empty() || kyber_pubkeys.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "file or kyber_pubkeys missing",
        )
            .into_response();
    }

    let encrypted = encrypt_bytes_for_recipients(
        &file_bytes,
        kyber_pubkeys,
    );

    Json(encrypted).into_response()
}
