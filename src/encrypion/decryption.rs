use axum::{
    extract::Json,
    http::StatusCode,
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

/// Mirror of `encryption::KyberEncryptedKey` for deserializing requests.
#[derive(Serialize, Deserialize)]
pub struct KyberEncryptedKey {
    pub kem_ciphertext: String,
    pub encrypted_chacha_key: String,
    pub wrap_nonce: String,
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
pub(crate) fn decrypt_payload(
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

    let nonce_bytes = hex::decode(&payload.nonce)
        .map_err(|_| "invalid nonce hex")?;

    if nonce_bytes.len() != 12 {
        return Err("invalid nonce length");
    }

    let ciphertext = hex::decode(&payload.ciphertext)
        .map_err(|_| "invalid ciphertext hex")?;

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

        //  USE STORED RANDOM NONCE
        let wrap_nonce_bytes = hex::decode(&entry.wrap_nonce)
            .map_err(|_| "invalid wrap nonce hex")?;

        if wrap_nonce_bytes.len() != 12 {
            continue;
        }

        let wrap_nonce = Nonce::from_slice(&wrap_nonce_bytes);

        let wrapped_key = hex::decode(&entry.encrypted_chacha_key)
            .map_err(|_| "invalid wrapped key hex")?;

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

    let kyber_sk = match hex::decode(&req.kyber_secret_key) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid kyber_secret_key hex")
                .into_response();
        }
    };

    match decrypt_payload(&req.encrypted_payload, &kyber_sk) {
        Ok(plaintext) => (StatusCode::OK, plaintext).into_response(),
        Err(e) => (StatusCode::UNAUTHORIZED, e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt_payload, EncryptedPayload};
    use crate::encrypion::encryption::encrypt_bytes_for_recipients;
    use pqcrypto_kyber::kyber768;
    use pqcrypto_traits::kem::{PublicKey, SecretKey};

    /// The encryption and decryption modules each define their own
    /// (structurally identical) payload type. Crossing the boundary via
    /// serde also exercises the JSON wire format the HTTP API uses.
    fn to_decrypt_payload(
        enc: &crate::encrypion::encryption::EncryptedPayload,
    ) -> EncryptedPayload {
        let json = serde_json::to_string(enc).expect("payload should serialize");
        serde_json::from_str(&json).expect("payload should deserialize")
    }

    #[test]
    fn encrypt_decrypt_round_trip_recovers_plaintext() {
        let (pk, sk) = kyber768::keypair();
        let plaintext = b"hybrid post-quantum round trip \x00\x01\x02 binary";

        let enc = encrypt_bytes_for_recipients(plaintext, vec![pk.as_bytes().to_vec()])
            .expect("encryption should succeed");
        let payload = to_decrypt_payload(&enc);

        let recovered = decrypt_payload(&payload, sk.as_bytes())
            .expect("authorized recipient should decrypt");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn multi_recipient_each_can_decrypt() {
        let (pk_a, sk_a) = kyber768::keypair();
        let (pk_b, sk_b) = kyber768::keypair();
        let plaintext = b"shared secret for two recipients";

        let enc = encrypt_bytes_for_recipients(
            plaintext,
            vec![pk_a.as_bytes().to_vec(), pk_b.as_bytes().to_vec()],
        )
        .expect("encryption should succeed");
        let payload = to_decrypt_payload(&enc);

        assert_eq!(payload.kyber_keys.len(), 2);
        assert_eq!(decrypt_payload(&payload, sk_a.as_bytes()).unwrap(), plaintext);
        assert_eq!(decrypt_payload(&payload, sk_b.as_bytes()).unwrap(), plaintext);
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let (pk, _sk) = kyber768::keypair();
        let (_other_pk, other_sk) = kyber768::keypair();
        let plaintext = b"top secret";

        let enc = encrypt_bytes_for_recipients(plaintext, vec![pk.as_bytes().to_vec()])
            .expect("encryption should succeed");
        let payload = to_decrypt_payload(&enc);

        assert!(decrypt_payload(&payload, other_sk.as_bytes()).is_err());
    }
}
