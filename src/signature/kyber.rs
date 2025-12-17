use axum::Json;
use serde::Serialize;
use hex;

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    PublicKey,
    SecretKey,
};

/// Kyber768 keypair (HEX encoded)
#[derive(Serialize)]
pub struct KyberKeypair {
    pub public_key_hex: String,   // 1184 bytes → 2368 hex chars
    pub secret_key_hex: String,   // 2400 bytes → 4800 hex chars
}

/// INTERNAL generator (logic only)
fn generate_kyber_keypair_internal() -> KyberKeypair {
    let (pk, sk) = kyber768::keypair();
    print!("Kyber Public Key: {}", pk.as_bytes().len());
    // ---- HARD VALIDATION ----
    assert_eq!(pk.as_bytes().len(), kyber768::public_key_bytes());
    assert_eq!(sk.as_bytes().len(), kyber768::secret_key_bytes());

    KyberKeypair {
        public_key_hex: hex::encode(pk.as_bytes()),
        secret_key_hex: hex::encode(sk.as_bytes()),
    }
}

/// ✅ AXUM HANDLER (THIS is what routing must use)
pub async fn generate_kyber_keypair() -> Json<KyberKeypair> {
    
    Json(generate_kyber_keypair_internal())
}

/// Decode Kyber768 public key from hex
pub fn kyber_pk_from_hex(hex_pk: &str) -> Result<kyber768::PublicKey, &'static str> {
    let bytes = hex::decode(hex_pk).map_err(|_| "Invalid hex")?;

    if bytes.len() != kyber768::public_key_bytes() {
        return Err("INVALID Kyber768 public key size");
    }

    kyber768::PublicKey::from_bytes(&bytes)
        .map_err(|_| "Invalid Kyber768 public key bytes")
}

/// Decode Kyber768 secret key from hex
pub fn kyber_sk_from_hex(hex_sk: &str) -> Result<kyber768::SecretKey, &'static str> {
    let bytes = hex::decode(hex_sk).map_err(|_| "Invalid hex")?;

    if bytes.len() != kyber768::secret_key_bytes() {
        return Err("INVALID Kyber768 secret key size");
    }

    kyber768::SecretKey::from_bytes(&bytes)
        .map_err(|_| "Invalid Kyber768 secret key bytes")
}
