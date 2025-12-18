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
    println!("Kyber Public Key: {}", pk.as_bytes().len());
    // ---- HARD VALIDATION ----
    assert_eq!(pk.as_bytes().len(), kyber768::public_key_bytes());
    assert_eq!(sk.as_bytes().len(), kyber768::secret_key_bytes());

    KyberKeypair {
        public_key_hex: hex::encode(pk.as_bytes()),
        secret_key_hex: hex::encode(sk.as_bytes()),
    }
}

///  AXUM HANDLER (THIS is what routing must use)
pub async fn generate_kyber_keypair() -> Json<KyberKeypair> {
    
    Json(generate_kyber_keypair_internal())
}
