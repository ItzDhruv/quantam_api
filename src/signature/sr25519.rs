use axum::Json;
use serde::Serialize;
use sp_core::{Pair, sr25519, crypto::Ss58Codec};
use hex;

#[derive(Serialize)]
pub struct Sr25519Wallet {
    pub public_key: String,
    pub secret_phrase: String,
    pub secret_seed: String,
    pub ss58_address: String,
}

pub async fn generate_sr25519_wallet() -> Json<Sr25519Wallet> {
    // Generate sr25519 keypair with mnemonic
    let (pair, phrase, seed) = sr25519::Pair::generate_with_phrase(None);

    let public_key = pair.public();
    let public_key_hex = format!("0x{}", hex::encode(public_key));

    let seed_hex = format!("0x{}", hex::encode(seed));

    let ss58_address = public_key.to_ss58check();

    let wallet = Sr25519Wallet {
        public_key: public_key_hex,
        secret_phrase: phrase,
        secret_seed: seed_hex,
        ss58_address: ss58_address,
    };

    Json(wallet)
}
