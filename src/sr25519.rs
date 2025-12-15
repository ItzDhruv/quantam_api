use axum::Json;
use serde::Serialize;
use sp_core::{Pair, sr25519, crypto::Ss58Codec};
use hex;

#[derive(Serialize)]
pub struct Sr25519Wallet {
    pub accountId: String,
    pub publicKey: String,
    pub secretPhrase: String,
    pub secretSeed: String,
    pub ss58Address: String,
}

pub async fn generate_sr25519_wallet() -> Json<Sr25519Wallet> {
    // Generate sr25519 keypair with mnemonic
    let (pair, phrase, seed) = sr25519::Pair::generate_with_phrase(None);

    let public_key = pair.public();
    let public_key_hex = format!("0x{}", hex::encode(public_key));

    let seed_hex = format!("0x{}", hex::encode(seed));

    // Default SS58 format = 42 (generic Substrate)
    // Works for Polkadot-based custom chains unless overridden
    let ss58_address = public_key.to_ss58check();

    let wallet = Sr25519Wallet {
        accountId: public_key_hex.clone(),
        publicKey: public_key_hex,
        secretPhrase: phrase,
        secretSeed: seed_hex,
        ss58Address: ss58_address,
    };

    Json(wallet)
}
