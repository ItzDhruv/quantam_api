use axum::Json;
use serde::Serialize;
use hex;
use blake3::Hasher;

use sp_core::{Pair, sr25519, crypto::Ss58Codec};

use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair,
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
};

use pqcrypto_traits::sign::PublicKey as _;
use pqcrypto_traits::sign::SecretKey as _;


#[derive(Serialize)]
pub struct HybridPublicKeyJson {
    pub compressed_key: String,
    pub dilithium_pk: String,
    pub sr25519_pk: String,
}

#[derive(Serialize)]
pub struct HybridSecretKeyJson {
    pub dilithium_sk: String,
    pub sr25519_seed: String,
}

#[derive(Serialize)]
pub struct Sr25519WalletJson {
    pub mnemonic: String,
    pub ss58_address: String,       // blockchain vala address prifix and addsum vala
}

#[derive(Serialize)]
pub struct HybridKeypairJson {
    pub public_key: HybridPublicKeyJson,
    pub secret_key: HybridSecretKeyJson,
    pub sr25519_wallet: Sr25519WalletJson,
}



pub struct HybridPublicKey {
    pub dilithium_pk: DilithiumPublicKey,
    pub sr25519_pk: sr25519::Public,
    pub compressed_key: [u8; 32],
}

pub struct HybridSecretKey {
    pub dilithium_sk: DilithiumSecretKey,
    pub sr25519_seed: [u8; 32],
}


fn minimize_key(
    dil_pk: &DilithiumPublicKey,
    sr_pk: &sr25519::Public,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(dil_pk.as_bytes());
    hasher.update(sr_pk.as_ref());

    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}



fn generate_hybrid_keypair() -> (
    HybridPublicKey,
    HybridSecretKey,
    Sr25519WalletJson,
) {
    // Dilithium (PQC)
    let (dil_pk, dil_sk) = dilithium_keypair();

    // Sr25519 (Classical)
    let (pair, mnemonic, seed) = sr25519::Pair::generate_with_phrase(None);
    let sr_pk = pair.public();

    let compressed = minimize_key(&dil_pk, &sr_pk);

    (
        HybridPublicKey {
            dilithium_pk: dil_pk,
            sr25519_pk: sr_pk,
            compressed_key: compressed,
        },
        HybridSecretKey {
            dilithium_sk: dil_sk,
            sr25519_seed: seed,
        },
        Sr25519WalletJson {
            mnemonic,
            ss58_address: sr_pk.to_ss58check(),
        },
    )
}



fn get_hybrid_keypair_json() -> HybridKeypairJson {
    let (pk, sk, wallet) = generate_hybrid_keypair();

    HybridKeypairJson {
        public_key: HybridPublicKeyJson {
            compressed_key: hex::encode(pk.compressed_key),
            dilithium_pk: hex::encode(pk.dilithium_pk.as_bytes()),
            sr25519_pk: hex::encode(pk.sr25519_pk),
        },
        secret_key: HybridSecretKeyJson {
            dilithium_sk: hex::encode(sk.dilithium_sk.as_bytes()),
            sr25519_seed: hex::encode(sk.sr25519_seed),
        },
        sr25519_wallet: wallet,
    }
}



pub async fn hybrid_sr25519_handler() -> Json<HybridKeypairJson> {
    Json(get_hybrid_keypair_json())
}
