use axum::Json;
use serde::Serialize;
use hex;
use blake3::Hasher;

use sp_core::{Pair, sr25519, crypto::Ss58Codec};

// ---------------- PQC ----------------
use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair,
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
};

use pqcrypto_kyber::kyber768::{
    keypair as kyber_keypair,
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
};

// Traits (IMPORTANT)
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};

// ---------------- JSON STRUCTS ----------------

#[derive(Serialize)]
pub struct HybridPublicKeyJson {
    pub compressed_key: String,
    pub dilithium_pk: String,
    pub sr25519_pk: String,
    pub kyber_pk: String,
}

#[derive(Serialize)]
pub struct HybridSecretKeyJson {
    pub dilithium_sk: String,
    pub sr25519_seed: String,
    pub kyber_sk: String,
}

#[derive(Serialize)]
pub struct Sr25519WalletJson {
    pub mnemonic: String,
    pub ss58_address: String,
}

#[derive(Serialize)]
pub struct HybridKeypairJson {
    pub public_key: HybridPublicKeyJson,
    pub secret_key: HybridSecretKeyJson,
    pub sr25519_wallet: Sr25519WalletJson,
}

// ---------------- INTERNAL STRUCTS ----------------

pub struct HybridPublicKey {
    pub dilithium_pk: DilithiumPublicKey,
    pub sr25519_pk: sr25519::Public,
    pub kyber_pk: KyberPublicKey,
    pub compressed_key: [u8; 32],
}

pub struct HybridSecretKey {
    pub dilithium_sk: DilithiumSecretKey,
    pub sr25519_seed: [u8; 32],
    pub kyber_sk: KyberSecretKey,
}

// ---------------- CORE LOGIC ----------------

fn minimize_key(
    dil_pk: &DilithiumPublicKey,
    sr_pk: &sr25519::Public,
    kyber_pk: &KyberPublicKey,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(dil_pk.as_bytes());
    hasher.update(sr_pk.as_ref());
    hasher.update(kyber_pk.as_bytes());

    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

fn generate_hybrid_keypair() -> (
    HybridPublicKey,
    HybridSecretKey,
    Sr25519WalletJson,
) {
    // 1️⃣ Dilithium (Signature – PQC)
    let (dil_pk, dil_sk) = dilithium_keypair();

    // 2️⃣ Sr25519 (Classical blockchain identity)
    let (pair, mnemonic, seed) = sr25519::Pair::generate_with_phrase(None);
    let sr_pk = pair.public();

    // 3️⃣ Kyber (PQC KEM – encryption)
    let (kyber_pk, kyber_sk) = kyber_keypair();

    // 4️⃣ Compressed hybrid identifier
    let compressed = minimize_key(&dil_pk, &sr_pk, &kyber_pk);

    (
        HybridPublicKey {
            dilithium_pk: dil_pk,
            sr25519_pk: sr_pk,
            kyber_pk,
            compressed_key: compressed,
        },
        HybridSecretKey {
            dilithium_sk: dil_sk,
            sr25519_seed: seed,
            kyber_sk,
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
            kyber_pk: hex::encode(pk.kyber_pk.as_bytes()),
        },
        secret_key: HybridSecretKeyJson {
            dilithium_sk: hex::encode(sk.dilithium_sk.as_bytes()),
            sr25519_seed: hex::encode(sk.sr25519_seed),
            kyber_sk: hex::encode(sk.kyber_sk.as_bytes()),
        },
        sr25519_wallet: wallet,
    }
}

// ---------------- AXUM HANDLER ----------------

pub async fn hybrid_sr25519_kyber_handler() -> Json<HybridKeypairJson> {
    Json(get_hybrid_keypair_json())
}
