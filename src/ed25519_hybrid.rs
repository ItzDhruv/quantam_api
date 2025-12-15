use rand::random;
use serde::Serialize;
use hex;

use ed25519_dalek::{SigningKey, VerifyingKey};
use blake3::Hasher;

use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair,
    
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey
   
};

use pqcrypto_traits::sign::PublicKey as _;
use pqcrypto_traits::sign::SecretKey as _;



#[derive(Serialize)]
pub struct HybridPublicKeyJson {
    pub compressed_key: String,
    pub dilithium_pk: String,
    pub ed25519_pk: String,
}

#[derive(Serialize)]
pub struct HybridSecretKeyJson {
    pub dilithium_sk: String,
    pub ed25519_sk: String,
}

#[derive(Serialize)]
pub struct HybridKeypairJson {
    pub public_key: HybridPublicKeyJson,
    pub secret_key: HybridSecretKeyJson,
}

pub struct HybridPublicKey {
    pub dilithium_pk: DilithiumPublicKey,
    pub ed25519_pk: VerifyingKey,
    pub compressed_key: [u8; 32],
}

pub struct HybridSecretKey {
    pub dilithium_sk: DilithiumSecretKey,
    pub ed25519_sk: SigningKey,
}





fn minimize_key(dil_pk: &DilithiumPublicKey, ed_pk: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(dil_pk.as_bytes());
    hasher.update(&ed_pk.to_bytes());

    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}


pub fn generate_hybrid_keypair() -> (HybridPublicKey, HybridSecretKey) {
    let (dil_pk, dil_sk) = dilithium_keypair();

    let seed: [u8; 32] = random();
    let ed_sk = SigningKey::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();

    let compressed = minimize_key(&dil_pk, &ed_pk);

    (
        HybridPublicKey {
            dilithium_pk: dil_pk,
            ed25519_pk: ed_pk,
            compressed_key: compressed,
        },
        HybridSecretKey {
            dilithium_sk: dil_sk,
            ed25519_sk: ed_sk,
        },
    )
}



pub fn get_hybrid_keypair_json() -> HybridKeypairJson {
    let (pk, sk) = generate_hybrid_keypair();

    HybridKeypairJson {
        public_key: HybridPublicKeyJson {
            compressed_key: hex::encode(pk.compressed_key),
            dilithium_pk: hex::encode(pk.dilithium_pk.as_bytes()),
            ed25519_pk: hex::encode(pk.ed25519_pk.to_bytes()),
        },
        secret_key: HybridSecretKeyJson {
            dilithium_sk: hex::encode(sk.dilithium_sk.as_bytes()),
            ed25519_sk: hex::encode(sk.ed25519_sk.to_bytes()),
        },
    }
}
