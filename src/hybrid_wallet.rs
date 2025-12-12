use rand::random;
use serde::Serialize;
use hex;

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use blake3::Hasher;

use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair,
    sign as dilithium_sign,
    open as dilithium_open,
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    SignedMessage as DilithiumSignedMessage,
};


use pqcrypto_traits::sign::PublicKey as _;
use pqcrypto_traits::sign::SecretKey as _;
use pqcrypto_traits::sign::SignedMessage as TraitSignedMessage;


/// Hybrid public key returned to the client
#[derive(Serialize)]
pub struct HybridPublicKeyJson {
    pub compressed_key: String,
    pub dilithium_pk: String,
    pub ed25519_pk: String,
}


#[derive(Serialize)]
pub struct PublicKeyAndPrivateKeyJson {
    pub public_key: HybridPublicKeyJson,
    pub secret_key: String,
}


/// Hybrid keypair internal usage
pub struct HybridPublicKey {
    pub dilithium_pk: DilithiumPublicKey,
    pub ed25519_pk: VerifyingKey,
    pub compressed_key: [u8; 32], 
}

pub struct HybridSecretKey {
    pub dilithium_sk: DilithiumSecretKey,
    pub ed25519_sk: SigningKey,
}

/// Signature JSON response
#[derive(Serialize)]
pub struct HybridSignatureJson {
    pub dilithium_signature: String,
    pub ed25519_signature: String,
}

/// Stored signature internal structure
pub struct HybridSignature {
    pub dilithium_sm: DilithiumSignedMessage,
    pub ed25519_sig: Signature,
}


/// 32-byte compressed key = Blake3(dilithium_pk || ed25519_pk)
fn minimize_key(dil_pk: &DilithiumPublicKey, ed_pk: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(dil_pk.as_bytes());
    hasher.update(&ed_pk.to_bytes());
    let hash = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}


/// Generate hybrid keypair (Dilithium + Ed25519)
pub fn generate_hybrid_keypair() -> (HybridPublicKey, HybridSecretKey) {
    let (dil_pk, dil_sk) = dilithium_keypair();

    let seed: [u8; 32] = random();
    let ed_sk = SigningKey::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();

    let compressed = minimize_key(&dil_pk, &ed_pk);

    let hybrid_pk = HybridPublicKey {
        dilithium_pk: dil_pk,
        ed25519_pk: ed_pk,
        compressed_key: compressed,
    };

    let hybrid_sk = HybridSecretKey {
        dilithium_sk: dil_sk,
        ed25519_sk: ed_sk,
    };

    (hybrid_pk, hybrid_sk)
}


/// Sign message using both Dilithium + Ed25519
pub fn hybrid_sign(message: &[u8], sk: &HybridSecretKey) -> HybridSignature {
    let dil_sm: DilithiumSignedMessage = dilithium_sign(message, &sk.dilithium_sk);
    let ed_sig: Signature = sk.ed25519_sk.sign(message);

    HybridSignature {
        dilithium_sm: dil_sm,
        ed25519_sig: ed_sig,
    }
}


/// Verify both Dilithium + Ed25519 signatures
pub fn hybrid_verify(message: &[u8], sig: &HybridSignature, pk: &HybridPublicKey) -> bool {
    let recovered = match dilithium_open(&sig.dilithium_sm, &pk.dilithium_pk) {
        Ok(msg) => msg,
        Err(_) => return false,
    };

    if recovered.as_slice() != message {
        return false;
    }

    pk.ed25519_pk.verify(message, &sig.ed25519_sig).is_ok()
}


/// Convert PK data to JSON response format
pub fn get_hybrid_keypair_json() -> (HybridPublicKeyJson, HybridSecretKey) {
    let (pk, sk) = generate_hybrid_keypair();

    let json = HybridPublicKeyJson {
        compressed_key: hex::encode(pk.compressed_key),
        dilithium_pk: hex::encode(pk.dilithium_pk.as_bytes()),
        ed25519_pk: hex::encode(pk.ed25519_pk.to_bytes()),
    };

    (json, sk)
}


/// Convert signature to JSON
pub fn signature_to_json(sig: &HybridSignature) -> HybridSignatureJson {
    HybridSignatureJson {
        dilithium_signature: hex::encode(sig.dilithium_sm.as_bytes()),
        ed25519_signature: hex::encode(sig.ed25519_sig.to_bytes()),
    }
}
