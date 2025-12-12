// use serde::{Serialize, Deserialize};
// use hex;
// use rand::rngs::OsRng;
// use rand::RngCore;
// use blake3::Hasher;

// use pqcrypto_kyber::kyber1024::{
//     keypair as kyber_keypair,
//     encapsulate,
//     decapsulate,
//     PublicKey as KyberPublicKey,
//     SecretKey as KyberSecretKey,
//     Ciphertext as KyberCiphertext,
//     SharedSecret as KyberSharedSecret,
// };

// use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _};

// use x25519_dalek::{PublicKey as X25519PublicKey, EphemeralSecret as X25519Secret};
// use chacha20poly1305::{
//     ChaCha20Poly1305, Key, Nonce,
//     aead::{Aead, KeyInit}
// };

// /// JSON: hybrid encryption public key
// #[derive(Serialize)]
// pub struct HybridEncPublicKeyJson {
//     pub kyber_pk_hex: String,
//     pub x25519_pk_hex: String,
// }

// /// JSON: hybrid encryption secret key (dev/demo only — do NOT expose in prod)
// #[derive(Serialize)]
// pub struct HybridEncSecretKeyJson {
//     pub kyber_sk_hex: String,
//     pub x25519_sk_hex: String,
// }

// /// Internal hybrid encryption public key
// pub struct HybridEncPublicKey {
//     pub kyber_pk: KyberPublicKey,
//     pub x25519_pk: X25519PublicKey,
// }

// /// Internal hybrid encryption secret key
// pub struct HybridEncSecretKey {
//     pub kyber_sk: KyberSecretKey,
//     pub x25519_sk: X25519Secret,
// }

// /// Request for /hybrid_encrypt
// #[derive(Deserialize)]
// pub struct HybridEncryptRequest {
//     pub message_hex: String,
//     pub kyber_pk_hex: String,
//     pub x25519_pk_hex: String,
// }

// /// Response from /hybrid_encrypt
// #[derive(Serialize)]
// pub struct HybridEncryptResponse {
//     pub ciphertext_hex: String,
//     pub nonce_hex: String,
//     pub kyber_ct_hex: String,
//     pub x25519_ephemeral_pk_hex: String,
// }

// /// Request for /hybrid_decrypt
// #[derive(Deserialize)]
// pub struct HybridDecryptRequest {
//     pub ciphertext_hex: String,
//     pub nonce_hex: String,
//     pub kyber_ct_hex: String,
//     pub x25519_ephemeral_pk_hex: String,
//     pub kyber_sk_hex: String,
//     pub x25519_sk_hex: String,
// }

// /// Response from /hybrid_decrypt
// #[derive(Serialize)]
// pub struct HybridDecryptResponse {
//     pub message_hex: String,
// }

// /// Generate a hybrid encryption keypair (Kyber + X25519)
// pub fn generate_hybrid_enc_keypair_json() -> (HybridEncPublicKeyJson, HybridEncSecretKeyJson) {
//     // 1) Kyber keypair
//     let (kyber_pk, kyber_sk) = kyber_keypair();

//     // 2) X25519 static keypair
//     let mut rng = OsRng;
//     let x_sk = X25519Secret::new(&mut rng);
//     let x_pk = X25519PublicKey::from(&x_sk);

//     // 3) To JSON
//     let pub_json = HybridEncPublicKeyJson {
//         kyber_pk_hex: hex::encode(kyber_pk.as_bytes()),
//         x25519_pk_hex: hex::encode(x_pk.as_bytes()),
//     };

//     let sec_json = HybridEncSecretKeyJson {
//         kyber_sk_hex: hex::encode(kyber_sk.as_bytes()),
//         x25519_sk_hex: hex::encode(x_sk.to_bytes()),
//     };

//     (pub_json, sec_json)
// }

// /// Derive symmetric key from Kyber shared secret + X25519 shared secret
// fn derive_symmetric_key(ss_pq: &KyberSharedSecret, ss_classic: &[u8; 32]) -> [u8; 32] {
//     let mut hasher = Hasher::new();
//     hasher.update(ss_pq.as_bytes());
//     hasher.update(ss_classic);
//     let h = hasher.finalize();
//     let mut out = [0u8; 32];
//     out.copy_from_slice(&h.as_bytes()[..32]);
//     out
// }

// /// Hybrid encrypt: requires *public* Kyber key + *public* X25519 key
// pub fn hybrid_encrypt(req: HybridEncryptRequest) -> HybridEncryptResponse {
//     // Decode inputs
//     let msg = hex::decode(&req.message_hex).expect("invalid message hex");
//     let kyber_pk_bytes = hex::decode(&req.kyber_pk_hex).expect("invalid kyber pk hex");
//     let x25519_pk_bytes = hex::decode(&req.x25519_pk_hex).expect("invalid x25519 pk hex");

//     // Rebuild Kyber public key
//     let kyber_pk = KyberPublicKey::from_bytes(&kyber_pk_bytes).expect("invalid kyber pk bytes");

//     // Rebuild X25519 public key (recipient)
//     let x25519_pk_array: [u8; 32] = x25519_pk_bytes.try_into().expect("x25519 pk must be 32 bytes");
//     let x25519_pk = X25519PublicKey::from(x25519_pk_array);

//     // 1) Kyber encapsulate -> ss_pq, kyber_ct
//     let (ss_pq, kyber_ct): (KyberSharedSecret, KyberCiphertext) = encapsulate(&kyber_pk);

//     // 2) X25519: ephemeral sender secret + shared secret
//     let mut rng = OsRng;
//     let x_sk_eph = X25519Secret::new(&mut rng);
//     let x_pk_eph = X25519PublicKey::from(&x_sk_eph);
//     let shared_classic = x_sk_eph.diffie_hellman(&x25519_pk);
//     let shared_classic_bytes: [u8; 32] = shared_classic.to_bytes();

//     // 3) Derive symmetric key = blake3(ss_pq || shared_classic)
//     let sym_key_bytes = derive_symmetric_key(&ss_pq, &shared_classic_bytes);

//     // 4) Encrypt with ChaCha20-Poly1305
//     let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key_bytes));

//     let mut nonce_bytes = [0u8; 12];
//     rng.fill_bytes(&mut nonce_bytes);
//     let nonce = Nonce::from_slice(&nonce_bytes);

//     let ciphertext = cipher.encrypt(nonce, msg.as_ref())
//         .expect("encryption failure");

//     HybridEncryptResponse {
//         ciphertext_hex: hex::encode(ciphertext),
//         nonce_hex: hex::encode(nonce_bytes),
//         kyber_ct_hex: hex::encode(kyber_ct.as_bytes()),
//         x25519_ephemeral_pk_hex: hex::encode(x_pk_eph.as_bytes()),
//     }
// }

// /// Hybrid decrypt: requires BOTH Kyber SK and X25519 SK
// pub fn hybrid_decrypt(req: HybridDecryptRequest) -> Option<HybridDecryptResponse> {
//     let ct = hex::decode(&req.ciphertext_hex).ok()?;
//     let nonce_bytes = hex::decode(&req.nonce_hex).ok()?;
//     let kyber_ct_bytes = hex::decode(&req.kyber_ct_hex).ok()?;
//     let x25519_ephemeral_pk_bytes = hex::decode(&req.x25519_ephemeral_pk_hex).ok()?;
//     let kyber_sk_bytes = hex::decode(&req.kyber_sk_hex).ok()?;
//     let x25519_sk_bytes = hex::decode(&req.x25519_sk_hex).ok()?;

//     // Rebuild Kyber types
//     let kyber_sk = KyberSecretKey::from_bytes(&kyber_sk_bytes).ok()?;
//     let kyber_ct = KyberCiphertext::from_bytes(&kyber_ct_bytes).ok()?;

//     // Rebuild X25519 secret + ephemeral public
//     let x_sk_array: [u8; 32] = x25519_sk_bytes.try_into().ok()?;
//     let x_sk = X25519Secret::from(x_sk_array);

//     let x_epk_array: [u8; 32] = x25519_ephemeral_pk_bytes.try_into().ok()?;
//     let x_pk_eph = X25519PublicKey::from(x_epk_array);

//     // 1) Kyber decapsulate
//     let ss_pq: KyberSharedSecret = decapsulate(&kyber_ct, &kyber_sk);

//     // 2) X25519 shared secret
//     let shared_classic = x_sk.diffie_hellman(&x_pk_eph);
//     let shared_classic_bytes: [u8; 32] = shared_classic.to_bytes();

//     // 3) Derive symmetric key
//     let sym_key_bytes = derive_symmetric_key(&ss_pq, &shared_classic_bytes);

//     // 4) Decrypt
//     let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key_bytes));
//     let nonce: [u8; 12] = nonce_bytes.try_into().ok()?;
//     let nonce_ref = Nonce::from_slice(&nonce);

//     let plaintext = cipher.decrypt(nonce_ref, ct.as_ref()).ok()?;

//     Some(HybridDecryptResponse {
//         message_hex: hex::encode(plaintext),
//     })
// }
