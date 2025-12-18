use axum::{
    routing::{get, post},
    Router,
    Json,
};

mod signature;
mod encrypion;

use signature::ed25519_hybrid::HybridKeypairJson;
use signature::{ed25519_hybrid, sr25519, sr25519_hybrid};
use signature::kyber::generate_kyber_keypair;

use encrypion::encryption::encrypt_file_handler;
use encrypion::decryption::decrypt_file_handler;

#[tokio::main]
async fn main() {
    println!("Server runs on http://localhost:3000");

    let app = Router::new()
        .route("/", get(|| async { "Scanbo key generation" }))

        //  Key generation APIs
        .route("/signature/ed25519_hk", get(hybrid_key))
        .route("/signature/kyber", get(generate_kyber_keypair))
        .route("/signature/sr25519", get(sr25519::generate_sr25519_wallet))
        .route(
            "/signature/sr25519_hk",
            get(sr25519_hybrid::hybrid_sr25519_kyber_handler),
        )

        //  File encryption APIs
        .route("/encrypt/file", post(encrypt_file_handler))
        .route("/decrypt/file", post(decrypt_file_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn hybrid_key() -> Json<HybridKeypairJson> {
    Json(ed25519_hybrid::get_hybrid_keypair_json())
}
