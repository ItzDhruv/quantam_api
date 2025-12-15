use axum::{routing::get, Router, Json};

mod ed25519_hybrid;
mod sr25519;
mod sr25519_hybrid;

use ed25519_hybrid::HybridKeypairJson;

#[tokio::main]
async fn main() {
    println!("Server runs on http://localhost:3000");

    let app = Router::new()
        .route("/", get(|| async { "Scanbo key generation" }))
        .route("/ed25519_hk", get(hybrid_key))
        .route("/sr25519", get(sr25519::generate_sr25519_wallet))
        .route(
            "/sr25519_hk",
            get(sr25519_hybrid::hybrid_sr25519_handler),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn hybrid_key() -> Json<HybridKeypairJson> {
    Json(ed25519_hybrid::get_hybrid_keypair_json())
}
